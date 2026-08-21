package signal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// maxFrame caps a single envelope. An ICE candidate is a couple of hundred
	// bytes and the seal adds a nonce and a tag; 8 KiB is far above anything
	// legitimate and low enough that a peer cannot make the server allocate on
	// its behalf.
	maxFrame = 8 << 10

	// sendQueue is how many envelopes may be waiting for one peer's socket.
	//
	// Negotiation is bursty in a way that scales with the mesh, and sixty-four
	// was sized against a pair rather than a fleet. Every peer that renegotiates
	// sends one offer and then trickles each candidate it finds, so a machine
	// in a mesh of eighteen receives on the order of a hundred and seventy
	// envelopes inside a second or two whenever the mesh comes back together —
	// after an update, after a signalling reset, after anything that makes
	// everyone try at once.
	//
	// Sixty-four overflowed on every one of those, and overflow closed the
	// socket. The peer reconnected within a second, and for that second every
	// machine negotiating with it was told it was offline. Those negotiations
	// failed, retried, and made the next burst larger. It is the whole of the
	// instability: sockets flapping all day, pairs stuck in negotiation for
	// hours, and a mesh that only recovered when somebody reconnected it by
	// hand.
	//
	// A thousand is a burst from sixty peers, and costs about three hundred
	// kilobytes per connection at the size an envelope actually is.
	sendQueue = 1024

	// enqueueWait is how long a full queue is given to drain before the peer is
	// treated as one that cannot keep up.
	//
	// The write loop drains as fast as the socket accepts, and a full burst is
	// tens of kilobytes — milliseconds on any link that works at all. So a
	// queue that is still full after this long is not a burst, it is a peer
	// that has stopped reading, and closing is right. Two seconds is far past
	// the first and far short of anything a person would notice.
	enqueueWait = 2 * time.Second

	// writeWait bounds a single write. Without it one peer on a dead TCP
	// connection parks a goroutine until the kernel gives up, which can be
	// minutes.
	writeWait = 10 * time.Second

	// pingEvery keeps the WebSocket alive through NAT and idle-connection
	// timeouts on whatever middlebox sits in the path. Peers may sit silent for
	// hours between negotiations, and a signal socket that quietly died is only
	// discovered when it is needed most.
	pingEvery = 30 * time.Second
)

// Server routes sealed envelopes between peers. It is a switchboard and nothing
// else: no state survives a disconnect, and nothing it holds is worth stealing.
type Server struct {
	log *slog.Logger

	mu    sync.RWMutex
	peers map[string]*conn
}

// conn is one peer's socket, owned by its writer goroutine.
type conn struct {
	key  string
	ws   *websocket.Conn
	send chan Envelope

	// closeOnce guards the two paths that can retire a connection at the same
	// time: the reader noticing the socket died, and a re-registration by the
	// same key kicking it out.
	closeOnce sync.Once
	closed    chan struct{}
}

func NewServer(log *slog.Logger) *Server {
	return &Server{log: log, peers: make(map[string]*conn)}
}

// Peers is how many sockets are currently registered. Exposed for the health
// endpoint and for tests.
func (s *Server) Peers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// Handler upgrades the request and serves one peer until it goes away.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// The signal server is reached by agents, not by browsers: there is
			// no page anywhere that should be opening this socket, so no origin
			// is worth allowing.
			OriginPatterns: nil,
		})
		if err != nil {
			s.log.Warn("signal: websocket upgrade failed", "err", err)
			return
		}
		ws.SetReadLimit(maxFrame)

		// Not tied to the request context: coder/websocket cancels that as soon
		// as the handler is considered done, and this handler runs for the whole
		// life of the socket.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s.serve(ctx, ws)
	})
}

func (s *Server) serve(ctx context.Context, ws *websocket.Conn) {
	key, err := s.awaitHello(ctx, ws)
	if err != nil {
		s.log.Debug("signal: registration refused", "err", err)
		_ = ws.Close(websocket.StatusPolicyViolation, "hello expected")
		return
	}

	c := &conn{
		key:    key,
		ws:     ws,
		send:   make(chan Envelope, sendQueue),
		closed: make(chan struct{}),
	}
	s.register(c)
	defer s.unregister(c)

	go c.writeLoop(ctx, s.log)
	go c.pingLoop(ctx)

	s.log.Info("signal: peer connected", "key", short(key), "peers", s.Peers())
	s.readLoop(ctx, c)
	s.log.Info("signal: peer gone", "key", short(key), "peers", s.Peers()-1)
}

// awaitHello reads the first frame, which has to be a hello naming a valid
// WireGuard public key. Anything else and the socket is not worth keeping.
func (s *Server) awaitHello(ctx context.Context, ws *websocket.Conn) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, data, err := ws.Read(ctx)
	if err != nil {
		return "", err
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return "", err
	}
	if e.Kind != KindHello {
		return "", errors.New("first frame was not a hello")
	}
	// Parsing the key is the only validation there is. It rejects garbage and
	// normalises the encoding, so two spellings of the same key cannot end up
	// as two entries in the routing table.
	k, err := wgtypes.ParseKey(e.From)
	if err != nil {
		return "", err
	}
	return k.String(), nil
}

func (s *Server) register(c *conn) {
	s.mu.Lock()
	old, existed := s.peers[c.key]
	s.peers[c.key] = c
	s.mu.Unlock()

	// A peer that changed networks reconnects before the old socket has been
	// noticed as dead. The new one wins: the stale socket cannot deliver
	// anything, and refusing the new one would lock out the peer for as long as
	// the ping timeout.
	if existed {
		s.log.Debug("signal: replacing an earlier socket", "key", short(c.key))
		old.close()
	}
}

func (s *Server) unregister(c *conn) {
	s.mu.Lock()
	// Only remove the entry if it is still ours: a reconnect may already have
	// put a newer connection under this key, and removing it here would
	// silently unregister a live peer.
	if cur, ok := s.peers[c.key]; ok && cur == c {
		delete(s.peers, c.key)
	}
	s.mu.Unlock()
	c.close()
}

func (s *Server) readLoop(ctx context.Context, c *conn) {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return
		}
		var e Envelope
		if err := json.Unmarshal(data, &e); err != nil {
			s.log.Debug("signal: undecodable frame", "key", short(c.key), "err", err)
			continue
		}
		// From is set by the server, never trusted from the wire: a peer that
		// could name its own sender would be able to inject candidates into
		// someone else's negotiation. It cannot forge the body, which is sealed
		// to a key it does not hold, but it could make the recipient waste a
		// session on a conversation that never happened.
		e.From = c.key
		s.route(e)
	}
}

func (s *Server) route(e Envelope) {
	s.mu.RLock()
	dst, ok := s.peers[e.To]
	s.mu.RUnlock()

	if !ok {
		s.mu.RLock()
		src := s.peers[e.From]
		s.mu.RUnlock()
		if src != nil {
			src.enqueue(Envelope{Kind: KindOffline, From: e.To, To: e.From})
		}
		return
	}
	dst.enqueue(e)
}

// enqueue hands an envelope to a peer's write loop.
//
// Dropping one is not an option: a missing candidate looks exactly like a NAT
// problem from the other end, and the negotiation it belonged to fails in a way
// nothing in the logs explains. So the choice is between waiting and closing,
// and closing used to be immediate — which turned every burst into a
// disconnection, and every disconnection into a round of failed negotiations
// that produced the next burst.
//
// Now it waits first. The write loop drains at socket speed, so a queue that
// clears at all clears in milliseconds; one that is still full after
// enqueueWait belongs to a peer that has stopped reading, and that peer is
// better off closed and reconnecting.
func (c *conn) enqueue(e Envelope) {
	select {
	case c.send <- e:
		return
	case <-c.closed:
		return
	default:
	}

	t := time.NewTimer(enqueueWait)
	defer t.Stop()
	select {
	case c.send <- e:
	case <-c.closed:
	case <-t.C:
		c.close()
	}
}

func (c *conn) writeLoop(ctx context.Context, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case e := <-c.send:
			data, err := json.Marshal(e)
			if err != nil {
				log.Warn("signal: encoding envelope", "err", err)
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, writeWait)
			err = c.ws.Write(wctx, websocket.MessageText, data)
			cancel()
			if err != nil {
				c.close()
				return
			}
		}
	}
}

func (c *conn) pingLoop(ctx context.Context) {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, writeWait)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				c.close()
				return
			}
		}
	}
}

func (c *conn) close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		// Guarded because close is reached from several paths and one of them
		// is reachable before the socket exists — and a nil dereference here
		// would take the whole signalling server down with it, which is the one
		// process every machine in the mesh depends on.
		if c.ws != nil {
			_ = c.ws.Close(websocket.StatusNormalClosure, "")
		}
	})
}

// short trims a public key for logging. A full key in every line makes the log
// unreadable, and the first characters are enough to tell peers apart.
func short(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8]
}
