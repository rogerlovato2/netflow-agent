package signal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// outQueue holds envelopes while the socket is down. A reconnect takes
	// seconds and a negotiation produces a few dozen candidates, so the queue
	// exists to carry one negotiation across one reconnect — not to hold a
	// backlog, which would only deliver candidates too stale to be useful.
	outQueue = 128

	// backoffMin and backoffMax bound the reconnect delay. The minimum is short
	// because the common case is a socket that died with the peer perfectly
	// online; the maximum is what keeps a thousand agents from hammering a
	// signal server that is coming back up.
	backoffMin = 500 * time.Millisecond
	backoffMax = 30 * time.Second

	// clientPingEvery is how often the client proves to itself that the path is
	// still there.
	//
	// The server pings too, but that only protects the server: the failure this
	// exists for is the one where nothing is closed and no FIN is ever sent —
	// a laptop that walks off Wi-Fi, a NAT that drops the mapping, a router
	// rebooted mid-session. Read blocks forever on such a socket, Connected()
	// keeps answering true, and the agent sits there believing it is reachable
	// while nobody can negotiate with it. A ping that expects a pong is the only
	// way to find out.
	//
	// Shorter than the server's interval on purpose: whoever notices first
	// closes, and it should be the side that can do something about it.
	clientPingEvery = 20 * time.Second

	// pingWait bounds the wait for a pong. A signal server on the other side of
	// the world answers in a fraction of a second; ten is not a threshold a
	// healthy path ever reaches.
	pingWait = 10 * time.Second
)

// Message is an envelope that arrived and was opened.
type Message struct {
	From wgtypes.Key
	Kind Kind
	Body Body
}

// Client keeps one socket to the signal server, reconnecting for as long as its
// context lives.
//
// Send never blocks on the network: envelopes go to a queue that the writer
// drains whenever there is a socket. That is what lets the engine trickle
// candidates without caring whether the signal server is up at this instant.
type Client struct {
	url  string
	priv wgtypes.Key
	pub  wgtypes.Key
	log  *slog.Logger

	out chan outbound

	// pingEvery and pingWait are fields rather than constants only so tests can
	// shorten them: a dead path is otherwise a twenty-second wait to reproduce.
	pingEvery time.Duration
	pingWait  time.Duration

	mu      sync.RWMutex
	handler func(Message)
	up      bool
	// drop ends the live session. See Reset.
	drop context.CancelFunc
}

func NewClient(url string, priv wgtypes.Key, log *slog.Logger) *Client {
	return &Client{
		url:       url,
		priv:      priv,
		pub:       priv.PublicKey(),
		log:       log,
		out:       make(chan outbound, outQueue),
		pingEvery: clientPingEvery,
		pingWait:  pingWait,
	}
}

// OnMessage sets the handler for opened envelopes. It runs on the reader
// goroutine, so it must not block: anything slow belongs on the caller's side.
func (c *Client) OnMessage(f func(Message)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handler = f
}

// Connected reports whether there is a live socket right now.
func (c *Client) Connected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.up
}

// Send seals a body for `to` and queues it.
//
// A full queue is reported rather than silently dropped: losing a candidate
// makes a connection fail in a way that looks exactly like a NAT problem, and
// the caller is the only one that can tell the difference.
func (c *Client) Send(to wgtypes.Key, kind Kind, b Body) error {
	sealed, err := Seal(b, c.priv, to)
	if err != nil {
		return err
	}
	return c.queue(outbound{env: c.envelope(to, kind, sealed)})
}

// SendNow is Send, but it waits until the writer has put the message on the
// socket or the wait runs out.
//
// It exists for the last message a process sends. Send hands the envelope to a
// queue and returns; a process that exits, or a context that is cancelled, in
// the moment between those two things sends nothing at all — and the one
// message where that matters is the one announcing that this machine is going
// away.
func (c *Client) SendNow(to wgtypes.Key, kind Kind, b Body, wait time.Duration) error {
	sealed, err := Seal(b, c.priv, to)
	if err != nil {
		return err
	}
	written := make(chan struct{})
	if err := c.queue(outbound{env: c.envelope(to, kind, sealed), written: written}); err != nil {
		return err
	}
	select {
	case <-written:
		return nil
	case <-time.After(wait):
		return errors.New("signal: the message did not reach the socket in time")
	}
}

func (c *Client) envelope(to wgtypes.Key, kind Kind, sealed []byte) Envelope {
	return Envelope{Kind: kind, From: c.pub.String(), To: to.String(), Body: sealed}
}

func (c *Client) queue(o outbound) error {
	select {
	case c.out <- o:
		return nil
	default:
		return errors.New("signal: outbound queue is full")
	}
}

// outbound is an envelope on its way out, and optionally somebody waiting to
// hear that it left.
type outbound struct {
	env Envelope
	// written is closed once the writer has handed the bytes to the socket, or
	// given up on them. Nil when nobody is waiting, which is almost always.
	written chan struct{}
}

// Run keeps the client connected until ctx is done. It only returns on ctx.
func (c *Client) Run(ctx context.Context) {
	delay := backoffMin
	for ctx.Err() == nil {
		err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		// At info, and this is the whole reason: a session that drops and comes
		// back in under a second leaves no trace anybody looks at, and an agent
		// doing it every quarter of an hour looks perfectly healthy from the
		// outside. It is not healthy — every peer that tries to negotiate
		// during one of those gaps is told this machine is offline, and a pair
		// that lands in enough of them stays down for hours.
		//
		// Thirty of these went unexplained in one day because the line that
		// would have explained them was invisible. Reconnecting is normal;
		// reconnecting constantly is a fault, and the difference is only
		// legible if the reconnections are written down.
		c.log.Info("signal: session ended, reconnecting", "err", err, "in", delay)

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(delay)):
		}
		delay = min(delay*2, backoffMax)

		// A session that lasted is evidence the server is healthy, so the next
		// failure should retry fast rather than inherit the long delay that an
		// earlier outage built up.
		if err == nil {
			delay = backoffMin
		}
	}
}

// Reset ends the current session so the next one is dialled fresh.
//
// The socket can be alive and useless. The ping proves the path is there and
// proves nothing about the server on the other end of it: one that has been
// restarted, or upgraded, or has quietly stopped relaying for this key, answers
// every ping and delivers nothing. From here that looks exactly like a mesh
// where nobody wants to talk, and no timeout will ever fire.
//
// So something that can tell the difference — the engine, which knows whether
// any peer has connected lately — gets to say "try that again from scratch".
// Reconnecting costs one websocket and disturbs no tunnel that is already up.
func (c *Client) Reset() {
	c.mu.Lock()
	drop := c.drop
	c.mu.Unlock()
	if drop != nil {
		c.log.Info("signal: reconnecting on request")
		drop()
	}
}

// session runs one socket from dial to death.
func (c *Client) session(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	ws, _, err := websocket.Dial(dialCtx, c.url, nil)
	cancel()
	if err != nil {
		return err
	}
	ws.SetReadLimit(maxFrame)
	defer ws.CloseNow()

	ctx, stop := context.WithCancel(ctx)
	defer stop()

	c.mu.Lock()
	c.drop = stop
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.drop = nil
		c.mu.Unlock()
	}()

	hello, err := json.Marshal(Envelope{Kind: KindHello, From: c.pub.String()})
	if err != nil {
		return err
	}
	wctx, wcancel := context.WithTimeout(ctx, writeWait)
	err = ws.Write(wctx, websocket.MessageText, hello)
	wcancel()
	if err != nil {
		return err
	}

	c.setUp(true)
	defer c.setUp(false)
	c.log.Info("signal: connected", "url", c.url, "key", short(c.pub.String()))

	errCh := make(chan error, 3)
	go func() { errCh <- c.writeLoop(ctx, ws) }()
	go func() { errCh <- c.readLoop(ctx, ws) }()
	go func() { errCh <- c.pingLoop(ctx, ws) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *Client) writeLoop(ctx context.Context, ws *websocket.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case o := <-c.out:
			data, err := json.Marshal(o.env)
			if err != nil {
				c.log.Warn("signal: encoding envelope", "err", err)
				closeIf(o.written)
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, writeWait)
			err = ws.Write(wctx, websocket.MessageText, data)
			cancel()
			// Whoever is waiting is told either way: they are waiting to stop
			// waiting, not to be promised delivery.
			closeIf(o.written)
			if err != nil {
				// The envelope is lost with the socket. Requeuing it would
				// deliver a candidate from a session the other side has already
				// abandoned, which is worse than the gap: the engine restarts
				// negotiation on reconnect anyway.
				return err
			}
		}
	}
}

// pingLoop is the client's only way to find out that a socket which was never
// closed has stopped carrying anything. Ping blocks until the pong comes back,
// so a failure here means the path is gone, and returning ends the session and
// sends Run into a reconnect.
func (c *Client) pingLoop(ctx context.Context, ws *websocket.Conn) error {
	t := time.NewTicker(c.pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, c.pingWait)
			err := ws.Ping(pctx)
			cancel()
			if err != nil {
				c.log.Info("signal: no pong within the wait; the path is gone", "err", err)
				return err
			}
		}
	}
}

func (c *Client) readLoop(ctx context.Context, ws *websocket.Conn) error {
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		var e Envelope
		if err := json.Unmarshal(data, &e); err != nil {
			c.log.Debug("signal: undecodable frame", "err", err)
			continue
		}
		msg, ok := c.open(e)
		if !ok {
			continue
		}
		c.mu.RLock()
		h := c.handler
		c.mu.RUnlock()
		if h != nil {
			h(msg)
		}
	}
}

// open turns a wire envelope into a Message, decrypting the body when there is
// one. It rejects rather than reports: a body that will not open came from
// someone who is not who they claim to be, and there is nothing useful to do
// with it beyond dropping it.
func (c *Client) open(e Envelope) (Message, bool) {
	from, err := wgtypes.ParseKey(e.From)
	if err != nil {
		c.log.Debug("signal: envelope with an unparseable sender", "from", e.From)
		return Message{}, false
	}
	// The server generates these itself and has no key to seal with, which is
	// exactly why it can only say "that peer is not here" and nothing more.
	if e.Kind == KindOffline || len(e.Body) == 0 {
		return Message{From: from, Kind: e.Kind}, true
	}
	body, err := Open(e.Body, c.priv, from)
	if err != nil {
		c.log.Debug("signal: body did not open", "from", short(e.From), "err", err)
		return Message{}, false
	}
	return Message{From: from, Kind: e.Kind, Body: body}, true
}

func (c *Client) setUp(v bool) {
	c.mu.Lock()
	c.up = v
	c.mu.Unlock()
}

// jitter spreads reconnects out. Without it every agent that lost the same
// server comes back at the same millisecond and knocks it over again.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}

func closeIf(ch chan struct{}) {
	if ch != nil {
		close(ch)
	}
}
