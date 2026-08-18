// Package engine runs one machine's side of the mesh.
//
// It owns the three pieces that have to agree with each other: the signalling
// connection that reaches peers there is no path to yet, one negotiation per
// peer, and the local WireGuard that carries the traffic once a path exists.
// Keeping them in one place is what makes the interesting rule expressible —
// that a peer whose path was renegotiated only needs its endpoint moved, not a
// new tunnel.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/rogerlovato2/netflow-agent/internal/p2p"
	"github.com/rogerlovato2/netflow-agent/internal/signal"
	"github.com/rogerlovato2/netflow-agent/internal/tunnel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// retryMin and retryMax bound the wait before a failed negotiation is tried
	// again. A path can fail because the peer is briefly gone, in which case a
	// quick retry wins, or because it is off for the weekend, in which case
	// anything short is just noise on the signal server.
	retryMin = 2 * time.Second
	retryMax = 60 * time.Second

	// negotiateTimeout bounds one attempt.
	//
	// Without it a lost offer is fatal rather than expensive: the session waits
	// for credentials that were dropped somewhere and nothing ever wakes it, so
	// the retry loop below — the entire recovery mechanism — never gets to run.
	// Every message here crosses a WebSocket that may have been reconnecting,
	// and a peer may have restarted mid-negotiation, so losing one is ordinary.
	negotiateTimeout = 25 * time.Second

	// handshakeStagger delays one of the two sides before it hands the path to
	// WireGuard.
	//
	// WireGuard keeps a single handshake slot per peer, so an initiation that
	// arrives overwrites the state your own outgoing initiation is waiting on,
	// and the response that comes back is then rejected as invalid. Two peers
	// that come up together initiate together and knock each other down; they
	// recover only when their five-second retries happen not to collide, which
	// took as long as thirty-six seconds in testing and produced a tunnel that
	// reported itself connected the whole time.
	//
	// The ICE tie-break already names one side. Letting the other go first
	// costs this delay once, and turns a race that resolves eventually into a
	// handshake that completes on the first attempt.
	handshakeStagger = 700 * time.Millisecond

	// earlyMessages is how much signalling is held for a session that does not
	// exist yet.
	//
	// Two machines told about each other at the same moment race: whichever
	// starts first offers into a peer whose session is still being built. That
	// offer is not junk, it is the negotiation, and dropping it costs a full
	// retry cycle.
	earlyMessages = 32
)

// Peer is a peer this machine should have a tunnel to.
type Peer struct {
	PublicKey    wgtypes.Key
	PresharedKey wgtypes.Key
	// AllowedIPs is what may travel to and from this peer. WireGuard drops a
	// decrypted packet whose source is not in here, whatever key signed it, so
	// this is the access control and not a routing hint.
	AllowedIPs []netip.Prefix
}

// Config is what an engine needs to come up.
type Config struct {
	PrivateKey wgtypes.Key
	// Addresses are this machine's addresses inside the tunnel.
	Addresses []netip.Addr
	// DNS is handed to the userspace stack. Empty is fine.
	DNS []netip.Addr
	MTU int
	// SignalURL is the ws:// or wss:// address of the signalling server.
	SignalURL string

	// Userspace keeps the network stack inside this process instead of
	// creating an interface the operating system can see.
	//
	// It needs no privilege and leaves no trace on the host, which is what
	// makes the end-to-end tests honest — and it also means nothing outside
	// this process can reach the mesh. `ping` finds no route and goes to the
	// default gateway. It is for tests and for a machine that only wants to
	// forward its own connections; a client wants the interface.
	Userspace bool

	// TUNName is the interface to create. Empty takes the default, and macOS
	// ignores it entirely because the kernel names utun devices itself.
	TUNName string
	// P2P configures candidate gathering. Its PrivateKey is filled in from the
	// one above, so there is only ever one key to get right.
	P2P p2p.Config
}

// Engine is one machine in the mesh.
type Engine struct {
	cfg Config
	log *slog.Logger

	dev *tunnel.Device
	sig *signal.Client

	mu    sync.Mutex
	peers map[string]*peerLink
}

// peerLink is everything the engine holds for one peer.
type peerLink struct {
	spec   Peer
	cancel context.CancelFunc
	done   chan struct{}
	// wake cuts the wait between attempts short.
	//
	// Two peers that back off independently drift apart: one settles into a
	// minute between tries while the other is still trying every few seconds,
	// and their windows stop overlapping — each one offering into a peer that
	// is asleep, forever. Signalling arriving for an idle link is the best
	// evidence there is that the peer is awake and trying right now, so it
	// starts an attempt instead of being buffered for one that is a minute away.
	wake chan struct{}

	mu      sync.Mutex
	session *p2p.Session
	proxy   *tunnel.Proxy
	state   p2p.State
	// early holds signalling that arrived before there was a session to give it
	// to, replayed in order the moment one exists.
	early []signal.Message
	// attemptCancel ends the negotiation currently in flight. It exists so a
	// peer that restarted can be followed: the only way to join its new attempt
	// is to abandon ours and start one of our own.
	attemptCancel context.CancelFunc
}

// New builds the engine and its device. Nothing touches the network until Run.
func New(cfg Config, log *slog.Logger) (*Engine, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	cfg.P2P.PrivateKey = cfg.PrivateKey

	var dev *tunnel.Device
	var err error
	if cfg.Userspace {
		dev, err = tunnel.NewUserspaceDevice(cfg.Addresses, cfg.DNS, cfg.MTU, log)
	} else {
		dev, err = tunnel.NewTUNDevice(cfg.TUNName, cfg.Addresses, cfg.MTU, log)
	}
	if err != nil {
		return nil, err
	}
	// Port zero: the engine does not care which port WireGuard listens on,
	// because nothing outside this machine ever addresses it. The proxies find
	// it through ListenPort.
	if err := dev.Configure(cfg.PrivateKey, 0); err != nil {
		_ = dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		_ = dev.Close()
		return nil, err
	}

	return &Engine{
		cfg:   cfg,
		log:   log,
		dev:   dev,
		sig:   signal.NewClient(cfg.SignalURL, cfg.PrivateKey, log),
		peers: map[string]*peerLink{},
	}, nil
}

// PublicKey is this machine's name everywhere in the mesh.
func (e *Engine) PublicKey() wgtypes.Key { return e.cfg.PrivateKey.PublicKey() }

// Device exposes the WireGuard instance, which is how a caller reaches anything
// inside the tunnel.
func (e *Engine) Device() *tunnel.Device { return e.dev }

// SignalConnected reports whether this machine can currently be reached for
// negotiation. It is the first thing to look at when a peer will not connect:
// without signalling there is no way to exchange candidates, and every
// negotiation fails the same way a NAT problem would.
func (e *Engine) SignalConnected() bool { return e.sig.Connected() }

// Run keeps the engine going until ctx ends.
func (e *Engine) Run(ctx context.Context) error {
	e.sig.OnMessage(e.dispatch)
	go e.sig.Run(ctx)

	<-ctx.Done()
	e.closeAllPeers()
	return e.dev.Close()
}

// SetPeers reconciles the desired set of peers against what is running.
//
// It is written as a reconcile rather than add/remove calls because that is the
// shape the management server will deliver: a full network map on every update,
// where what changed is whatever differs from what is already here.
func (e *Engine) SetPeers(ctx context.Context, peers []Peer) {
	wanted := make(map[string]Peer, len(peers))
	for _, p := range peers {
		wanted[p.PublicKey.String()] = p
	}

	e.mu.Lock()
	// Gone from the map means gone from the mesh.
	for key, link := range e.peers {
		if _, keep := wanted[key]; !keep {
			delete(e.peers, key)
			go e.retire(link, key)
		}
	}
	// New, or changed enough to need rebuilding.
	var starting []*peerLink
	for key, spec := range wanted {
		if existing, ok := e.peers[key]; ok {
			existing.mu.Lock()
			existing.spec = spec
			existing.mu.Unlock()
			continue
		}
		link := &peerLink{
			spec:  spec,
			done:  make(chan struct{}),
			wake:  make(chan struct{}, 1),
			state: p2p.StateIdle,
		}
		e.peers[key] = link
		starting = append(starting, link)

		// The route goes in with the peer and not when it connects. Until the
		// tunnel is up the packet enters the interface and is dropped there,
		// which is what should happen; without the route it would go to the
		// default gateway, and a mesh address on the local network is both
		// wrong and quiet about it.
		for _, a := range spec.AllowedIPs {
			if rerr := e.dev.AddRoute(a); rerr != nil {
				e.log.Warn("engine: could not route to a peer",
					"peer", short(spec.PublicKey), "prefix", a, "err", rerr)
			}
		}
	}
	e.mu.Unlock()

	for _, link := range starting {
		lctx, cancel := context.WithCancel(ctx)
		link.cancel = cancel
		go e.keepPeerConnected(lctx, link)
	}
}

// PeerState reports where a peer's negotiation stands.
func (e *Engine) PeerState(pub wgtypes.Key) p2p.State {
	e.mu.Lock()
	link, ok := e.peers[pub.String()]
	e.mu.Unlock()
	if !ok {
		return p2p.StateIdle
	}
	link.mu.Lock()
	defer link.mu.Unlock()
	return link.state
}

// SetRelay points later negotiations at a relay.
//
// It takes effect on the next attempt rather than the ones already running: an
// ICE agent gathers its candidates once, at the start, so a relay learned
// halfway through a negotiation cannot join it. That is the right trade — a
// pair that is already connected does not need a relay, and one that is failing
// will retry within seconds and pick it up then.
func (e *Engine) SetRelay(url, username, password string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if url == "" {
		e.cfg.P2P.TURN = nil
		return
	}
	e.cfg.P2P.TURN = []p2p.TURNServer{{URL: url, Username: username, Password: password}}
}

// p2pConfig is a copy taken under the lock.
//
// The relay can change while a negotiation is being set up — a map arrives on
// one goroutine while another is building a session — and reading the field
// directly is a race the tests would not catch, because they never configure a
// relay at all.
func (e *Engine) p2pConfig() p2p.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.cfg.P2P
	if len(c.TURN) > 0 {
		c.TURN = append([]p2p.TURNServer(nil), c.TURN...)
	}
	return c
}

// RelayConfigured reports whether a pair with no direct path has somewhere to
// fall back to. Asked of the engine and not of a file, because the relay
// arrives with the network map and the file only knows what it was last told.
func (e *Engine) RelayConfigured() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.cfg.P2P.TURN) > 0
}

// PeerKeys is every peer this engine is currently working on.
//
// It is the authority on that question, and the configuration file is not: the
// file is the last map that was written down, while this is what the engine is
// actually negotiating and carrying right now. Anything describing the machine
// to somebody else should ask here.
func (e *Engine) PeerKeys() []wgtypes.Key {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]wgtypes.Key, 0, len(e.peers))
	for _, l := range e.peers {
		l.mu.Lock()
		out = append(out, l.spec.PublicKey)
		l.mu.Unlock()
	}
	return out
}

// PeerPath reports the route in use for a peer, which is the only way anything
// outside this process learns whether a tunnel is direct or being relayed.
func (e *Engine) PeerPath(pub wgtypes.Key) p2p.Path {
	e.mu.Lock()
	link, ok := e.peers[pub.String()]
	e.mu.Unlock()
	if !ok {
		return p2p.Path{}
	}
	link.mu.Lock()
	sess := link.session
	link.mu.Unlock()
	if sess == nil {
		return p2p.Path{}
	}
	return sess.Path()
}

// keepPeerConnected negotiates, wires the result into WireGuard, and does it
// again whenever the path dies. It returns only when the peer is retired.
func (e *Engine) keepPeerConnected(ctx context.Context, link *peerLink) {
	defer close(link.done)

	delay := retryMin
	for ctx.Err() == nil {
		err := e.connectOnce(ctx, link)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			e.log.Debug("engine: peer connection ended",
				"peer", short(link.spec.PublicKey), "err", err, "retry_in", delay)
		}

		select {
		case <-ctx.Done():
			return
		case <-link.wake:
			// The peer is trying right now. Meeting it beats waiting.
			delay = retryMin
			continue
		case <-time.After(jitter(delay)):
		}
		delay = min(delay*2, retryMax)
		// A connection that lasted means the peer is reachable and something
		// transient broke it; the next attempt should not inherit a backoff
		// built up by an outage that is over.
		if err == nil {
			delay = retryMin
		}
	}
}

// connectOnce runs one negotiation and stays until the resulting path dies.
func (e *Engine) connectOnce(ctx context.Context, link *peerLink) error {
	link.mu.Lock()
	spec := link.spec
	link.mu.Unlock()

	// A fresh session every attempt. ICE credentials identify an attempt, and a
	// retry that reused them would be answered with checks belonging to the
	// attempt that already failed.
	sess := p2p.NewSession(e.PublicKey(), spec.PublicKey, e.p2pConfig(), e.signaller(), e.log)

	// Its own context, so a peer that restarted can end this attempt without
	// ending the peer.
	ctx, abandon := context.WithCancel(ctx)
	defer abandon()

	// Nothing held for this attempt outlives it. Whatever is still buffered
	// when it ends belongs to a negotiation that is over, and the next attempt
	// inheriting it is the same poisoning this guards against on arrival.
	defer func() {
		link.mu.Lock()
		link.early = nil
		link.session = nil
		link.mu.Unlock()
	}()

	link.mu.Lock()
	link.session = sess
	link.state = p2p.StateNegotiating
	link.attemptCancel = abandon
	early := link.early
	link.early = nil
	link.mu.Unlock()

	sess.OnStateChange(func(st p2p.State) {
		// Connected is not adopted from the session. ICE finishing means a path
		// exists, not that anything can use it: the engine still has to build a
		// proxy and tell WireGuard about it. Reporting connected in between
		// gives a status display a state in which it claims a working tunnel
		// while the first packet has nowhere to go — and gives anything reading
		// that state a race it cannot see.
		if st == p2p.StateConnected {
			return
		}
		link.mu.Lock()
		link.state = st
		link.mu.Unlock()
	})
	defer sess.Close()

	// Whatever the peer sent while this session was being built.
	for _, m := range early {
		feed(sess, m)
	}

	// Only the negotiation is bounded. Once there is a path the proxy runs for
	// as long as it lasts, which is the point.
	nctx, stopWaiting := context.WithTimeout(ctx, negotiateTimeout)
	err := sess.Start(nctx)
	stopWaiting()
	if err != nil {
		return err
	}

	wgPort, err := e.dev.ListenPort()
	if err != nil {
		return fmt.Errorf("engine: reading the WireGuard port: %w", err)
	}
	proxy, err := tunnel.NewProxy(sess.Conn(), wgPort, e.log)
	if err != nil {
		return err
	}
	defer proxy.Close()

	link.mu.Lock()
	link.proxy = proxy
	link.mu.Unlock()

	// The pumps start before WireGuard is told anything.
	//
	// WireGuard initiates a handshake the instant it learns about a peer, and
	// the peer's own initiation crosses at the same moment. A path with nobody
	// reading it yet drops what arrives, so configuring first cost a lost
	// initiation and a five-second retry on every single connect — a delay that
	// looked like slow NAT traversal and was entirely self-inflicted.
	runErr := make(chan error, 1)
	go func() { runErr <- proxy.Run(ctx) }()

	// One side goes first, so the two initiations do not cross. Which side does
	// not matter as long as both agree, and they already do: the same tie-break
	// that decided who offers decides who waits.
	if !sess.Controlling() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(handshakeStagger):
		}
	}

	// WireGuard learns about the peer only now, pointed at the proxy rather than
	// at anything real. If the peer was already configured this moves it, which
	// is what a renegotiated path costs: an endpoint update, no new handshake,
	// no interruption to whatever was running above it.
	if _, known := e.dev.PeerEndpoint(spec.PublicKey); known {
		err = e.dev.SetPeerEndpoint(spec.PublicKey, proxy.Endpoint())
	} else {
		err = e.dev.SetPeer(tunnel.Peer{
			PublicKey:    spec.PublicKey,
			PresharedKey: spec.PresharedKey,
			Endpoint:     proxy.Endpoint(),
			AllowedIPs:   spec.AllowedIPs,
			// Both ends are usually behind NAT and neither can tell, so the
			// keepalive is unconditional. Its cost is one small packet every
			// twenty-five seconds; its absence is a tunnel that works until it
			// goes quiet for a minute.
			KeepaliveSeconds: 25,
		})
	}
	if err != nil {
		return err
	}

	// Now it is true.
	link.mu.Lock()
	link.state = p2p.StateConnected
	link.mu.Unlock()

	e.log.Info("engine: peer connected", "peer", short(spec.PublicKey))
	return <-runErr
}

// retire tears a peer down and forgets it.
func (e *Engine) retire(link *peerLink, key string) {
	if link.cancel != nil {
		link.cancel()
	}
	<-link.done

	link.mu.Lock()
	spec := link.spec
	link.mu.Unlock()

	for _, a := range spec.AllowedIPs {
		if rerr := e.dev.DelRoute(a); rerr != nil {
			e.log.Debug("engine: could not remove a peer's route",
				"peer", short(spec.PublicKey), "prefix", a, "err", rerr)
		}
	}
	if err := e.dev.RemovePeer(spec.PublicKey); err != nil {
		e.log.Debug("engine: removing a peer from the device", "peer", short(spec.PublicKey), "err", err)
	}
	e.log.Info("engine: peer retired", "peer", key[:min(8, len(key))])
}

func (e *Engine) closeAllPeers() {
	e.mu.Lock()
	links := make([]*peerLink, 0, len(e.peers))
	for _, l := range e.peers {
		links = append(links, l)
	}
	e.peers = map[string]*peerLink{}
	e.mu.Unlock()

	for _, l := range links {
		if l.cancel != nil {
			l.cancel()
		}
		<-l.done
	}
}

// dispatch routes an opened signal message to the session it belongs to.
//
// A message from somebody who is not a configured peer is dropped: the sealed
// body proves who sent it, but not that this machine has any business talking
// to them, and that decision belongs to the peer list.
func (e *Engine) dispatch(m signal.Message) {
	e.mu.Lock()
	link, ok := e.peers[m.From.String()]
	e.mu.Unlock()
	if !ok {
		e.log.Debug("engine: signal from someone who is not a peer", "from", short(m.From))
		return
	}

	link.mu.Lock()
	sess := link.session
	if sess == nil {
		// The session is still being built. Holding the message is the whole
		// difference between a negotiation that starts now and one that starts
		// after a retry cycle.
		// A fresh offer or answer starts a new attempt on the peer's side, so
		// everything held from before it is dead: replaying it would hand the
		// session about to be built the credentials of an attempt the peer has
		// already discarded, and that session would then spend its whole
		// negotiation timeout checking against them.
		if m.Kind == signal.KindOffer || m.Kind == signal.KindAnswer {
			link.early = link.early[:0]
		}
		if len(link.early) < earlyMessages {
			link.early = append(link.early, m)
		}
		link.mu.Unlock()

		// Nothing is running for this peer, and it just proved it is awake.
		select {
		case link.wake <- struct{}{}:
		default:
		}
		return
	}
	link.mu.Unlock()

	switch m.Kind {
	case signal.KindOffer, signal.KindAnswer:
		if sess.SetRemoteCredentials(m.Body.UFrag, m.Body.Pwd) {
			return
		}
		// The peer is on a newer attempt than this session can join. Abandoning
		// ours sends the retry loop straight into a fresh one, which is the only
		// thing that converges: left alone, both ends keep checking with
		// credentials the other has already discarded and neither ever fails
		// fast enough to notice.
		e.log.Debug("engine: peer restarted its negotiation, following it",
			"peer", short(m.From))
		link.mu.Lock()
		abandon := link.attemptCancel
		link.mu.Unlock()
		if abandon != nil {
			abandon()
		}
	case signal.KindCandidate:
		sess.AddRemoteCandidate(m.Body.Candidate)
	case signal.KindOffline:
		// Nothing to do beyond noting it. The negotiation will time out on its
		// own and the retry loop is already the right response; tearing down
		// here would only race with it.
		e.log.Debug("engine: peer is not on the signal server", "peer", short(m.From))
	}
}

// feed hands one signalling message to a session.
func feed(sess *p2p.Session, m signal.Message) {
	switch m.Kind {
	case signal.KindOffer, signal.KindAnswer:
		sess.SetRemoteCredentials(m.Body.UFrag, m.Body.Pwd)
	case signal.KindCandidate:
		sess.AddRemoteCandidate(m.Body.Candidate)
	}
}

// signaller adapts the signal client to what a session expects.
func (e *Engine) signaller() p2p.Signaller { return sigLink{e.sig} }

type sigLink struct{ c *signal.Client }

func (s sigLink) SendOffer(to wgtypes.Key, ufrag, pwd string) error {
	return s.c.Send(to, signal.KindOffer, signal.Body{UFrag: ufrag, Pwd: pwd})
}

func (s sigLink) SendAnswer(to wgtypes.Key, ufrag, pwd string) error {
	return s.c.Send(to, signal.KindAnswer, signal.Body{UFrag: ufrag, Pwd: pwd})
}

func (s sigLink) SendCandidate(to wgtypes.Key, cand string) error {
	return s.c.Send(to, signal.KindCandidate, signal.Body{Candidate: cand})
}

func short(k wgtypes.Key) string {
	s := k.String()
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// jitter spreads retries out, so a signal server coming back up is not met by
// every agent that lost it arriving in the same millisecond.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}
