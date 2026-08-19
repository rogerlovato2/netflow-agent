package p2p

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Session is one peer, and the attempt to reach it.
//
// announceEvery is how often an attempt repeats its credentials while it waits.
//
// Two seconds: short enough that a machine which learns about its peer a poll
// later still meets it within a poll, long enough that an attempt which is
// simply going to fail sends a handful of messages rather than a stream.
const announceEvery = 2 * time.Second

// It owns exactly one ICE agent at a time. A failed negotiation does not reuse
// the agent: ICE credentials identify an attempt, and a retry that kept them
// would be answered with checks from the attempt that already failed. Restart
// therefore means a new agent, new credentials, and a new offer.
type Session struct {
	remote      wgtypes.Key
	controlling bool
	cfg         Config
	sig         Signaller
	log         *slog.Logger

	// onState is called outside the lock whenever the state changes, so a
	// handler is free to call back into the session without deadlocking.
	onState func(State)

	mu    sync.Mutex
	agent *ice.Agent
	conn  *ice.Conn
	state State

	// remoteUfrag and remotePwd arrive in the offer or the answer, and are what
	// Dial and Accept wait for.
	remoteUfrag string
	remotePwd   string
	credsReady  chan struct{}
	// settled is closed once there is a path. It is what stops the offer being
	// repeated: receiving the peer's credentials is not the same as the peer
	// having received ours, and stopping on the first would leave the other
	// side waiting for something nobody is sending any more.
	settled chan struct{}

	// pending holds candidates that arrived before there was an agent to give
	// them to. On the answering side this is the normal case, not an edge one:
	// the other peer starts trickling the moment it offers, and the offer and
	// its first candidates cross the signal server back to back.
	pending []string

	closed bool
}

// NewSession prepares a session. Nothing happens on the network until Start.
func NewSession(local wgtypes.Key, remote wgtypes.Key, cfg Config, sig Signaller, log *slog.Logger) *Session {
	return &Session{
		remote:      remote,
		controlling: controls(local, remote),
		cfg:         cfg,
		sig:         sig,
		log:         log.With("peer", shortKey(remote)),
		state:       StateIdle,
		credsReady:  make(chan struct{}),
		settled:     make(chan struct{}),
	}
}

// Path describes what the negotiation settled on.
//
// Kind is the distinction that matters operationally: "direct" means the two
// machines are exchanging packets themselves, "relay" means a TURN server is
// carrying them and paying for every byte. A pair that looks connected can be
// either, and from a status line they are indistinguishable — which is exactly
// why it is reported.
type Path struct {
	Kind   string // "direct" | "relay" | "" when there is no path
	Local  string
	Remote string
	RTT    time.Duration
}

// Path is the route in use, or a zero Path if there is not one.
func (s *Session) Path() Path {
	s.mu.Lock()
	agent := s.agent
	connected := s.conn != nil
	s.mu.Unlock()
	if agent == nil || !connected {
		return Path{}
	}

	pair, err := agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return Path{}
	}
	kind := "direct"
	if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		kind = "relay"
	}
	p := Path{Kind: kind, Local: pair.Local.String(), Remote: pair.Remote.String()}
	if st, ok := agent.GetSelectedCandidatePairStats(); ok {
		p.RTT = time.Duration(st.CurrentRoundTripTime * float64(time.Second))
	}
	return p
}

// Remote is the peer this session is for.
func (s *Session) Remote() wgtypes.Key { return s.remote }

// Controlling reports whether this side sends the offer.
func (s *Session) Controlling() bool { return s.controlling }

// State is where the session is right now.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// OnStateChange registers a callback. It must be set before Start.
func (s *Session) OnStateChange(f func(State)) { s.onState = f }

// Conn is the negotiated path, or nil if there is not one yet.
func (s *Session) Conn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn
}

// Start begins a negotiation and blocks until there is a path or ctx ends.
//
// The controlling side offers and dials; the other answers and accepts. Both
// gather and trickle throughout — waiting for gathering to finish before
// sending anything would add the slowest STUN server's timeout to every
// connection, and host candidates, which are all a LAN needs, are known at once.
func (s *Session) Start(ctx context.Context) error {
	agent, err := s.newAgent()
	if err != nil {
		return err
	}

	s.setState(StateNegotiating)

	// The offer must go out before gathering starts. The other side needs the
	// credentials to make sense of the candidates that follow, and on a LAN the
	// first candidate is produced almost immediately.
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return fmt.Errorf("p2p: reading local credentials: %w", err)
	}
	if err := s.announce(ufrag, pwd); err != nil {
		return fmt.Errorf("p2p: sending credentials: %w", err)
	}
	// And again, until the other side answers.
	//
	// Sending once assumes somebody was listening, and there is a common moment
	// when nobody was: the two machines learn about each other from the
	// management server at different times, up to a poll apart. Whoever hears
	// first offers into a peer that has no session yet, the message is dropped
	// as coming from a stranger, and that attempt then spends its whole
	// timeout waiting for a reply to something the other end never saw. The
	// pair only meets when two attempts happen to line up, which — with a
	// backoff growing between them — is where minutes come from.
	//
	// Re-announcing costs one small message every couple of seconds for as long
	// as an attempt is waiting, and it is idempotent: the same credentials
	// arriving twice are a duplicate the far side already ignores.
	go s.reannounce(ctx, ufrag, pwd)

	if err := agent.GatherCandidates(); err != nil {
		return fmt.Errorf("p2p: gathering candidates: %w", err)
	}

	// Dial and Accept both need the other side's credentials, which arrive on
	// the signal channel at a moment nothing here controls.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.credsReady:
	}

	s.mu.Lock()
	ru, rp := s.remoteUfrag, s.remotePwd
	s.mu.Unlock()

	var conn *ice.Conn
	if s.controlling {
		conn, err = agent.Dial(ctx, ru, rp)
	} else {
		conn, err = agent.Accept(ctx, ru, rp)
	}
	if err != nil {
		s.setState(StateFailed)
		return fmt.Errorf("p2p: no path to the peer: %w", err)
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	close(s.settled)
	s.setState(StateConnected)

	if pair, err := agent.GetSelectedCandidatePair(); err == nil && pair != nil {
		s.log.Info("p2p: path established",
			"local", pair.Local.String(), "remote", pair.Remote.String())
	}
	return nil
}

// newAgent builds the ICE agent and wires its callbacks.
func (s *Session) newAgent() (*ice.Agent, error) {
	cfg, err := agentConfig(s.cfg)
	if err != nil {
		return nil, fmt.Errorf("p2p: building the ICE configuration: %w", err)
	}
	agent, err := ice.NewAgent(cfg)
	if err != nil {
		return nil, fmt.Errorf("p2p: creating the ICE agent: %w", err)
	}

	if err := agent.OnCandidate(func(c ice.Candidate) {
		// A nil candidate is pion saying gathering is over. There is nothing to
		// send: the other side does not wait for an end-of-candidates marker,
		// it just stops receiving.
		if c == nil {
			return
		}
		// Logged because a negotiation that fails is almost always a question
		// of which candidates existed and which arrived, and without this the
		// two are indistinguishable from outside.
		s.log.Debug("p2p: sending candidate", "candidate", c.Marshal())
		if err := s.sig.SendCandidate(s.remote, c.Marshal()); err != nil {
			s.log.Warn("p2p: could not send a candidate", "err", err)
		}
	}); err != nil {
		_ = agent.Close()
		return nil, err
	}

	if err := agent.OnConnectionStateChange(func(st ice.ConnectionState) {
		s.log.Debug("p2p: ice state", "state", st.String())
		if st == ice.ConnectionStateFailed {
			s.setState(StateFailed)
		}
	}); err != nil {
		_ = agent.Close()
		return nil, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = agent.Close()
		return nil, errors.New("p2p: session is closed")
	}
	s.agent = agent
	held := s.pending
	s.pending = nil
	s.mu.Unlock()

	// Whatever arrived before the agent existed is delivered now, in the order
	// it came in.
	for _, raw := range held {
		s.addCandidate(agent, raw)
	}
	return agent, nil
}

// SetRemoteCredentials records what the offer or answer carried. It is what
// Start is blocked on.
//
// It reports whether the session can use them. False means the peer is
// negotiating an attempt this session cannot join: the agent is bound to the
// credentials of the attempt it started with, and ICE checks carrying any
// others are rejected by both ends. There is no way to adopt them in place, so
// the caller has to abandon this session and start a new one — and if it does
// not, the two sides sit there checking with credentials the other has already
// forgotten, which looks exactly like a NAT that will not open.
func (s *Session) SetRemoteCredentials(ufrag, pwd string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.remoteUfrag == "" {
		s.remoteUfrag, s.remotePwd = ufrag, pwd
		close(s.credsReady)
		return true
	}
	// The same credentials again is a duplicate — the peer re-sent its offer,
	// or an answer crossed an offer. Harmless, and emphatically not a reason to
	// tear anything down.
	return s.remoteUfrag == ufrag && s.remotePwd == pwd
}

// AddRemoteCandidate feeds one trickled candidate in.
func (s *Session) AddRemoteCandidate(raw string) {
	s.mu.Lock()
	agent := s.agent
	if agent == nil {
		s.pending = append(s.pending, raw)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.addCandidate(agent, raw)
}

func (s *Session) addCandidate(agent *ice.Agent, raw string) {
	s.log.Debug("p2p: received candidate", "candidate", raw)
	c, err := ice.UnmarshalCandidate(raw)
	if err != nil {
		s.log.Debug("p2p: undecodable candidate", "raw", raw, "err", err)
		return
	}
	if err := agent.AddRemoteCandidate(c); err != nil {
		s.log.Debug("p2p: candidate refused", "raw", raw, "err", err)
	}
}

// Close tears the session down. It is safe to call more than once.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	agent, conn := s.agent, s.conn
	s.agent, s.conn = nil, nil
	s.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if agent != nil {
		_ = agent.Close()
	}
	s.setState(StateClosed)
	return nil
}

// setState records the state and notifies, never holding the lock across the
// callback.
func (s *Session) setState(st State) {
	s.mu.Lock()
	if s.state == st || s.state == StateClosed {
		s.mu.Unlock()
		return
	}
	s.state = st
	f := s.onState
	s.mu.Unlock()

	if f != nil {
		f(st)
	}
}

// shortKey trims a public key for logging: the first characters are enough to
// tell peers apart, and a full key on every line makes a log unreadable.
func shortKey(k wgtypes.Key) string {
	s := k.String()
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// announce sends this attempt's credentials to the peer.
func (s *Session) announce(ufrag, pwd string) error {
	if s.controlling {
		return s.sig.SendOffer(s.remote, ufrag, pwd)
	}
	return s.sig.SendAnswer(s.remote, ufrag, pwd)
}

// reannounce repeats them until the peer answers or the attempt ends.
func (s *Session) reannounce(ctx context.Context, ufrag, pwd string) {
	t := time.NewTicker(announceEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.settled:
			// There is a path, so both ends have everything they need.
			// Stopping at the peer's answer instead would be the same bug seen
			// from the other side: our credentials might still be the thing
			// they are waiting for.
			return
		case <-t.C:
			if err := s.announce(ufrag, pwd); err != nil {
				s.log.Debug("p2p: could not repeat the offer", "err", err)
			}
		}
	}
}
