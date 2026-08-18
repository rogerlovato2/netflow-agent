package p2p

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func key(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k
}

// memHub wires sessions to each other in memory, standing in for the signal
// server. Delivery is asynchronous, because that is what a real signal server
// is, and one goroutine per destination preserves the order candidates were
// sent in.
type memHub struct {
	mu    sync.Mutex
	inbox map[string]chan func()
	subs  map[string]*Session
}

func newMemHub() *memHub {
	return &memHub{inbox: map[string]chan func(){}, subs: map[string]*Session{}}
}

// join registers a session and starts draining its inbox.
func (h *memHub) join(k wgtypes.Key, s *Session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan func(), 256)
	h.inbox[k.String()] = ch
	h.subs[k.String()] = s
	go func() {
		for f := range ch {
			f()
		}
	}()
}

func (h *memHub) deliver(to wgtypes.Key, f func(*Session)) {
	h.mu.Lock()
	ch, ok := h.inbox[to.String()]
	s := h.subs[to.String()]
	h.mu.Unlock()
	if !ok || s == nil {
		return
	}
	select {
	case ch <- func() { f(s) }:
	default:
	}
}

// link is one peer's view of the hub.
type link struct{ h *memHub }

func (l *link) SendOffer(to wgtypes.Key, ufrag, pwd string) error {
	l.h.deliver(to, func(s *Session) { s.SetRemoteCredentials(ufrag, pwd) })
	return nil
}

func (l *link) SendAnswer(to wgtypes.Key, ufrag, pwd string) error {
	l.h.deliver(to, func(s *Session) { s.SetRemoteCredentials(ufrag, pwd) })
	return nil
}

func (l *link) SendCandidate(to wgtypes.Key, cand string) error {
	l.h.deliver(to, func(s *Session) { s.AddRemoteCandidate(cand) })
	return nil
}

// testConfig negotiates entirely on loopback.
//
// No STUN, so the test never touches the internet, and loopback only, so it
// does not depend on which interfaces this machine happens to have or on what
// else is loading it. Gathering from every real interface makes the check
// matrix the product of two candidate lists, and under load that turns a
// one-second negotiation into a one-minute one.
func testConfig() Config {
	return Config{
		DisableSTUN:     true,
		IncludeLoopback: true,
		InterfaceFilter: onlyLoopback,
	}
}

// onlyLoopback keeps lo on Linux and lo0 on macOS.
func onlyLoopback(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "lo")
}

// pair builds two sessions that know about each other.
func pair(t *testing.T, cfg Config) (a, b *Session, aKey, bKey wgtypes.Key) {
	t.Helper()
	h := newMemHub()

	aPriv, bPriv := key(t), key(t)
	aKey, bKey = aPriv.PublicKey(), bPriv.PublicKey()

	a = NewSession(aKey, bKey, cfg, &link{h}, quietLogger())
	b = NewSession(bKey, aKey, cfg, &link{h}, quietLogger())
	h.join(aKey, a)
	h.join(bKey, b)

	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b, aKey, bKey
}

// The point of the package: two agents that were told nothing about each other
// beyond a public key end up with a usable path.
func TestTwoSessionsNegotiateAPath(t *testing.T) {
	a, b, _, _ := pair(t, testConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	errs := make(chan error, 2)
	go func() { errs <- a.Start(ctx) }()
	go func() { errs <- b.Start(ctx) }()

	for range 2 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("negotiation failed: %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("timed out: a=%s b=%s", a.State(), b.State())
		}
	}

	if a.State() != StateConnected || b.State() != StateConnected {
		t.Fatalf("states are a=%s b=%s, want both connected", a.State(), b.State())
	}
	if a.Conn() == nil || b.Conn() == nil {
		t.Fatal("connected without a usable conn")
	}
}

// A path that cannot carry bytes is not a path. This is the assertion that
// separates "ICE said connected" from "the hole is actually open".
func TestTheNegotiatedPathCarriesBytes(t *testing.T) {
	a, b, _, _ := pair(t, testConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	errs := make(chan error, 2)
	go func() { errs <- a.Start(ctx) }()
	go func() { errs <- b.Start(ctx) }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("negotiation failed: %v", err)
		}
	}

	want := []byte("a packet that has to survive the round trip")
	if _, err := a.Conn().Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := b.Conn().SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := b.Conn().Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Errorf("got %q, want %q", buf[:n], want)
	}

	// And back, because a hole punched in one direction is only half of one.
	reply := []byte("and the answer")
	if _, err := b.Conn().Write(reply); err != nil {
		t.Fatalf("write back: %v", err)
	}
	if err := a.Conn().SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	n, err = a.Conn().Read(buf)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf[:n]) != string(reply) {
		t.Errorf("got %q, want %q", buf[:n], reply)
	}
}

// Exactly one side must offer. If both did there would be two negotiations
// converging on different pairs; if neither did, nobody would ever start.
func TestExactlyOneSideControls(t *testing.T) {
	a, b, _, _ := pair(t, testConfig())
	if a.Controlling() == b.Controlling() {
		t.Fatalf("both sides report controlling=%v", a.Controlling())
	}
}

// The tie-break has to be computed identically on both machines from nothing
// but the two keys, since that is all either side has when it starts.
func TestControlIsDecidedFromTheKeysAlone(t *testing.T) {
	for range 50 {
		x, y := key(t).PublicKey(), key(t).PublicKey()
		if controls(x, y) == controls(y, x) {
			t.Fatalf("keys %s and %s both claim the same role", x, y)
		}
	}
}

// Candidates routinely arrive before the agent exists — the peer starts
// trickling the moment it offers. They have to be held, not dropped.
func TestCandidatesArrivingBeforeTheAgentAreHeld(t *testing.T) {
	h := newMemHub()
	aPriv, bPriv := key(t), key(t)
	s := NewSession(aPriv.PublicKey(), bPriv.PublicKey(), testConfig(), &link{h}, quietLogger())
	t.Cleanup(func() { _ = s.Close() })

	// Nothing has started, so there is no agent yet.
	s.AddRemoteCandidate("candidate:1 1 udp 2130706431 192.168.1.5 51820 typ host")
	s.AddRemoteCandidate("candidate:2 1 udp 2130706431 192.168.1.6 51821 typ host")

	s.mu.Lock()
	held := len(s.pending)
	s.mu.Unlock()
	if held != 2 {
		t.Fatalf("held %d candidates, want 2", held)
	}
}

// A second offer for a live session is a peer that restarted. The session must
// not adopt it: the agent is bound to the first attempt's credentials.
func TestASecondOfferDoesNotOverwriteTheFirst(t *testing.T) {
	h := newMemHub()
	aPriv, bPriv := key(t), key(t)
	s := NewSession(aPriv.PublicKey(), bPriv.PublicKey(), testConfig(), &link{h}, quietLogger())
	t.Cleanup(func() { _ = s.Close() })

	s.SetRemoteCredentials("first-ufrag", "first-password")
	s.SetRemoteCredentials("second-ufrag", "second-password")

	s.mu.Lock()
	gotU, gotP := s.remoteUfrag, s.remotePwd
	s.mu.Unlock()
	if gotU != "first-ufrag" || gotP != "first-password" {
		t.Errorf("credentials were overwritten: %s/%s", gotU, gotP)
	}
}

// Close has to be safe to call twice: the engine closes sessions it is
// replacing, and a failed session closes itself.
func TestCloseIsIdempotent(t *testing.T) {
	a, _, _, _ := pair(t, testConfig())
	if err := a.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if a.State() != StateClosed {
		t.Errorf("state is %s, want %s", a.State(), StateClosed)
	}
}

// A cancelled context has to end the wait rather than leave a goroutine parked
// on credentials that are never coming.
func TestStartGivesUpWhenTheContextEnds(t *testing.T) {
	h := newMemHub()
	aPriv, bPriv := key(t), key(t)
	// Registered with nobody on the other end, so no answer ever arrives.
	s := NewSession(aPriv.PublicKey(), bPriv.PublicKey(), testConfig(), &link{h}, quietLogger())
	t.Cleanup(func() { _ = s.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Start returned nil with no peer on the other side")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start ignored the cancelled context")
	}
}

// IPv6 has to be gathered by default: for two peers behind carrier-grade NAT it
// is frequently the only family that yields a direct path at all.
func TestIPv6IsGatheredByDefault(t *testing.T) {
	cfg, err := agentConfig(Config{DisableSTUN: true})
	if err != nil {
		t.Fatalf("agentConfig: %v", err)
	}
	var v4, v6 bool
	for _, n := range cfg.NetworkTypes {
		switch n.String() {
		case "udp4":
			v4 = true
		case "udp6":
			v6 = true
		}
	}
	if !v4 || !v6 {
		t.Errorf("network types are %v, want both udp4 and udp6", cfg.NetworkTypes)
	}
}

func TestIPv6CanBeTurnedOff(t *testing.T) {
	cfg, err := agentConfig(Config{DisableSTUN: true, DisableIPv6: true})
	if err != nil {
		t.Fatalf("agentConfig: %v", err)
	}
	for _, n := range cfg.NetworkTypes {
		if n.String() == "udp6" {
			t.Error("udp6 is still gathered with DisableIPv6 set")
		}
	}
}

// With no STUN configured the default list is what gets used, or a peer behind
// NAT would only ever produce host candidates and never find a path out.
func TestSTUNDefaultsAreApplied(t *testing.T) {
	cfg, err := agentConfig(Config{})
	if err != nil {
		t.Fatalf("agentConfig: %v", err)
	}
	if len(cfg.Urls) != len(DefaultSTUN) {
		t.Fatalf("got %d urls, want the %d defaults", len(cfg.Urls), len(DefaultSTUN))
	}
	cfg, err = agentConfig(Config{DisableSTUN: true})
	if err != nil {
		t.Fatalf("agentConfig: %v", err)
	}
	if len(cfg.Urls) != 0 {
		t.Errorf("got %d urls with STUN disabled, want 0", len(cfg.Urls))
	}
}

// A TURN server has to reach the agent with its credentials attached, or the
// relay is gathered anonymously and refused.
func TestTURNCredentialsReachTheAgent(t *testing.T) {
	cfg, err := agentConfig(Config{
		DisableSTUN: true,
		TURN: []TURNServer{{
			URL: "turn:relay.example.com:3478", Username: "u", Password: "p",
		}},
	})
	if err != nil {
		t.Fatalf("agentConfig: %v", err)
	}
	if len(cfg.Urls) != 1 {
		t.Fatalf("got %d urls, want 1", len(cfg.Urls))
	}
	if cfg.Urls[0].Username != "u" || cfg.Urls[0].Password != "p" {
		t.Errorf("credentials did not reach the url: %+v", cfg.Urls[0])
	}
}
