package engine

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/rogerlovato2/netflow-agent/internal/p2p"
	"github.com/rogerlovato2/netflow-agent/internal/signal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// iceLogs is nil unless NETFLOW_ICE_LOG is set, which is how a flaky
// negotiation is investigated without drowning every other run in output.
var iceLogs = func() logging.LoggerFactory {
	if os.Getenv("NETFLOW_ICE_LOG") == "" {
		return nil
	}
	return &logging.DefaultLoggerFactory{
		Writer:          os.Stderr,
		DefaultLogLevel: logging.LogLevelDebug,
	}
}()

// quietLogger is silent unless NETFLOW_TEST_LOG is set, which is how
// wireguard-go's own narration of a handshake is reached when one will not
// complete. It is the only thing that says why a packet was rejected.
func quietLogger() *slog.Logger {
	if os.Getenv("NETFLOW_TEST_LOG") == "" {
		return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func genKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k
}

func waitUntil(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// signalServer starts a real one. The end-to-end test is worth little if the
// piece in the middle is a stand-in.
func signalServer(t *testing.T) string {
	t.Helper()
	hs := httptest.NewServer(signal.NewServer(quietLogger()).Handler())
	t.Cleanup(hs.Close)
	return "ws" + strings.TrimPrefix(hs.URL, "http")
}

// machine is one participant: an engine with an address inside the mesh.
type machine struct {
	priv wgtypes.Key
	pub  wgtypes.Key
	addr netip.Addr
	eng  *Engine
}

func newMachine(t *testing.T, ctx context.Context, signalURL, addr string) *machine {
	t.Helper()

	priv := genKey(t)
	ip := netip.MustParseAddr(addr)

	eng, err := New(Config{
		PrivateKey: priv,
		Addresses:  []netip.Addr{ip},
		SignalURL:  signalURL,
		Userspace:  true,
		// Loopback only, and no STUN: the test proves the plumbing, and
		// gathering from every real interface would make it depend on the
		// internet, on this machine's interfaces, and on how loaded it is.
		P2P: p2p.Config{
			DisableSTUN:     true,
			IncludeLoopback: true,
			InterfaceFilter: func(n string) bool {
				return strings.HasPrefix(strings.ToLower(n), "lo")
			},
		},
	}, quietLogger())
	if err != nil {
		t.Fatalf("creating the engine: %v", err)
	}
	go func() { _ = eng.Run(ctx) }()

	return &machine{priv: priv, pub: priv.PublicKey(), addr: ip, eng: eng}
}

// echoOnce answers one TCP connection inside the tunnel.
func echoOnce(t *testing.T, m *machine, port uint16, ready chan<- struct{}) {
	t.Helper()
	go func() {
		ln, err := m.eng.Device().Net.ListenTCPAddrPort(netip.AddrPortFrom(m.addr, port))
		if err != nil {
			t.Errorf("listening inside the tunnel: %v", err)
			close(ready)
			return
		}
		defer ln.Close()
		close(ready)

		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		_, _ = c.Write(buf[:n])
	}()
}

// The milestone.
//
// Two machines that know nothing about each other beyond a public key find a
// path through a real signalling server, negotiate it with real ICE, bring up
// real WireGuard over it, and carry a TCP conversation inside the tunnel. No
// component in the path is a stand-in.
func TestTwoMachinesBuildATunnelEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	url := signalServer(t)
	a := newMachine(t, ctx, url, "10.20.0.1")
	b := newMachine(t, ctx, url, "10.20.0.2")

	// Both have to be reachable for negotiation before either offers, or the
	// first offer is answered with "that peer is not here" and the attempt is
	// spent waiting for a reply that was never sent.
	waitUntil(t, "both machines on the signal server", 20*time.Second, func() bool {
		return a.eng.SignalConnected() && b.eng.SignalConnected()
	})

	psk := genKey(t)
	a.eng.SetPeers(ctx, []Peer{{
		PublicKey: b.pub, PresharedKey: psk,
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(b.addr, 32)},
	}})
	b.eng.SetPeers(ctx, []Peer{{
		PublicKey: a.pub, PresharedKey: psk,
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(a.addr, 32)},
	}})

	// Reported per side on failure: "no path" and "a path in one direction
	// only" have different causes, and the message is the only evidence a
	// future failure will leave behind.
	deadline := time.Now().Add(60 * time.Second)
	for {
		sa, sb := a.eng.PeerState(b.pub), b.eng.PeerState(a.pub)
		if sa == p2p.StateConnected && sb == p2p.StateConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no path after 60s: a->b=%s, b->a=%s (signal: a=%v b=%v)",
				sa, sb, a.eng.SignalConnected(), b.eng.SignalConnected())
		}
		time.Sleep(50 * time.Millisecond)
	}

	ready := make(chan struct{})
	echoOnce(t, b, 8080, ready)
	<-ready

	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()

	conn, err := a.eng.Device().Net.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(b.addr, 8080))
	if err != nil {
		t.Fatalf("dialling inside the tunnel: %v", err)
	}
	defer conn.Close()

	want := "this crossed ICE, a proxy and WireGuard"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != want {
		t.Errorf("got %q, want %q", buf[:n], want)
	}
}

// A peer dropped from the map has to be torn down: left running it keeps
// negotiating with somebody the network map no longer lists.
func TestRemovingAPeerTearsItDown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	url := signalServer(t)
	a := newMachine(t, ctx, url, "10.21.0.1")
	b := newMachine(t, ctx, url, "10.21.0.2")

	waitUntil(t, "both on the signal server", 20*time.Second, func() bool {
		return a.eng.SignalConnected() && b.eng.SignalConnected()
	})

	peerOfA := []Peer{{PublicKey: b.pub, AllowedIPs: []netip.Prefix{netip.PrefixFrom(b.addr, 32)}}}
	a.eng.SetPeers(ctx, peerOfA)
	b.eng.SetPeers(ctx, []Peer{{PublicKey: a.pub, AllowedIPs: []netip.Prefix{netip.PrefixFrom(a.addr, 32)}}})

	waitUntil(t, "a path", 60*time.Second, func() bool {
		return a.eng.PeerState(b.pub) == p2p.StateConnected
	})
	// Connected has to mean WireGuard knows about the peer, not merely that ICE
	// finished. If this ever fails, the state is being reported too early.
	if _, known := a.eng.Device().PeerEndpoint(b.pub); !known {
		t.Fatal("state is connected but WireGuard was never told about the peer")
	}

	// An empty map is a peer list with nobody on it.
	a.eng.SetPeers(ctx, nil)

	waitUntil(t, "the peer to leave WireGuard", 20*time.Second, func() bool {
		_, known := a.eng.Device().PeerEndpoint(b.pub)
		return !known
	})
	if got := a.eng.PeerState(b.pub); got != p2p.StateIdle {
		t.Errorf("state is %s after removal, want %s", got, p2p.StateIdle)
	}
}

// SetPeers is a reconcile, so calling it twice with the same list must not
// rebuild anything — the management server will send a full map on every
// update, and most of them change nothing.
func TestReconcilingTheSameListIsNotDisruptive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	url := signalServer(t)
	a := newMachine(t, ctx, url, "10.22.0.1")
	b := newMachine(t, ctx, url, "10.22.0.2")

	waitUntil(t, "both on the signal server", 20*time.Second, func() bool {
		return a.eng.SignalConnected() && b.eng.SignalConnected()
	})

	peers := []Peer{{PublicKey: b.pub, AllowedIPs: []netip.Prefix{netip.PrefixFrom(b.addr, 32)}}}
	a.eng.SetPeers(ctx, peers)
	b.eng.SetPeers(ctx, []Peer{{PublicKey: a.pub, AllowedIPs: []netip.Prefix{netip.PrefixFrom(a.addr, 32)}}})

	waitUntil(t, "a path", 60*time.Second, func() bool {
		return a.eng.PeerState(b.pub) == p2p.StateConnected
	})
	before, known := a.eng.Device().PeerEndpoint(b.pub)
	if !known {
		t.Fatal("state is connected but WireGuard was never told about the peer")
	}

	a.eng.SetPeers(ctx, peers)
	a.eng.SetPeers(ctx, peers)

	// A rebuild would show up as a new proxy on a different port.
	time.Sleep(500 * time.Millisecond)
	after, known := a.eng.Device().PeerEndpoint(b.pub)
	if !known {
		t.Fatal("the peer disappeared after reconciling an unchanged list")
	}
	if before != after {
		t.Errorf("the tunnel was rebuilt: endpoint moved %s -> %s", before, after)
	}
	if got := a.eng.PeerState(b.pub); got != p2p.StateConnected {
		t.Errorf("state is %s, want %s", got, p2p.StateConnected)
	}
}

// A signal message from somebody who is not in the peer list has to be dropped.
// The seal proves who sent it; it does not prove this machine has any business
// talking to them, and that decision belongs to the peer list.
func TestSignalFromAStrangerIsIgnored(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := signalServer(t)
	a := newMachine(t, ctx, url, "10.23.0.1")

	waitUntil(t, "the machine on the signal server", 20*time.Second, func() bool {
		return a.eng.SignalConnected()
	})

	stranger := genKey(t)
	sc := signal.NewClient(url, stranger, quietLogger())
	go sc.Run(ctx)
	waitUntil(t, "the stranger to connect", 20*time.Second, sc.Connected)

	if err := sc.Send(a.pub, signal.KindOffer, signal.Body{UFrag: "u", Pwd: "p"}); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Nothing to assert beyond the engine still being healthy afterwards: the
	// message must produce no peer and no panic.
	time.Sleep(500 * time.Millisecond)
	if got := a.eng.PeerState(stranger.PublicKey()); got != p2p.StateIdle {
		t.Errorf("a stranger created state %s", got)
	}
	if !a.eng.SignalConnected() {
		t.Error("the engine dropped its signal connection over a stranger's message")
	}
}

// A machine can be given a different address while it is connected, and the
// other machines have to follow it there.
//
// This is the failure it was written for: the peer's note was updated and
// nothing else was, so the route and WireGuard's allowed IPs still pointed at
// the address the machine used to have. The panel showed the new one, the
// tunnel stayed up, and the machine was unreachable — which is the worst shape
// a bug can take, because everything on screen says it is working.
func TestAPeerThatMovesIsFollowed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	url := signalServer(t)
	a := newMachine(t, ctx, url, "10.23.0.1")
	b := newMachine(t, ctx, url, "10.23.0.2")

	waitUntil(t, "both on the signal server", 20*time.Second, func() bool {
		return a.eng.SignalConnected() && b.eng.SignalConnected()
	})

	was := netip.PrefixFrom(b.addr, 32)
	a.eng.SetPeers(ctx, []Peer{{PublicKey: b.pub, AllowedIPs: []netip.Prefix{was}}})
	b.eng.SetPeers(ctx, []Peer{{PublicKey: a.pub,
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(a.addr, 32)}}})

	waitUntil(t, "a path", 60*time.Second, func() bool {
		return a.eng.PeerState(b.pub) == p2p.StateConnected
	})
	before, known := a.eng.Device().PeerEndpoint(b.pub)
	if !known {
		t.Fatal("state is connected but WireGuard was never told about the peer")
	}

	// The same machine, at another address.
	now := netip.MustParsePrefix("10.23.0.20/32")
	a.eng.SetPeers(ctx, []Peer{{PublicKey: b.pub, AllowedIPs: []netip.Prefix{now}}})

	st, err := a.eng.Device().Status()
	if err != nil {
		t.Fatalf("reading the device: %v", err)
	}
	got := st[b.pub.String()].AllowedIPs
	if !containsPrefix(got, now) {
		t.Errorf("WireGuard allows %v, and the peer has moved to %s", got, now)
	}
	if containsPrefix(got, was) {
		t.Errorf("WireGuard still allows %s, which the peer left", was)
	}

	// Where a peer is reachable has nothing to do with how it is reached, so
	// moving it must not cost the path that was already working.
	after, known := a.eng.Device().PeerEndpoint(b.pub)
	if !known {
		t.Fatal("the peer left WireGuard when it should only have moved")
	}
	if before != after {
		t.Errorf("the tunnel was rebuilt to change an address: %s -> %s", before, after)
	}
	if got := a.eng.PeerState(b.pub); got != p2p.StateConnected {
		t.Errorf("state is %s after a move, want %s", got, p2p.StateConnected)
	}
}

// A map that comes back with the same addresses in another order is not a move.
// Treating it as one would rewrite every peer's allowed IPs on every poll.
func TestReorderedAddressesAreNotAMove(t *testing.T) {
	x := netip.MustParsePrefix("10.24.0.1/32")
	y := netip.MustParsePrefix("10.24.0.2/32")
	if !samePrefixes([]netip.Prefix{x, y}, []netip.Prefix{y, x}) {
		t.Error("a reordered list reads as a move")
	}
	if samePrefixes([]netip.Prefix{x}, []netip.Prefix{x, y}) {
		t.Error("an added address does not read as a move")
	}
	if samePrefixes([]netip.Prefix{x}, []netip.Prefix{y}) {
		t.Error("a different address does not read as a move")
	}
}
