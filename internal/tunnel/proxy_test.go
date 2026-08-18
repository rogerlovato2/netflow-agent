package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func loopback(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// harness stands in for the two things a proxy sits between: WireGuard on one
// side and the negotiated path on the other. Both are real sockets, because the
// thing under test is precisely how datagrams cross between them.
type harness struct {
	wg    *net.UDPConn // pretends to be the local WireGuard
	far   *net.UDPConn // pretends to be the peer at the far end of the path
	proxy *Proxy
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	wg := loopback(t)
	far := loopback(t)

	// The proxy's view of the path: a socket connected to the far end.
	path, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		far.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial path: %v", err)
	}
	t.Cleanup(func() { _ = path.Close() })

	p, err := NewProxy(path, wg.LocalAddr().(*net.UDPAddr).Port, quietLogger())
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Run(ctx) }()

	return &harness{wg: wg, far: far, proxy: p}
}

func readWithin(t *testing.T, c *net.UDPConn, d time.Duration) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, maxPacket)
	n, from, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n], from
}

// What WireGuard sends to the proxy has to come out of the path unchanged.
func TestPacketsFromWireGuardReachThePath(t *testing.T) {
	h := newHarness(t)

	want := []byte("an encrypted wireguard packet")
	ep := h.proxy.Endpoint()
	if _, err := h.wg.WriteToUDP(want, net.UDPAddrFromAddrPort(ep)); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, _ := readWithin(t, h.far, 3*time.Second)
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// And the other direction, arriving at WireGuard from the endpoint it has
// configured — a reply from any other address would be discarded as coming
// from a stranger.
func TestPacketsFromThePathReachWireGuard(t *testing.T) {
	h := newHarness(t)

	// The far end has to learn where to answer, which it does from a first
	// packet — the same way a real peer does.
	if _, err := h.wg.WriteToUDP([]byte("hello"), net.UDPAddrFromAddrPort(h.proxy.Endpoint())); err != nil {
		t.Fatalf("priming write: %v", err)
	}
	_, proxyAddr := readWithin(t, h.far, 3*time.Second)

	want := []byte("the peer answering")
	if _, err := h.far.WriteToUDP(want, proxyAddr); err != nil {
		t.Fatalf("write back: %v", err)
	}

	got, from := readWithin(t, h.wg, 3*time.Second)
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if from.AddrPort() != h.proxy.Endpoint() {
		t.Errorf("the packet arrived from %s, want the configured endpoint %s",
			from.AddrPort(), h.proxy.Endpoint())
	}
}

// Datagram boundaries are the whole point. Three packets in must be three
// packets out, each intact: a WireGuard packet that arrives merged with the
// next one or split across two is not a WireGuard packet at all.
func TestDatagramBoundariesSurvive(t *testing.T) {
	h := newHarness(t)

	sent := [][]byte{
		[]byte("first"),
		[]byte("the second one, rather longer than the first"),
		[]byte("3"),
	}
	ep := net.UDPAddrFromAddrPort(h.proxy.Endpoint())
	for _, p := range sent {
		if _, err := h.wg.WriteToUDP(p, ep); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for i, want := range sent {
		got, _ := readWithin(t, h.far, 3*time.Second)
		if string(got) != string(want) {
			t.Errorf("packet %d: got %q, want %q", i, got, want)
		}
	}
}

// A full-size packet has to survive whole. The buffer is what decides this, and
// getting it wrong produces a tunnel that works until somebody sends something
// big — a failure that surfaces far from its cause.
func TestAFullSizePacketIsNotTruncated(t *testing.T) {
	h := newHarness(t)

	want := make([]byte, 1452) // tunnel MTU 1420 plus WireGuard's own header
	for i := range want {
		want[i] = byte(i % 251)
	}
	if _, err := h.wg.WriteToUDP(want, net.UDPAddrFromAddrPort(h.proxy.Endpoint())); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, _ := readWithin(t, h.far, 3*time.Second)
	if len(got) != len(want) {
		t.Fatalf("got %d bytes, want %d", len(got), len(want))
	}
	if string(got) != string(want) {
		t.Error("the packet came out changed")
	}
}

// The endpoint has to be on loopback: this hop never leaves the machine, and a
// socket bound anywhere else would forward straight into the tunnel for whoever
// found it.
func TestTheEndpointIsOnLoopback(t *testing.T) {
	h := newHarness(t)
	if !h.proxy.Endpoint().Addr().IsLoopback() {
		t.Errorf("the endpoint is %s, which is not loopback", h.proxy.Endpoint())
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	h := newHarness(t)
	if err := h.proxy.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := h.proxy.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Run has to return when the context ends, or every torn-down session leaks two
// goroutines parked on a read that will never complete.
func TestRunStopsWithTheContext(t *testing.T) {
	wg := loopback(t)
	far := loopback(t)
	path, err := net.DialUDP("udp4", nil, far.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer path.Close()

	p, err := NewProxy(path, wg.LocalAddr().(*net.UDPAddr).Port, quietLogger())
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run ignored the cancelled context")
	}
}

func TestNewProxyRejectsNonsense(t *testing.T) {
	wg := loopback(t)
	path, err := net.DialUDP("udp4", nil, wg.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer path.Close()

	if _, err := NewProxy(nil, 51820, quietLogger()); err == nil {
		t.Error("a nil path was accepted")
	}
	for _, port := range []int{0, -1, 70000} {
		if _, err := NewProxy(path, port, quietLogger()); err == nil {
			t.Errorf("port %d was accepted", port)
		}
	}
}
