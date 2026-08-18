package tunnel

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const testMTU = 1420

func genKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k
}

// node is one end of a tunnel: a userspace WireGuard with an address inside it.
type node struct {
	priv wgtypes.Key
	pub  wgtypes.Key
	addr netip.Addr
	dev  *Device
	port int
}

func newNode(t *testing.T, addr string) *node {
	t.Helper()

	priv := genKey(t)
	ip := netip.MustParseAddr(addr)

	dev, err := NewUserspaceDevice([]netip.Addr{ip}, nil, testMTU, quietLogger())
	if err != nil {
		t.Fatalf("creating the device: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })

	// Port zero lets the kernel choose, which is what keeps two nodes in one
	// test process from colliding.
	if err := dev.Configure(priv, 0); err != nil {
		t.Fatalf("configuring: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("bringing up: %v", err)
	}
	port, err := dev.ListenPort()
	if err != nil {
		t.Fatalf("reading the listen port: %v", err)
	}

	return &node{priv: priv, pub: priv.PublicKey(), addr: ip, dev: dev, port: port}
}

// echoOnce answers exactly one TCP connection inside the tunnel, echoing what
// it reads. It is the far end of the assertion "traffic actually flows".
func echoOnce(t *testing.T, n *node, port uint16, ready chan<- struct{}) {
	t.Helper()
	go func() {
		ln, err := n.dev.Net.ListenTCPAddrPort(netip.AddrPortFrom(n.addr, port))
		if err != nil {
			t.Errorf("listen inside the tunnel: %v", err)
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
		buf := make([]byte, 256)
		read, err := c.Read(buf)
		if err != nil {
			return
		}
		_, _ = c.Write(buf[:read])
	}()
}

// Two userspace WireGuards pointed straight at each other's ports. No ICE and
// no proxy yet: this is the device wrapper on its own, so that a later failure
// in the full path can be blamed on the part that is actually new.
func TestTwoDevicesCarryTrafficDirectly(t *testing.T) {
	a := newNode(t, "10.10.0.1")
	b := newNode(t, "10.10.0.2")

	psk := genKey(t)
	loop := netip.MustParseAddr("127.0.0.1")

	if err := a.dev.SetPeer(Peer{
		PublicKey:    b.pub,
		PresharedKey: psk,
		Endpoint:     netip.AddrPortFrom(loop, uint16(b.port)),
		AllowedIPs:   []netip.Prefix{netip.PrefixFrom(b.addr, 32)},
	}); err != nil {
		t.Fatalf("a.SetPeer: %v", err)
	}
	if err := b.dev.SetPeer(Peer{
		PublicKey:    a.pub,
		PresharedKey: psk,
		Endpoint:     netip.AddrPortFrom(loop, uint16(a.port)),
		AllowedIPs:   []netip.Prefix{netip.PrefixFrom(a.addr, 32)},
	}); err != nil {
		t.Fatalf("b.SetPeer: %v", err)
	}

	ready := make(chan struct{})
	echoOnce(t, b, 8080, ready)
	<-ready

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := a.dev.Net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(b.addr, 8080))
	if err != nil {
		t.Fatalf("dialling through the tunnel: %v", err)
	}
	defer conn.Close()

	want := "through the tunnel"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != want {
		t.Errorf("got %q, want %q", buf[:n], want)
	}
}

// A peer without allowed IPs completes a handshake and carries nothing, which
// reads as a broken tunnel rather than as a missing line of configuration.
// Refusing it up front is what turns that into an error message.
func TestAPeerWithoutAllowedIPsIsRefused(t *testing.T) {
	a := newNode(t, "10.10.0.1")
	err := a.dev.SetPeer(Peer{
		PublicKey: genKey(t).PublicKey(),
		Endpoint:  netip.MustParseAddrPort("127.0.0.1:51820"),
	})
	if err == nil {
		t.Error("a peer with no allowed IPs was accepted")
	}
}

// Moving a peer's endpoint is what a renegotiated path looks like from
// WireGuard's side: keys and allowed IPs untouched, only the address changes.
func TestAPeerCanBeMovedToANewEndpoint(t *testing.T) {
	a := newNode(t, "10.10.0.1")
	peer := genKey(t).PublicKey()

	first := netip.MustParseAddrPort("127.0.0.1:51820")
	if err := a.dev.SetPeer(Peer{
		PublicKey:  peer,
		Endpoint:   first,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.10.0.2/32")},
	}); err != nil {
		t.Fatalf("SetPeer: %v", err)
	}
	if got, ok := a.dev.PeerEndpoint(peer); !ok || got != first {
		t.Fatalf("endpoint is %s (found=%v), want %s", got, ok, first)
	}

	second := netip.MustParseAddrPort("127.0.0.1:51821")
	if err := a.dev.SetPeerEndpoint(peer, second); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}
	if got, ok := a.dev.PeerEndpoint(peer); !ok || got != second {
		t.Errorf("endpoint is %s (found=%v), want %s", got, ok, second)
	}
}

func TestAPeerCanBeRemoved(t *testing.T) {
	a := newNode(t, "10.10.0.1")
	peer := genKey(t).PublicKey()

	if err := a.dev.SetPeer(Peer{
		PublicKey:  peer,
		Endpoint:   netip.MustParseAddrPort("127.0.0.1:51820"),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.10.0.2/32")},
	}); err != nil {
		t.Fatalf("SetPeer: %v", err)
	}
	if err := a.dev.RemovePeer(peer); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if _, ok := a.dev.PeerEndpoint(peer); ok {
		t.Error("the peer is still configured after being removed")
	}
}

func TestDeviceCloseIsIdempotent(t *testing.T) {
	a := newNode(t, "10.10.0.1")
	if err := a.dev.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := a.dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
