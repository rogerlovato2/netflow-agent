package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/rogerlovato2/netflow-agent/internal/p2p"
)

// A completed WireGuard handshake is the assertion that "ICE reported
// connected" does not give you.
//
// This exists because of a bug it would have caught immediately. The proxy used
// a connected UDP socket, so the kernel dropped every reply whose source was not
// the exact address it was connected to — and wireguard-go, whose bind keeps
// separate IPv4 and IPv6 sockets, sometimes answered from ::ffff:127.0.0.1
// instead of 127.0.0.1. The result was a tunnel where ICE said connected,
// endpoints were configured on both sides, counters showed bytes moving in both
// directions, and no handshake ever completed. Every test at the time passed.
func TestTheTunnelCompletesAWireGuardHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	url := signalServer(t)
	a := newMachine(t, ctx, url, "10.24.0.1")
	b := newMachine(t, ctx, url, "10.24.0.2")

	waitUntil(t, "both on the signal server", 20*time.Second, func() bool {
		return a.eng.SignalConnected() && b.eng.SignalConnected()
	})

	a.eng.SetPeers(ctx, []Peer{{PublicKey: b.pub,
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(b.addr, 32)}}})
	b.eng.SetPeers(ctx, []Peer{{PublicKey: a.pub,
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(a.addr, 32)}}})

	waitUntil(t, "a path on both sides", 60*time.Second, func() bool {
		return a.eng.PeerState(b.pub) == p2p.StateConnected &&
			b.eng.PeerState(a.pub) == p2p.StateConnected
	})

	// The handshake is what proves packets survive the round trip through both
	// proxies, not merely that they left.
	//
	// Ten seconds is deliberately tight. A correct connect completes in well
	// under one, and the two bugs this guards against both showed up as a
	// handshake that eventually worked: one cost a fixed five-second WireGuard
	// retry, the other took up to forty-seven seconds to resolve. A generous
	// timeout would have called both of them a pass.
	deadline := time.Now().Add(10 * time.Second)
	for {
		sa, errA := a.eng.Device().Status()
		sb, errB := b.eng.Device().Status()
		if errA != nil || errB != nil {
			t.Fatalf("reading device status: %v / %v", errA, errB)
		}
		ha, hb := sa[b.pub.String()], sb[a.pub.String()]
		if ha.LastHandshake > 0 && hb.LastHandshake > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no handshake after 10s with a path on both sides.\n"+
				"  a->b: handshake=%d endpoint=%q tx=%d rx=%d\n"+
				"  b->a: handshake=%d endpoint=%q tx=%d rx=%d\n"+
				"bytes moving with no handshake means packets leave and the "+
				"replies do not arrive.",
				ha.LastHandshake, ha.Endpoint, ha.TXBytes, ha.RXBytes,
				hb.LastHandshake, hb.Endpoint, hb.TXBytes, hb.RXBytes)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
