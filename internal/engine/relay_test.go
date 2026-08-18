package engine

import (
	"net/netip"
	"testing"
)

// A relay arriving from the network map has to reach the next negotiation.
// Nothing else in the tests configures one, so without this the plumbing
// between the map and ICE is never exercised at all.
func TestSetRelayReachesTheNextNegotiation(t *testing.T) {
	eng, err := New(Config{
		PrivateKey: genKey(t),
		Addresses:  []netip.Addr{netip.MustParseAddr("10.99.0.1")},
		SignalURL:  "ws://127.0.0.1:1/never",
		Userspace:  true,
	}, quietLogger())
	if err != nil {
		t.Fatalf("creating the engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Device().Close() })

	if got := eng.p2pConfig().TURN; len(got) != 0 {
		t.Fatalf("a fresh engine already has %d relays", len(got))
	}

	eng.SetRelay("turn:relay.example.com:3478", "1700000000:machine", "a-password")
	got := eng.p2pConfig().TURN
	if len(got) != 1 {
		t.Fatalf("got %d relays, want 1", len(got))
	}
	if got[0].URL != "turn:relay.example.com:3478" || got[0].Username != "1700000000:machine" {
		t.Errorf("the credential did not arrive intact: %+v", got[0])
	}

	// An empty URL is how the server says there is no relay any more. Leaving
	// the old one configured would keep a fleet pointed at a machine that has
	// been turned off.
	eng.SetRelay("", "", "")
	if got := eng.p2pConfig().TURN; len(got) != 0 {
		t.Errorf("clearing the relay left %d behind", len(got))
	}
}

// The copy has to be a copy: handing out the engine's own slice lets a caller
// mutate what the next negotiation will use.
func TestP2PConfigDoesNotShareItsRelaySlice(t *testing.T) {
	eng, err := New(Config{
		PrivateKey: genKey(t),
		Addresses:  []netip.Addr{netip.MustParseAddr("10.99.0.2")},
		SignalURL:  "ws://127.0.0.1:1/never",
		Userspace:  true,
	}, quietLogger())
	if err != nil {
		t.Fatalf("creating the engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Device().Close() })

	eng.SetRelay("turn:a.example.com:3478", "u", "p")
	first := eng.p2pConfig().TURN
	first[0].URL = "turn:somewhere-else.example.com:3478"

	if got := eng.p2pConfig().TURN; got[0].URL != "turn:a.example.com:3478" {
		t.Errorf("the engine's relay was changed from outside: %s", got[0].URL)
	}
}
