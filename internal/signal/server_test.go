package signal

import (
	"testing"
	"time"
)

// A burst must not cost the peer its session.
//
// This is the fault that made the mesh unusable. Sixty-four envelopes was sized
// against one negotiation, but every peer that renegotiates trickles a candidate
// at a time, so a machine in a mesh of eighteen takes a hundred and seventy of
// them inside a second whenever everyone comes back at once. Overflow closed
// the socket; the peer reconnected within a second; and every negotiation aimed
// at it during that second was answered "offline", which produced the retries
// that made the next burst larger.
func TestABurstOfCandidatesDoesNotCloseTheSocket(t *testing.T) {
	c := &conn{
		key:    "peer",
		send:   make(chan Envelope, sendQueue),
		closed: make(chan struct{}),
	}

	// What a mesh of eighteen actually delivers when it renegotiates: one offer
	// and a trickle of candidates from each of the other seventeen.
	const burst = 17 * 10
	if burst > sendQueue {
		t.Fatalf("the queue (%d) is smaller than an ordinary burst (%d), which is the bug",
			sendQueue, burst)
	}
	for i := 0; i < burst; i++ {
		c.enqueue(Envelope{Kind: KindCandidate, To: "peer"})
	}

	select {
	case <-c.closed:
		t.Fatal("the peer was disconnected by an ordinary burst of candidates")
	default:
	}
	if got := len(c.send); got != burst {
		t.Fatalf("queued %d envelopes, want %d: something was dropped, and a "+
			"missing candidate reads as a NAT problem at the far end", got, burst)
	}
}

// A peer that has genuinely stopped reading is still closed, eventually.
func TestAPeerThatNeverDrainsIsClosed(t *testing.T) {
	c := &conn{
		key:    "stalled",
		send:   make(chan Envelope, 1),
		closed: make(chan struct{}),
	}
	c.enqueue(Envelope{Kind: KindOffer}) // fills it
	select {
	case <-c.closed:
		t.Fatal("closed while there was still room")
	default:
	}

	done := make(chan struct{})
	go func() {
		c.enqueue(Envelope{Kind: KindOffer}) // has to wait, then give up
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(enqueueWait + 5*time.Second):
		t.Fatal("enqueue never returned for a peer that is not draining")
	}
	select {
	case <-c.closed:
	default:
		t.Fatal("a peer that did not drain within the wait was left connected")
	}
}
