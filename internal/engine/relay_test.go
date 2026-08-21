package engine

import (
	"testing"
	"time"
)

// A pair that has just been noticed on the relay is left alone.
//
// Renegotiating a path the instant it comes up is churn, not repair: the pair
// has not had time to be anything yet.
func TestARelayedPairIsLeftAloneUntilItHasStood(t *testing.T) {
	now := time.Now()
	seen := map[string]*relayWatch{}
	paths := map[string]string{"a": "relay"}

	if got := pickRelayToRetry(paths, seen, now); got != "" {
		t.Fatalf("a pair noticed this instant was disturbed: %q", got)
	}
	if got := pickRelayToRetry(paths, seen, now.Add(relaySettledFor-time.Second)); got != "" {
		t.Fatalf("a pair was disturbed before it had settled: %q", got)
	}
	if got := pickRelayToRetry(paths, seen, now.Add(relaySettledFor+time.Second)); got != "a" {
		t.Fatalf("a pair that has sat on the relay long enough was not retried: %q", got)
	}
}

// One at a time. A machine with a dozen relayed peers that renegotiated all of
// them at once would take its whole mesh down in order to improve it.
func TestOnlyOnePairIsDisturbedAtATime(t *testing.T) {
	now := time.Now()
	seen := map[string]*relayWatch{}
	paths := map[string]string{"a": "relay", "b": "relay", "c": "relay"}

	pickRelayToRetry(paths, seen, now)
	// The one that has been paying longest goes first.
	seen["a"].since = now.Add(-time.Hour)
	seen["b"].since = now.Add(-time.Minute)

	later := now.Add(relaySettledFor + time.Second)
	if got := pickRelayToRetry(paths, seen, later); got != "a" {
		t.Fatalf("the pair on the relay longest was not the one retried: %q", got)
	}
	// And having just retried "a", the next look picks somebody else rather
	// than the same one again.
	if got := pickRelayToRetry(paths, seen, later.Add(time.Second)); got == "a" {
		t.Fatal("the same pair was retried twice in a row, without its backoff being respected")
	}
}

// The backoff must survive the renegotiation it causes.
//
// A pair being renegotiated has no path at all for a moment. Treating that
// absence as success would clear the record at the exact instant the attempt
// was made, and a pair with no direct path to find would retry every fifteen
// minutes forever, resetting its own backoff each time.
func TestBeingMidNegotiationDoesNotResetTheBackoff(t *testing.T) {
	now := time.Now()
	seen := map[string]*relayWatch{}

	pickRelayToRetry(map[string]string{"a": "relay"}, seen, now)
	due := now.Add(relaySettledFor + time.Second)
	if got := pickRelayToRetry(map[string]string{"a": "relay"}, seen, due); got != "a" {
		t.Fatalf("expected the retry, got %q", got)
	}
	wait := seen["a"].wait

	// Mid-negotiation: no path.
	if got := pickRelayToRetry(map[string]string{"a": ""}, seen, due.Add(time.Second)); got != "" {
		t.Fatalf("a pair with no path was disturbed: %q", got)
	}
	if seen["a"] == nil {
		t.Fatal("the record was thrown away while the pair was mid-negotiation, so its backoff is gone")
	}
	if seen["a"].wait != wait {
		t.Fatalf("the backoff moved while the pair had no path: %v then %v", wait, seen["a"].wait)
	}

	// It failed and is back on the relay: the wait must have grown, not reset.
	if got := pickRelayToRetry(map[string]string{"a": "relay"}, seen, due.Add(2*time.Second)); got != "" {
		t.Fatalf("a pair was retried before its backoff had run: %q", got)
	}
	if seen["a"].wait <= relayRetryMin {
		t.Fatalf("the backoff did not grow after a failed attempt: %v", seen["a"].wait)
	}
}

// Landing direct is the one thing that counts as having worked.
func TestGoingDirectClearsTheRecord(t *testing.T) {
	now := time.Now()
	seen := map[string]*relayWatch{}
	pickRelayToRetry(map[string]string{"a": "relay"}, seen, now)
	if len(seen) != 1 {
		t.Fatal("a relayed pair is not being watched")
	}
	pickRelayToRetry(map[string]string{"a": "direct"}, seen, now.Add(time.Minute))
	if len(seen) != 0 {
		t.Fatal("a pair that reached a direct path is still being watched, so its backoff outlives the problem")
	}
}

// A pair that never escapes must not renegotiate forever at the same rate.
func TestTheBackoffIsCapped(t *testing.T) {
	now := time.Now()
	seen := map[string]*relayWatch{}
	paths := map[string]string{"a": "relay"}
	pickRelayToRetry(paths, seen, now)

	at := now.Add(relaySettledFor + time.Second)
	for i := 0; i < 20; i++ {
		at = at.Add(relayRetryMax * 2)
		pickRelayToRetry(paths, seen, at)
	}
	if seen["a"].wait > relayRetryMax {
		t.Fatalf("the wait climbed past its cap: %v", seen["a"].wait)
	}
	if seen["a"].wait != relayRetryMax {
		t.Fatalf("the wait did not climb to its cap: %v", seen["a"].wait)
	}
}

// Peers that leave the mesh stop being watched.
func TestARetiredPeerIsForgotten(t *testing.T) {
	now := time.Now()
	seen := map[string]*relayWatch{}
	pickRelayToRetry(map[string]string{"a": "relay"}, seen, now)
	pickRelayToRetry(map[string]string{}, seen, now.Add(time.Minute))
	if len(seen) != 0 {
		t.Fatal("a peer that is gone is still being watched")
	}
}

// What the watchdog decides a peer is doing, from its last handshake.
//
// This is the judgement that cost seven hours. The watchdog asked ICE whether a
// peer was connected; a flapping signalling session let a negotiation through
// now and then, ICE said connected for a moment, and that moment reset the
// clock the watchdog was counting on. Meanwhile the tunnel had not completed a
// handshake since the night before.
func TestCarryingReadsTheHandshakeAndNotTheHope(t *testing.T) {
	now := int64(1_000_000)
	stale := int64(handshakeStale / time.Second)

	// A peer the device has never heard of is mid-setup, not in trouble.
	if !carrying(false, 0, now) {
		t.Fatal("a peer the device does not know yet was called dead")
	}

	// A negotiated path that has never completed a handshake is not carrying,
	// whatever ICE says about it.
	if carrying(true, 0, now) {
		t.Fatal("a path with no handshake at all was called healthy")
	}

	// Fresh.
	if !carrying(true, now-1, now) {
		t.Fatal("a handshake from a second ago was called stale")
	}
	if !carrying(true, now-stale+1, now) {
		t.Fatal("a handshake just inside the window was called stale")
	}

	// And the case that matters: a tunnel that has been silent for hours while
	// ICE still calls itself connected.
	if carrying(true, now-stale-1, now) {
		t.Fatal("a handshake past the window was still called healthy")
	}
	if carrying(true, now-9*3600, now) {
		t.Fatal("a tunnel with no handshake for nine hours was called healthy; this is the outage")
	}
}

// The escalations must not fire because one machine is switched off.
//
// This is the regression that cost an afternoon. Once the watchdog started
// measuring handshakes instead of ICE state it began seeing the truth, and the
// truth in any real mesh includes a shop with no route and a laptop that is
// asleep. Measuring only the worst peer, that truth reads as a permanent
// emergency: fifteen self-restarts in three hours, each renegotiating every
// tunnel and losing several to the relay on the way back.
func TestEscalationNeedsMostOfTheMeshNotOnePeer(t *testing.T) {
	// One peer down out of eighteen is an ordinary Tuesday.
	if share(1, 18) >= resetShare {
		t.Fatalf("one peer down out of eighteen (%.2f) reconnects the signalling", share(1, 18))
	}
	if share(1, 18) >= restartShare {
		t.Fatal("one peer down out of eighteen restarts the whole agent")
	}
	// A laptop and two closed shops, still ordinary.
	if share(3, 18) >= resetShare {
		t.Fatalf("three peers down out of eighteen (%.2f) reconnects the signalling", share(3, 18))
	}

	// Half the mesh gone is this machine's problem, not the mesh's.
	if share(9, 18) < resetShare {
		t.Fatal("half the mesh unreachable does not even reconnect the signalling")
	}
	// And almost all of it gone is the case where starting over has always
	// helped.
	if share(15, 18) < restartShare {
		t.Fatal("fifteen of eighteen unreachable is not enough to restart")
	}
	if share(9, 18) >= restartShare {
		t.Fatal("half the mesh unreachable restarts the agent, before reconnecting has been given a chance")
	}

	// A mesh of one peer must not be a permanent emergency either: the share is
	// 1.0 the moment that peer blinks, which is why the time thresholds still
	// guard everything above this.
	if share(0, 0) != 0 {
		t.Fatal("a mesh with no peers reports trouble")
	}
}

func share(stuck, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(stuck) / float64(total)
}
