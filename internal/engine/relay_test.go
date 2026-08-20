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
