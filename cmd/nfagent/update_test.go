package main

import (
	"testing"
	"time"
)

// The gate is what keeps a standing permission from becoming a download loop.
//
// The map is polled every twenty seconds and a request stays open for half an
// hour, so "you may update" arrives about ninety times for one press of one
// button. Without this, that is ninety downloads.
func TestOnlyOneAttemptAtATime(t *testing.T) {
	var g attemptGate

	if !g.begin() {
		t.Fatal("the first attempt was refused")
	}
	if g.begin() {
		t.Error("a second attempt started while the first was running")
	}
	g.done()

	// And still refused immediately afterwards, which is the poll arriving
	// again twenty seconds later.
	if g.begin() {
		t.Error("an attempt started again with no gap")
	}

	// The gap is measured from the end of the last attempt, so a download that
	// took minutes is not followed by another one straight away.
	g.mu.Lock()
	g.last = time.Now().Add(-attemptGap - time.Second)
	g.mu.Unlock()
	if !g.begin() {
		t.Error("an attempt was refused after the gap had passed")
	}
	g.done()
}

// What is reported about the last try, which is the only way a machine that
// keeps refusing an update is visible from the panel.
func TestTheLastFailureIsRemembered(t *testing.T) {
	setUpdateError(nil)
	if got := updateError(); got != "" {
		t.Fatalf("a machine that never tried reports %q", got)
	}

	setUpdateError(errString("the signature does not match"))
	if got := updateError(); got != "the signature does not match" {
		t.Errorf("reported %q", got)
	}

	// A later success clears it, or the panel would show a failure that is over.
	setUpdateError(nil)
	if got := updateError(); got != "" {
		t.Errorf("a failure survived a success: %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
