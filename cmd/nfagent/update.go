package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/rogerlovato2/netflow-agent/internal/engine"
	"github.com/rogerlovato2/netflow-agent/internal/selfupdate"
)

// How often a machine looks for a newer release once it has been told it may.
//
// Six hours because an update is not urgent and a fleet that all wakes at the
// same minute is a spike on somebody's bandwidth. A release that matters is
// still applied within a day without anybody touching a machine, and a release
// that cannot wait is what the button in the panel is for.
const updateEvery = 6 * time.Hour

// lastUpdateError is what the panel is told about the last attempt.
//
// Reported rather than only logged: an update that quietly refuses itself looks
// exactly like an update nobody asked for, and the machine that needs looking
// at is the one that has been failing for a week.
var lastUpdateError struct {
	sync.Mutex
	text string
}

func setUpdateError(err error) {
	lastUpdateError.Lock()
	defer lastUpdateError.Unlock()
	if err == nil {
		lastUpdateError.text = ""
		return
	}
	lastUpdateError.text = err.Error()
}

func updateError() string {
	lastUpdateError.Lock()
	defer lastUpdateError.Unlock()
	return lastUpdateError.text
}

// considerUpdate replaces this binary if everything agrees that it should.
//
// Three separate yeses are required, and they are checked in the order that
// costs least: this build has a key it trusts, this machine has not refused
// locally, and the panel has asked. Any one of them missing and nothing is
// downloaded at all.
func considerUpdate(ctx context.Context, eng *engine.Engine, cfg *Config, policy *updatePolicy, log *slog.Logger) {
	if cfg.NoRemoteUpdate || policy == nil || !policy.Enabled {
		return
	}
	// The map is polled every twenty seconds and a request stays alive for half
	// an hour, so "may update" arrives many times for one press of one button.
	// Without this, that is a download every twenty seconds.
	if !attempts.begin() {
		return
	}
	defer attempts.done()
	if !selfupdate.Enabled() {
		// Said once per attempt rather than never: a panel with the switch on
		// and a build with no key will otherwise sit there looking like it is
		// working.
		setUpdateError(selfupdate.ErrNoKey)
		log.Debug("update: asked to update, but this build trusts no key")
		return
	}

	changed, err := selfupdate.Apply(ctx, policy.Version, version, log)
	switch {
	case errors.Is(err, selfupdate.ErrNotNewer):
		// The ordinary state of an up-to-date machine, and not a failure.
		setUpdateError(nil)
		return
	case err != nil:
		setUpdateError(err)
		log.Warn("update: refused", "err", err)
		return
	case !changed:
		setUpdateError(nil)
		return
	}

	setUpdateError(nil)
	log.Info("update: installed; restarting into the new binary")
	restart(eng)
}

// watchForUpdates is the periodic half. The map is polled far more often than
// this and carries the policy with it, so the ticker is only what makes a
// machine that has been left alone eventually catch up.
func watchForUpdates(ctx context.Context, eng *engine.Engine, cfg *Config, policy func() *updatePolicy, log *slog.Logger) {
	t := time.NewTicker(updateEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			considerUpdate(ctx, eng, cfg, policy(), log)
		}
	}
}

// attemptGap is the least time between two tries.
//
// Five minutes: a machine that failed for a reason that will pass — the release
// page unreachable, a disk that was full — gets several more chances inside the
// window a request stays open, without turning a standing permission into a
// download loop.
const attemptGap = 5 * time.Minute

// attemptGate keeps one update running at a time, and no more often than
// attemptGap.
type attemptGate struct {
	mu      sync.Mutex
	running bool
	last    time.Time
}

var attempts attemptGate

// begin reports whether this attempt may go ahead, and claims the slot if so.
func (g *attemptGate) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.running || time.Since(g.last) < attemptGap {
		return false
	}
	g.running = true
	return true
}

func (g *attemptGate) done() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.running = false
	// Counted from the end, not the start: a download that took four minutes
	// should not be followed by another one a minute later.
	g.last = time.Now()
}
