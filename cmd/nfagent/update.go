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
