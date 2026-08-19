package main

import (
	"context"
	"os/exec"
	"runtime"
	"time"

	"fyne.io/systray"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// version is stamped at build time. "dev" means somebody built this by hand.
var version = "dev"

// App is what the page can call.
//
// Four methods, and three of them are questions. This program holds no state
// worth the name: the agent has all of it, and anything cached here would be a
// second copy to be wrong.
type App struct {
	ctx  context.Context
	tray *tray
	// endTray takes the menu bar item down. Without it the icon outlives the
	// process by a few seconds, which looks like an application that did not
	// really quit.
	endTray func()
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// The menu bar item, sharing this process rather than being one of its
	// own. systray is told not to take the application over: it builds a status
	// item and leaves the event loop, the delegate and the window to wails.
	a.tray = &tray{app: a}
	start, end := systray.RunWithExternalLoop(a.tray.build, nil)
	a.endTray = end
	onMainThread(start)

	// The page asks for status when it wants it, and this pushes one every two
	// seconds so it does not have to poll on a timer of its own. Two seconds is
	// faster than anything actually changes — which is the right speed for a
	// window somebody opens because they already suspect something is wrong.
	//
	// The menu bar is fed from the same tick, so the corner of the screen and
	// the window can never be showing two different answers.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st := a.Status()
				wruntime.EventsEmit(ctx, "status", st)
				a.tray.update(st)
			}
		}
	}()
}

// shutdown is wails' way out. Returning false lets it close.
func (a *App) shutdown(context.Context) {
	if a.endTray != nil {
		a.endTray()
	}
}

// Status is what the agent says about itself, or why it said nothing.
func (a *App) Status() Status {
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Second)
	defer cancel()
	st := fetchStatus(ctx)
	st.Version = version
	return st
}

// OpenPanel opens the management server in a browser.
//
// The address comes from the agent rather than from anything typed here: this
// machine already knows which panel admitted it, and asking somebody to
// remember a URL they have already proved they know is busywork.
func (a *App) OpenPanel() {
	st := a.Status()
	if st.Server == "" {
		return
	}
	wruntime.BrowserOpenURL(a.ctx, st.Server)
}

// Fit makes the window as tall as what is in it.
//
// A status window with two peers in a frame built for ten looks broken, and one
// with ten in a frame built for two hides half of them. The page is the only
// thing that knows how tall it is, so it measures itself and says; this clamps
// the answer, because a page that asks for four thousand pixels is a page with
// a bug and not a window anybody wants.
func (a *App) Fit(height int) {
	const (
		min = 260
		max = 760
	)
	if height < min {
		height = min
	}
	if height > max {
		height = max
	}
	// The width is left exactly as it is: the height follows the content, and
	// somebody who widened the window meant it.
	w, _ := wruntime.WindowGetSize(a.ctx)
	wruntime.WindowSetSize(a.ctx, w, height)
}

// Copy puts a value on the clipboard — an address, a key. It is the one thing a
// window can do that a status line cannot.
func (a *App) Copy(value string) {
	_ = wruntime.ClipboardSetText(a.ctx, value)
}

// OpenLog shows the agent's log in whatever the system uses for such things.
//
// When something is wrong, the next question is always "what does it say", and
// the answer lives in a file whose path nobody remembers.
func (a *App) OpenLog() {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", "-a", "Console", "/var/log/netflow-agent.log").Start()
	case "windows":
		_ = exec.Command("notepad.exe", `C:\ProgramData\netflow\agent.log`).Start()
	default:
		_ = exec.Command("xdg-open", "/var/log/netflow-agent.log").Start()
	}
}
