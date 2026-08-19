package main

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"fyne.io/systray"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// maxRows is how many machines the submenu lists.
//
// The rows are created up front and hidden, because a menu that is rebuilt
// every two seconds is a menu that changes under the cursor. Forty is past the
// point where anybody reads a menu, and the window is where the rest live.
const maxRows = 40

// The state of a machine, in the only vocabulary a menu has. There is no way
// to colour a menu item's text, so the colour is the character.
const (
	dotOn  = "\U0001F7E2" // a green circle: a tunnel that is up
	dotOff = "\u26AA"     // a pale one: everything else
)

// tray is the menu bar item.
//
// It exists because the window is not the thing somebody wants open all day —
// the answer to "is it working" belongs in the corner of the screen, and the
// window is what you open when the answer is no.
type tray struct {
	app *App

	status   *systray.MenuItem
	address  *systray.MenuItem
	uptime   *systray.MenuItem
	machines *systray.MenuItem
	connect  *systray.MenuItem
	rows     []*systray.MenuItem

	mu    sync.Mutex
	solid bool // what the icon last showed, so it is only redrawn on a change
	shown bool
}

func (t *tray) build() {
	systray.SetTemplateIcon(trayIcon(false), trayIcon(false))
	systray.SetTooltip("netflow")

	t.status = systray.AddMenuItem("…", "")
	t.status.Disable()
	t.address = systray.AddMenuItem("", "")
	t.address.Disable()
	t.address.Hide()
	t.uptime = systray.AddMenuItem("", "")
	t.uptime.Disable()
	t.uptime.Hide()

	systray.AddSeparator()
	// A submenu rather than a list in the open: this menu is looked at to
	// answer "is it working", and the answer to that is the line above. Which
	// machines, one by one, is the next question and belongs one level in.
	t.machines = systray.AddMenuItem("Machines", "")
	for range maxRows {
		it := t.machines.AddSubMenuItem("", "")
		it.Disable()
		it.Hide()
		t.rows = append(t.rows, it)
	}

	systray.AddSeparator()
	open := systray.AddMenuItem("Open netflow", "")
	copyAddr := systray.AddMenuItem("Copy my address", "")
	t.connect = systray.AddMenuItem("Disconnect", "")

	systray.AddSeparator()
	// The log lives here rather than in the window: it is what somebody wants
	// when they are not going to read anything else, and reaching it should not
	// cost a window. The panel is not here at all — it is a web page about the
	// whole mesh, and this menu is about this machine.
	logs := systray.AddMenuItem("Open the log", "")

	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit", "")

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				wruntime.WindowShow(t.app.ctx)
			case <-copyAddr.ClickedCh:
				t.app.Copy(t.app.Status().Address)
			case <-t.connect.ClickedCh:
				// Whatever it is now, ask for the other one.
				t.app.SetConnected(t.app.Status().Paused)
			case <-logs.ClickedCh:
				t.app.OpenLog()
			case <-quit.ClickedCh:
				wruntime.Quit(t.app.ctx)
				return
			}
		}
	}()
}

// update redraws the menu from one status. Called on the same two-second tick
// that feeds the window, so the two never disagree.
func (t *tray) update(st Status) {
	up, total := 0, len(st.Peers)
	for _, p := range st.Peers {
		if p.State == "connected" && p.Handshake > 0 {
			up++
		}
	}

	solid := st.Reachable && st.Signal && !st.Paused && (total == 0 || up == total)
	t.setIcon(solid)

	if st.Paused {
		t.connect.SetTitle("Connect")
	} else {
		t.connect.SetTitle("Disconnect")
	}
	if st.Reachable {
		t.connect.Show()
	} else {
		t.connect.Hide()
	}

	switch {
	case !st.Reachable:
		t.status.SetTitle(orDefault(st.Error, "the agent did not answer"))
	case st.Paused:
		t.status.SetTitle("disconnected by request")
	case !st.Signal:
		t.status.SetTitle("cannot reach the signal server")
	case total == 0:
		t.status.SetTitle("no peers yet")
	default:
		t.status.SetTitle(fmt.Sprintf("%d of %d connected", up, total))
	}

	if st.Address == "" {
		t.address.Hide()
	} else {
		t.address.SetTitle(st.Address + "  ·  " + orDefault(st.Interface, "userspace"))
		t.address.Show()
	}

	if total == 0 || st.Paused {
		t.machines.Hide()
	} else {
		t.machines.SetTitle(fmt.Sprintf("Machines (%d)", total))
		t.machines.Show()
	}

	order := ordered(st.Peers)
	if st.StartedAt > 0 {
		t.uptime.SetTitle("up " + duration(time.Since(time.Unix(st.StartedAt, 0))))
		t.uptime.Show()
	} else {
		t.uptime.Hide()
	}

	for i, r := range t.rows {
		if i >= len(order) {
			r.Hide()
			continue
		}
		r.SetTitle(describe(order[i]))
		r.Show()
	}
}

// ordered is the list as somebody would want to read it: what is working
// first, and inside each group by address.
//
// By address rather than by name, because an address is where a machine is and
// a name is what somebody called it — and the list is stable under a rename,
// which a list sorted by name is not.
func ordered(peers []Peer) []Peer {
	out := append([]Peer(nil), peers...)
	slices.SortFunc(out, func(a, b Peer) int {
		if up(a) != up(b) {
			if up(a) {
				return -1
			}
			return 1
		}
		return compareAddresses(a.Address, b.Address)
	})
	return out
}

func up(p Peer) bool { return p.State == "connected" && p.Handshake > 0 }

// compareAddresses puts 10.90.0.9 before 10.90.0.30, which sorting the strings
// would not. An address that does not parse sorts last and keeps its order.
func compareAddresses(a, b string) int {
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	switch {
	case errX != nil && errY != nil:
		return 0
	case errX != nil:
		return 1
	case errY != nil:
		return -1
	}
	return x.Compare(y)
}

// setIcon redraws the mark only when the state it stands for has changed.
// Rendering forty-four squared pixels every two seconds forever is not
// expensive, but it is not nothing either, and nothing is the right amount.
func (t *tray) setIcon(solid bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.shown && t.solid == solid {
		return
	}
	t.solid, t.shown = solid, true
	icon := trayIcon(solid)
	systray.SetTemplateIcon(icon, icon)
}

// describe is one machine in one line: whether it is up, and what it is called.
//
// No latency and no path here. A menu is read at a glance and a number that
// changes every two seconds is not read at all — it is in the window, where
// somebody who wants it has gone looking for it.
func describe(p Peer) string {
	name := p.Name
	if name == "" {
		name = p.PublicKey
		if len(name) > 8 {
			name = name[:8]
		}
	}
	if up(p) {
		return dotOn + "  " + name
	}
	return dotOff + "  " + name
}

// duration says how long, in the two largest units that apply.
//
// Two, because one is imprecise enough to be useless at the boundaries — "1h"
// covers an hour and fifty-nine minutes — and three is a number nobody reads to
// the end of.
func duration(d time.Duration) string {
	s := int(d.Seconds())
	if s < 0 {
		return "—"
	}
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	days, hours, mins := s/86400, (s%86400)/3600, (s%3600)/60
	switch {
	case days > 0 && hours > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0 && mins > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	default:
		return fmt.Sprintf("%dm %ds", mins, s%60)
	}
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
