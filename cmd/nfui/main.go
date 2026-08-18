// Command nfui is the menu bar client.
//
// It shows what the agent is doing and it does not do anything itself. The
// agent runs as a system service, as root, because creating a network interface
// needs it; this runs as whoever is logged in and reads the agent's control
// socket. Joining, leaving and choosing a mesh stay on the command line, where
// they have a credential behind them.
//
// The whole of it is an icon that says whether the mesh is working and a menu
// that says why when it is not. A window would be a bigger promise than there
// is anything to put in it.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"fyne.io/systray"
)

// refreshEvery is how often the menu is redrawn from the agent.
//
// Two seconds, which is faster than anything actually changes. This is the one
// place where being slightly ahead costs nothing: a menu bar is looked at for
// three seconds by somebody who already suspects something is wrong, and a
// stale answer in that moment is worse than a hundred wasted reads.
const refreshEvery = 2 * time.Second

func main() {
	systray.Run(onReady, func() {})
}

func onReady() {
	systray.SetTitle("")
	systray.SetTooltip("netflow")

	status := systray.AddMenuItem("…", "")
	status.Disable()
	address := systray.AddMenuItem("", "")
	address.Disable()
	systray.AddSeparator()

	peers := systray.AddMenuItem("peers", "")
	peers.Disable()
	// A fixed set of rows, hidden until there is something to put in them.
	// systray on macOS cannot remove an item once added, so the alternative is
	// a menu that grows every refresh and never shrinks.
	rows := make([]*systray.MenuItem, 0, maxPeerRows)
	for range maxPeerRows {
		it := systray.AddMenuItem("", "")
		it.Disable()
		it.Hide()
		rows = append(rows, it)
	}

	systray.AddSeparator()
	copyAddr := systray.AddMenuItem("Copy my address", "")
	quit := systray.AddMenuItem("Quit", "")

	var mine string
	go func() {
		for {
			st, err := askAgent()
			render(st, err, status, address, peers, rows)
			mine = st.Address
			time.Sleep(refreshEvery)
		}
	}()

	go func() {
		for {
			select {
			case <-copyAddr.ClickedCh:
				if mine != "" {
					_ = copyToClipboard(mine)
				}
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// maxPeerRows bounds the menu. A mesh can be large and a menu cannot: past a
// dozen the list stops being something anybody reads and the panel is the right
// place to look instead.
const maxPeerRows = 12

func render(st agentStatus, err error, status, address, peers *systray.MenuItem, rows []*systray.MenuItem) {
	if err != nil {
		// The two ways this fails need different answers from the person
		// reading it, so they are not folded into "disconnected".
		systray.SetTitle("○")
		status.SetTitle("agent not running")
		address.SetTitle("start it: sudo nfagent up")
		address.Show()
		peers.Hide()
		for _, r := range rows {
			r.Hide()
		}
		return
	}

	connected, total := 0, len(st.Peers)
	for _, p := range st.Peers {
		if p.State == "connected" && p.Handshake > 0 {
			connected++
		}
	}

	switch {
	case !st.Signal:
		systray.SetTitle("○")
		status.SetTitle("cannot reach the signal server")
	case total == 0:
		systray.SetTitle("●")
		status.SetTitle("no peers yet")
	case connected == total:
		systray.SetTitle("●")
		status.SetTitle(fmt.Sprintf("%d of %d connected", connected, total))
	default:
		systray.SetTitle("◐")
		status.SetTitle(fmt.Sprintf("%d of %d connected", connected, total))
	}

	address.SetTitle(st.Address + "  ·  " + orDash(st.Interface))
	address.Show()

	if total == 0 {
		peers.Hide()
		for _, r := range rows {
			r.Hide()
		}
		return
	}
	peers.Show()
	for i, r := range rows {
		if i >= len(st.Peers) {
			r.Hide()
			continue
		}
		r.SetTitle("   " + describe(st.Peers[i]))
		r.Show()
	}
}

// describe is one peer in one line, said the way somebody would ask about it.
func describe(p agentPeer) string {
	key := p.PublicKey
	if len(key) > 8 {
		key = key[:8]
	}
	switch {
	case p.State == "connected" && p.Handshake > 0 && p.Path == "relay":
		return fmt.Sprintf("%s  relayed  %dms", key, p.RTTMillis)
	case p.State == "connected" && p.Handshake > 0:
		return fmt.Sprintf("%s  direct  %dms", key, p.RTTMillis)
	case p.State == "connected":
		// A path exists and WireGuard has not agreed keys over it. Calling that
		// connected is what sends somebody looking in the wrong place.
		return key + "  no handshake"
	default:
		return key + "  " + p.State
	}
}

func orDash(s string) string {
	if s == "" {
		return "userspace"
	}
	return s
}

func copyToClipboard(s string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = stringReader(s)
		return cmd.Run()
	case "linux":
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = stringReader(s)
		if err := cmd.Run(); err == nil {
			return nil
		}
		cmd = exec.Command("wl-copy")
		cmd.Stdin = stringReader(s)
		return cmd.Run()
	default:
		return fmt.Errorf("no clipboard on %s", runtime.GOOS)
	}
}

func stringReader(s string) *os.File {
	r, w, err := os.Pipe()
	if err != nil {
		return nil
	}
	go func() {
		_, _ = w.WriteString(s)
		_ = w.Close()
	}()
	return r
}
