//go:build linux

package router

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// On Linux both halves are the kernel's: a sysctl turns forwarding on, and
// nftables does the rest.
//
// Its own table, separate from the one the access rules live in. They are
// rewritten on different clocks by different parts of the agent, and sharing a
// table would mean each rebuild wiping the other's work — a bug that would look
// like the firewall randomly forgetting things.
const table = "netflow-router"

const forwardSysctl = "/proc/sys/net/ipv4/ip_forward"

type linuxRouter struct {
	// wasForwarding is what the machine said before this touched it, so a
	// machine that already forwarded for its own reasons is left forwarding
	// when the agent stops.
	wasForwarding string
	touched       bool
}

func newRouter() Router { return &linuxRouter{} }

func available() (bool, string) {
	if _, err := exec.LookPath("nft"); err != nil {
		return false, "nftables is not installed (apt install nftables)"
	}
	if _, err := os.Stat(forwardSysctl); err != nil {
		return false, "this kernel has no IPv4 forwarding switch"
	}
	return true, ""
}

func (l *linuxRouter) Apply(iface string, mesh netip.Prefix, routes []Route) error {
	routes = sorted(routes)

	// Nothing to carry: take the rules away and stop. Forwarding is left as it
	// was found — see Close.
	if len(routes) == 0 {
		return l.clear()
	}

	if ok, why := available(); !ok {
		return fmt.Errorf("router: %s", why)
	}
	if err := l.enableForwarding(); err != nil {
		return err
	}
	return nftRun(buildRouterRuleset(iface, mesh, routes))
}

// buildRouterRuleset is the ruleset as text, which is what the test reads.
//
// Written whole and replacing whatever was there, for the same reason the
// access rules are: a firewall that is a little bit wrong is worse than one
// that is rebuilt, and rebuilding needs no memory of what it changed from.
func buildRouterRuleset(iface string, mesh netip.Prefix, routes []Route) string {
	var b strings.Builder
	// Created and deleted before being created, so this works whether or not
	// the table was already there. nft has no "replace table".
	fmt.Fprintf(&b, "table inet %s\n", table)
	fmt.Fprintf(&b, "delete table inet %s\n", table)
	fmt.Fprintf(&b, "table inet %s {\n", table)

	// What may be forwarded.
	//
	// Only traffic arriving on the mesh interface, and only towards the
	// networks this machine was told to carry. Everything else forwarded
	// through this machine is somebody else's business and is not accepted
	// here — the chain's policy stays accept so that a machine which was
	// already routing for its own reasons keeps doing it.
	fmt.Fprintf(&b, "  chain forward {\n")
	fmt.Fprintf(&b, "    type filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
	fmt.Fprintf(&b, "    iifname \"%s\" ip saddr %s ip daddr { %s } accept\n",
		iface, mesh, networks(routes))
	fmt.Fprintf(&b, "  }\n")

	// What is rewritten on the way out.
	var masq []Route
	for _, r := range routes {
		if r.Masquerade {
			masq = append(masq, r)
		}
	}
	if len(masq) > 0 {
		fmt.Fprintf(&b, "  chain postrouting {\n")
		fmt.Fprintf(&b, "    type nat hook postrouting priority srcnat; policy accept;\n")
		// Only what came in over the mesh. Without the interface test this
		// would also rewrite the machine's own traffic to those networks,
		// which is its own LAN and which it reaches perfectly well as itself.
		fmt.Fprintf(&b, "    ip saddr %s ip daddr { %s } masquerade\n", mesh, networks(masq))
		fmt.Fprintf(&b, "  }\n")
	}

	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func (l *linuxRouter) enableForwarding() error {
	current, err := os.ReadFile(forwardSysctl)
	if err != nil {
		return fmt.Errorf("router: reading %s: %w", forwardSysctl, err)
	}
	if strings.TrimSpace(string(current)) == "1" {
		return nil
	}
	if !l.touched {
		l.wasForwarding = strings.TrimSpace(string(current))
		l.touched = true
	}
	if err := os.WriteFile(forwardSysctl, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("router: turning on IPv4 forwarding: %w", err)
	}
	return nil
}

func (l *linuxRouter) clear() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	// Deleting a table that is not there is an error worth ignoring: it is the
	// state this was trying to reach.
	_ = nftRun(fmt.Sprintf("table inet %s\ndelete table inet %s\n", table, table))
	return nil
}

// Close stops forwarding and puts the sysctl back, but only if this turned it
// on. A machine that was already a router before the agent arrived stays one
// after it leaves.
func (l *linuxRouter) Close() error {
	err := l.clear()
	if l.touched && l.wasForwarding != "" && l.wasForwarding != "1" {
		if werr := os.WriteFile(forwardSysctl, []byte(l.wasForwarding+"\n"), 0o644); werr != nil && err == nil {
			err = werr
		}
	}
	return err
}

func nftRun(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("router: nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
