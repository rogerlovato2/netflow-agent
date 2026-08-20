//go:build darwin

package router

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// macOS has both halves too, under different names: a sysctl for forwarding and
// pf for the rewriting.
//
// pf is one firewall shared by the whole machine, and other things use it —
// Internet Sharing, corporate VPN clients, whatever somebody installed. So this
// does not touch the main ruleset. It writes an anchor, which is pf's word for
// a named compartment, and only ever loads and flushes its own.
//
// The anchor still has to be referenced from the main ruleset once. macOS ships
// /etc/pf.conf with anchors for exactly this, and the reference is added there
// if it is missing — the one edit outside our own compartment, and the smallest
// that makes the rest possible.
const anchorName = "netflow"

const (
	pfConf       = "/etc/pf.conf"
	anchorFile   = "/etc/pf.anchors/netflow"
	forwardingV4 = "net.inet.ip.forwarding"
)

type darwinRouter struct {
	wasForwarding string
	touched       bool
}

func newRouter() Router { return &darwinRouter{} }

func available() (bool, string) {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return false, "pfctl is missing, which should not happen on macOS"
	}
	return true, ""
}

func (d *darwinRouter) Apply(iface string, mesh netip.Prefix, routes []Route) error {
	routes = sorted(routes)
	if len(routes) == 0 {
		return d.clear()
	}
	if ok, why := available(); !ok {
		return fmt.Errorf("router: %s", why)
	}
	if err := d.enableForwarding(); err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/pf.anchors", 0o755); err != nil {
		return fmt.Errorf("router: %w", err)
	}
	if err := os.WriteFile(anchorFile, []byte(buildAnchor(iface, mesh, routes, egress)), 0o644); err != nil {
		return fmt.Errorf("router: writing the pf anchor: %w", err)
	}
	if err := ensureAnchorReferenced(); err != nil {
		return err
	}
	// Enabling pf when it is already on returns an error saying so, which is
	// not one: the state it was asked for is the state it is in.
	_ = run("pfctl", "-E")
	if err := run("pfctl", "-a", anchorName, "-f", anchorFile); err != nil {
		return err
	}
	return nil
}

// buildAnchor is the anchor's rules as text, which is what the test reads.
//
// out says which interface each network leaves by. It is asked of the routing
// table rather than assumed, because "en0" is right on a laptop and wrong on a
// Mac with a dock, a second card, or Wi-Fi off — and a nat rule on the wrong
// interface silently rewrites nothing.
func buildAnchor(iface string, mesh netip.Prefix, routes []Route, out func(netip.Prefix) string) string {
	var b strings.Builder
	b.WriteString("# Written by nfagent. Edits are lost on the next change.\n")
	for _, r := range routes {
		if !r.Masquerade {
			continue
		}
		dev := out(r.Network)
		if dev == "" {
			continue
		}
		// From the mesh only. Without that the rule would also rewrite this
		// machine's own traffic to its own LAN, which it reaches perfectly well
		// as itself.
		fmt.Fprintf(&b, "nat on %s from %s to %s -> (%s)\n",
			dev, mesh.String(), r.Network.String(), dev)
	}
	// What may be forwarded, said explicitly. pf passes by default, so these
	// exist for the machine whose main ruleset does not.
	for _, r := range routes {
		fmt.Fprintf(&b, "pass in on %s from %s to %s\n", iface, mesh.String(), r.Network.String())
		fmt.Fprintf(&b, "pass out from %s to %s\n", mesh.String(), r.Network.String())
	}
	return b.String()
}

// egress asks the routing table which interface reaches a network.
//
// Empty when it cannot tell, and the caller writes no rule rather than a wrong
// one: a nat rule on an interface the traffic never crosses does nothing, and
// looks from the outside exactly like the feature being broken.
func egress(network netip.Prefix) string {
	out, err := exec.Command("route", "-n", "get", network.Addr().String()).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if _, rest, ok := strings.Cut(strings.TrimSpace(line), "interface:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// ensureAnchorReferenced adds the one line to /etc/pf.conf that makes the
// anchor load, and only if it is not already there.
//
// Appended rather than rewritten, and the file is left alone entirely once the
// line exists: /etc/pf.conf belongs to the machine, not to this.
func ensureAnchorReferenced() error {
	current, err := os.ReadFile(pfConf)
	if err != nil {
		return fmt.Errorf("router: reading %s: %w", pfConf, err)
	}
	line := fmt.Sprintf("anchor \"%s\"", anchorName)
	if strings.Contains(string(current), line) {
		return nil
	}
	updated := string(current)
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += fmt.Sprintf("\n# Added by nfagent so it can carry networks for the mesh.\n"+
		"%s\nnat-anchor \"%s\"\n", line, anchorName)
	if err := os.WriteFile(pfConf, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("router: adding the anchor to %s: %w", pfConf, err)
	}
	// The main ruleset has to be reloaded for the new reference to exist.
	return run("pfctl", "-f", pfConf)
}

func (d *darwinRouter) enableForwarding() error {
	out, err := exec.Command("sysctl", "-n", forwardingV4).Output()
	if err != nil {
		return fmt.Errorf("router: reading %s: %w", forwardingV4, err)
	}
	if strings.TrimSpace(string(out)) == "1" {
		return nil
	}
	if !d.touched {
		d.wasForwarding = strings.TrimSpace(string(out))
		d.touched = true
	}
	return run("sysctl", "-w", forwardingV4+"=1")
}

func (d *darwinRouter) clear() error {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return nil
	}
	// Flushing an anchor that holds nothing is not an error worth reporting.
	_ = run("pfctl", "-a", anchorName, "-F", "all")
	return nil
}

func (d *darwinRouter) Close() error {
	err := d.clear()
	if d.touched && d.wasForwarding != "" && d.wasForwarding != "1" {
		if werr := run("sysctl", "-w", forwardingV4+"="+d.wasForwarding); werr != nil && err == nil {
			err = werr
		}
	}
	return err
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("router: %s %s: %w: %s", name, strings.Join(args, " "),
			err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
