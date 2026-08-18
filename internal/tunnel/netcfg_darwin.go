//go:build darwin

package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
)

// configureInterface gives the interface its addresses and brings it up.
//
// macOS has no `ip`, and utun is a point-to-point interface: `ifconfig` wants
// the local address twice, as local and destination. Getting that wrong yields
// an interface that comes up and drops everything, with no error anywhere.
func configureInterface(name string, addrs []netip.Addr, mtu int) error {
	for _, a := range addrs {
		family := "inet"
		if a.Is6() {
			family = "inet6"
			if err := run("ifconfig", name, family, a.String(), "prefixlen", "128", "alias"); err != nil {
				return err
			}
			if err := loopbackSelf(a); err != nil {
				return err
			}
			continue
		}
		if err := run("ifconfig", name, family, a.String(), a.String(), "netmask", "255.255.255.255"); err != nil {
			return err
		}
		if err := loopbackSelf(a); err != nil {
			return err
		}
	}
	if err := run("ifconfig", name, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}
	return run("ifconfig", name, "up")
}

func addRoute(name string, p netip.Prefix) error {
	family := "-inet"
	if p.Addr().Is6() {
		family = "-inet6"
	}
	// Deleted first because macOS `route add` fails on a route that exists, and
	// a reconnect is exactly when it exists. The delete is expected to fail the
	// first time and its error is deliberately ignored.
	_ = exec.Command("route", "-n", "delete", family, p.String()).Run()
	return run("route", "-n", "add", family, p.String(), "-interface", name)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tunnel: %s %v: %w: %s", name, args, err, out)
	}
	return nil
}

func delRoute(_ string, p netip.Prefix) error {
	family := "-inet"
	if p.Addr().Is6() {
		family = "-inet6"
	}
	return run("route", "-n", "delete", family, p.String())
}

// loopbackSelf makes a machine's own mesh address reachable from itself.
//
// utun is point-to-point, and macOS sends a packet addressed to the interface's
// own address out of that interface rather than looping it back. It reaches
// WireGuard, which looks for a peer allowed to hold that address, finds none —
// the address belongs to this machine, not to a peer — and drops it.
//
// The result is a machine whose own mesh address answers every other machine in
// the mesh and not itself: `ping 10.90.0.3` from 10.90.0.3 times out, and so
// does connecting to a service bound to it. Somebody testing their own service
// from their own laptop concludes it is broken.
//
// Linux does not need this. An address there lands in the local routing table
// automatically, which is the same thing this arranges by hand.
func loopbackSelf(a netip.Addr) error {
	// Removed first: the alias survives a process that was killed rather than
	// stopped, and `ifconfig alias` on an address that is already there fails.
	// The removal is expected to fail the first time, and its error is ignored.
	_ = exec.Command("ifconfig", "lo0", family(a), a.String(), "-alias").Run()

	if a.Is6() {
		return run("ifconfig", "lo0", "inet6", a.String(), "prefixlen", "128", "alias")
	}
	return run("ifconfig", "lo0", "inet", a.String(), "netmask", "255.255.255.255", "alias")
}

// unconfigureInterface takes the loopback aliases back out.
//
// The interface itself disappears with the process that holds it; these do not,
// and an address left on lo0 would answer for a mesh this machine has left.
func unconfigureInterface(_ string, addrs []netip.Addr) {
	for _, a := range addrs {
		_ = exec.Command("ifconfig", "lo0", family(a), a.String(), "-alias").Run()
	}
}

func family(a netip.Addr) string {
	if a.Is6() {
		return "inet6"
	}
	return "inet"
}
