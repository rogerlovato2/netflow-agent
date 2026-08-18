//go:build linux

package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
)

// configureInterface gives the interface its addresses and brings it up.
//
// Shelling out to iproute2 rather than talking netlink directly. The netlink
// path is one more thing to get right per kernel version, and this runs once
// per start: the cost is a process, and what is bought is behaviour identical
// to what an administrator would type and can therefore verify by typing it.
func configureInterface(name string, addrs []netip.Addr, mtu int) error {
	if err := run("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}
	for _, a := range addrs {
		// A host address, not the mesh subnet: the subnet arrives as one route
		// per peer, so a peer that leaves the map stops being routed instead of
		// falling into a hole the interface would otherwise keep open.
		bits := 32
		family := "-4"
		if a.Is6() {
			bits = 128
			family = "-6"
		}
		cidr := fmt.Sprintf("%s/%d", a.String(), bits)
		if err := run("ip", family, "addr", "add", cidr, "dev", name); err != nil {
			return err
		}
	}
	return run("ip", "link", "set", "dev", name, "up")
}

func addRoute(name string, p netip.Prefix) error {
	family := "-4"
	if p.Addr().Is6() {
		family = "-6"
	}
	// `replace` and not `add`: a route already there is the normal case on a
	// reconnect, and it is not an error worth failing a peer over.
	return run("ip", family, "route", "replace", p.String(), "dev", name)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tunnel: %s %v: %w: %s", name, args, err, out)
	}
	return nil
}

func delRoute(name string, p netip.Prefix) error {
	family := "-4"
	if p.Addr().Is6() {
		family = "-6"
	}
	return run("ip", family, "route", "del", p.String(), "dev", name)
}
