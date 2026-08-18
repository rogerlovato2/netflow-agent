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
			continue
		}
		if err := run("ifconfig", name, family, a.String(), a.String(), "netmask", "255.255.255.255"); err != nil {
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
