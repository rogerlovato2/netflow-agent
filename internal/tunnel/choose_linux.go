//go:build linux

package tunnel

import (
	"fmt"
	"log/slog"
	"net/netip"
)

// NewSystemDevice creates the best interface this machine can give.
//
// The kernel's WireGuard first, and not only because it is faster. It goes
// through netlink, which an unprivileged container is given, while the
// userspace path needs /dev/net/tun, which it is not — so on a large share of
// Linux machines the kernel is the only one of the two that works at all.
//
// Falling back rather than choosing once: a kernel without the module and a
// kernel with it look the same from here until the attempt is made, and asking
// is more code than trying.
func NewSystemDevice(name string, addrs []netip.Addr, mtu int, log *slog.Logger) (*Device, error) {
	d, kerr := NewKernelDevice(name, addrs, mtu, log)
	if kerr == nil {
		return d, nil
	}
	log.Info("tunnel: the kernel would not take it, trying userspace", "err", kerr)

	d, uerr := NewTUNDevice(name, addrs, mtu, log)
	if uerr == nil {
		return d, nil
	}
	// Both are reported. Either one alone sends somebody looking in the wrong
	// place: the kernel error says nothing about the missing device node, and
	// the userspace error says nothing about the missing module.
	return nil, fmt.Errorf("tunnel: no way to create an interface on this machine.\n"+
		"  kernel:    %v\n"+
		"  userspace: %v", kerr, uerr)
}
