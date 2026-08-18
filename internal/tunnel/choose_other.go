//go:build !linux

package tunnel

import (
	"log/slog"
	"net/netip"
)

// NewSystemDevice creates the best interface this machine can give.
//
// Only one option away from Linux: macOS has no WireGuard in the kernel, and
// utun is the way an interface is made there at all.
func NewSystemDevice(name string, addrs []netip.Addr, mtu int, log *slog.Logger) (*Device, error) {
	return NewTUNDevice(name, addrs, mtu, log)
}
