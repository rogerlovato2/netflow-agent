//go:build !darwin

package tunnel

import "net/netip"

// unconfigureInterface has nothing to do anywhere but macOS: every other
// platform puts a machine's own address in its local routing table by itself,
// and the interface takes its addresses with it when it goes.
func unconfigureInterface(string, []netip.Addr) {}
