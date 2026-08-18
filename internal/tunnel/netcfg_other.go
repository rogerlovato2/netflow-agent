//go:build !linux && !darwin

package tunnel

import (
	"fmt"
	"net/netip"
	"runtime"
)

// Windows needs the wintun driver and its own way of setting an address; the
// BSDs need theirs. Refusing here is better than creating an interface that
// carries nothing and reporting success.
func configureInterface(string, []netip.Addr, int) error {
	return fmt.Errorf("tunnel: %s is not supported yet; run with -userspace", runtime.GOOS)
}

func addRoute(string, netip.Prefix) error {
	return fmt.Errorf("tunnel: %s is not supported yet", runtime.GOOS)
}

func delRoute(string, netip.Prefix) error {
	return fmt.Errorf("tunnel: %s is not supported yet", runtime.GOOS)
}
