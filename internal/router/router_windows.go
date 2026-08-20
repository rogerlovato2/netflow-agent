//go:build windows

package router

// Windows can do this — RRAS forwards and the built-in NAT rewrites — but the
// agent itself does not run here yet. When it does, this is where the two
// halves go: IPEnableRouter in the registry plus a service restart for the
// first, and a NetNat object for the second.
//
// Refusing with a sentence beats half-working: a machine that says it carries a
// network and does not is a machine somebody debugs from the other end.
func newRouter() Router {
	return unsupported{why: "carrying a network is not implemented on Windows yet"}
}

func available() (bool, string) {
	return false, "carrying a network is not implemented on Windows yet"
}
