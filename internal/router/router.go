// Package router lets one machine carry a network for the whole mesh.
//
// The mesh reaches machines that run an agent. Most networks contain machines
// that never will: a printer, a camera, a switch, a controller whose vendor
// stopped shipping firmware in 2016. Somebody has to stand at the edge of that
// network and forward for them, and this is what turns a machine into that
// somebody.
//
// Two things have to be true for it to work, and they are true on every
// operating system even though the way to arrange them is different on each:
//
//   - the kernel must forward packets that are not addressed to it, which is
//     off by default everywhere and for good reason;
//   - traffic leaving towards the network must usually be rewritten to come
//     from the router, because the machines behind it have no idea the mesh
//     exists and would answer a mesh address by asking their default gateway,
//     which has never heard of it either.
//
// The second is masquerading, and it is why this works at all on a network
// nobody can configure. Its cost is that the network sees one address instead
// of the real sender — the same trade every home router makes.
package router

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Route is one network this machine carries.
type Route struct {
	// Network is what to forward for.
	Network netip.Prefix
	// Masquerade rewrites the source as traffic leaves. Off means the network
	// needs a route back into the mesh configured somewhere in it, which is
	// possible and is almost never why somebody wanted this.
	Masquerade bool
}

// Router applies what the server asked for.
//
// Apply is given the whole list every time and makes the machine match it,
// including making it match an empty list. Incremental updates would need to
// know what was there before, and a machine that half stopped forwarding is
// worse than one that never started.
type Router interface {
	// Apply makes this machine forward for exactly these networks.
	//
	// mesh is the prefix the tunnel addresses come from. It is what separates
	// traffic that arrived over the mesh from the machine's own traffic to the
	// same networks — which it reaches perfectly well as itself, and which must
	// not be rewritten.
	Apply(iface string, mesh netip.Prefix, routes []Route) error
	// Close puts the machine back as it was found.
	Close() error
}

// Available reports whether this machine can be a router at all, and says why
// not when it cannot. The panel shows the reason: "it did not work" is a
// support conversation, and "this needs nftables, which is not installed" is
// somebody typing one command.
func Available() (bool, string) { return available() }

// New makes a router for this operating system.
func New() Router { return newRouter() }

// sorted returns the routes in a stable order, so the same set produces the
// same rules and a change in the rules means a change in the routes.
func sorted(routes []Route) []Route {
	out := append([]Route(nil), routes...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Network.String() < out[j].Network.String()
	})
	return out
}

// unsupported is what an operating system that cannot do this returns.
type unsupported struct{ why string }

func (u unsupported) Apply(string, netip.Prefix, []Route) error {
	if len(u.why) == 0 {
		return fmt.Errorf("router: not supported on this system")
	}
	return fmt.Errorf("router: %s", u.why)
}

func (u unsupported) Close() error { return nil }

// networks is the prefixes as text, for a rule that takes a set.
func networks(routes []Route) string {
	parts := make([]string, 0, len(routes))
	for _, r := range routes {
		parts = append(parts, r.Network.String())
	}
	return strings.Join(parts, ", ")
}
