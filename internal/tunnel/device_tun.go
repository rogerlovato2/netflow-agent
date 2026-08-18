package tunnel

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultTUNName is the interface this creates when nothing else is asked for.
//
// On macOS the kernel names the interface itself — utun0, utun1, whichever is
// free — and refuses any name that is not "utun" or "utunN". The name asked for
// here is therefore a request on Linux and a hint everywhere else, which is why
// callers read the name back from the Device rather than assuming it.
const DefaultTUNName = "netflow0"

// NewTUNDevice builds a device the operating system can see.
//
// This is the difference between a tunnel and a demonstration. The userspace
// device keeps its network stack inside this process: the agent can reach the
// mesh through it, and nothing else on the machine can — `ping` goes to the
// default gateway and dies, because no interface holds the address and no route
// points anywhere. Here an interface appears, an address is set on it, and the
// mesh becomes something the whole machine can use.
//
// The price is privilege. Creating an interface and writing a route need root
// on Linux and macOS, which is why the error says so instead of failing with
// whatever the kernel returned.
func NewTUNDevice(name string, addrs []netip.Addr, mtu int, log *slog.Logger) (*Device, error) {
	if name == "" {
		name = DefaultTUNName
	}
	if runtime.GOOS == "darwin" {
		// The kernel picks the number; asking for one it dislikes fails with an
		// error that says nothing about why.
		name = "utun"
	}

	t, err := tun.CreateTUN(name, mtu)
	if err != nil {
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("tunnel: creating the interface needs root: %w", err)
		}
		return nil, fmt.Errorf("tunnel: creating the interface: %w", err)
	}

	// What the kernel actually called it, which on macOS is never what was asked.
	real, err := t.Name()
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("tunnel: reading the interface name: %w", err)
	}

	if err := configureInterface(real, addrs, mtu); err != nil {
		_ = t.Close()
		return nil, err
	}

	d := device.NewDevice(t, conn.NewDefaultBind(), deviceLogger(log))
	log.Info("tunnel: interface up", "name", real, "addrs", addrs, "mtu", mtu)
	return &Device{dev: d, tun: t, name: real, log: log, peers: map[string]netip.AddrPort{}}, nil
}

// AddRoute sends a prefix through this interface.
//
// One route per peer rather than one for the whole mesh subnet: a peer removed
// from the map has its route removed with it, so its address goes back to
// being unreachable instead of disappearing into an interface that no longer
// carries it.
//
// The route goes in when the peer is configured, not when it connects. While
// the tunnel is down the packet enters the interface and is dropped there,
// which is what a VPN should do — without the route it would go to the default
// gateway instead, and a mesh address leaking onto the local network is both
// wrong and hard to notice.
func (d *Device) AddRoute(p netip.Prefix) error {
	if d.name == "" {
		// A userspace device has no interface, so there is nowhere to put a
		// route. Saying nothing is right: the caller is the same code either
		// way, and in userspace the peer is reached through Device.Net.
		return nil
	}
	return addRoute(d.name, p)
}

// DelRoute stops sending a prefix through this interface.
func (d *Device) DelRoute(p netip.Prefix) error {
	if d.name == "" {
		return nil
	}
	return delRoute(d.name, p)
}

// Name is what the operating system calls this interface, empty in userspace.
func (d *Device) Name() string { return d.name }

// ensure the key type stays imported for the platform files' signatures
var _ = wgtypes.Key{}
