package tunnel

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Device is a userspace WireGuard instance.
//
// Userspace rather than the kernel because this has to be the same code on
// Linux, Windows and macOS: only Linux has WireGuard in the kernel, and two of
// the three platforms would need a different implementation anyway. One code
// path costs roughly fifteen percent of throughput and buys a single set of
// bugs to fix.
type Device struct {
	dev *device.Device
	tun tun.Device

	// Net is the userspace network stack when the device was built with one. It
	// is what makes an end-to-end test possible without root: the tunnel is
	// dialled from inside the process instead of from the operating system.
	Net *netstack.Net

	// name is what the operating system calls the interface, empty when the
	// device keeps its stack inside this process.
	name string

	log *slog.Logger

	mu     sync.Mutex
	peers  map[string]netip.AddrPort // public key -> endpoint currently configured
	closed bool
}

// NewUserspaceDevice builds a device whose network stack lives in this process.
//
// Nothing is created on the host: no interface appears, no route is written,
// and no privilege is required. Traffic reaches it through Device.Net, which is
// exactly what an end-to-end test wants and what a client that only forwards
// its own connections could use.
func NewUserspaceDevice(addrs []netip.Addr, dns []netip.Addr, mtu int, log *slog.Logger) (*Device, error) {
	t, n, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunnel: creating the userspace interface: %w", err)
	}
	d := device.NewDevice(t, conn.NewDefaultBind(), deviceLogger(log))
	return &Device{dev: d, tun: t, Net: n, log: log, peers: map[string]netip.AddrPort{}}, nil
}

// Configure sets the private key and the port WireGuard listens on.
//
// The port is where the proxies deliver: every peer's packets arrive here, from
// loopback, whatever path they crossed to reach this machine.
func (d *Device) Configure(private wgtypes.Key, listenPort int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(private[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", listenPort)
	if err := d.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("tunnel: configuring the device: %w", err)
	}
	return nil
}

// Peer is one remote WireGuard peer.
type Peer struct {
	PublicKey wgtypes.Key
	// PresharedKey is optional and adds a symmetric secret on top of the key
	// pair. Zero means none.
	PresharedKey wgtypes.Key
	// Endpoint is where to send this peer's packets. With p2p in the picture it
	// is always a proxy on loopback, never the peer's real address.
	Endpoint netip.AddrPort
	// AllowedIPs is what may travel to and arrive from this peer. It is the
	// access control of WireGuard itself: a packet whose source is not in this
	// list is dropped after decryption, no matter which key signed it.
	AllowedIPs []netip.Prefix
	// Keepalive keeps a NAT mapping alive from the side that is behind one.
	// Zero disables it.
	KeepaliveSeconds int
}

// SetPeer adds a peer or replaces the configuration of one already there.
func (d *Device) SetPeer(p Peer) error {
	if len(p.AllowedIPs) == 0 {
		// A peer with no allowed IPs can complete a handshake and never carry a
		// packet, which looks like a broken tunnel rather than a missing line
		// of configuration.
		return fmt.Errorf("tunnel: peer %s has no allowed IPs", shortKey(p.PublicKey))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
	// update_only is deliberately not used: this has to create the peer the
	// first time and replace it afterwards.
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	if p.PresharedKey != (wgtypes.Key{}) {
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
	}
	if p.Endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
	}
	for _, a := range p.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
	}
	if p.KeepaliveSeconds > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.KeepaliveSeconds)
	}

	if err := d.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("tunnel: configuring peer %s: %w", shortKey(p.PublicKey), err)
	}

	d.mu.Lock()
	d.peers[p.PublicKey.String()] = p.Endpoint
	d.mu.Unlock()
	return nil
}

// SetPeerEndpoint moves an existing peer to a new endpoint.
//
// This is what a renegotiated path looks like from WireGuard's side: the keys
// and the allowed IPs are untouched, only the address changes, and the tunnel
// carries on without a new handshake. It is also why a peer whose network
// changed does not have to be torn down and rebuilt.
func (d *Device) SetPeerEndpoint(pub wgtypes.Key, ep netip.AddrPort) error {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub[:]))
	fmt.Fprintf(&b, "update_only=true\n")
	fmt.Fprintf(&b, "endpoint=%s\n", ep.String())

	if err := d.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("tunnel: moving peer %s: %w", shortKey(pub), err)
	}

	d.mu.Lock()
	d.peers[pub.String()] = ep
	d.mu.Unlock()
	return nil
}

// RemovePeer forgets a peer entirely.
func (d *Device) RemovePeer(pub wgtypes.Key) error {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub[:]))
	fmt.Fprintf(&b, "remove=true\n")

	if err := d.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("tunnel: removing peer %s: %w", shortKey(pub), err)
	}

	d.mu.Lock()
	delete(d.peers, pub.String())
	d.mu.Unlock()
	return nil
}

// PeerEndpoint reports the endpoint currently configured for a peer.
func (d *Device) PeerEndpoint(pub wgtypes.Key) (netip.AddrPort, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ep, ok := d.peers[pub.String()]
	return ep, ok
}

// ListenPort is the port WireGuard ended up on, which matters when Configure
// was given zero and the kernel chose.
func (d *Device) ListenPort() (int, error) {
	raw, err := d.dev.IpcGet()
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(raw, "\n") {
		if port, ok := strings.CutPrefix(line, "listen_port="); ok {
			var n int
			if _, err := fmt.Sscanf(port, "%d", &n); err != nil {
				return 0, err
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("tunnel: the device did not report a listen port")
}

// Up brings the device online.
func (d *Device) Up() error {
	if err := d.dev.Up(); err != nil {
		return fmt.Errorf("tunnel: bringing the device up: %w", err)
	}
	return nil
}

// Close shuts the device down. It is safe to call more than once.
func (d *Device) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()

	// Closes the tun as well, which is why the tun is not closed here too.
	d.dev.Close()
	return nil
}

// deviceLogger routes wireguard-go's own logging into ours at debug level.
// Its verbose level narrates every handshake, which is invaluable when a tunnel
// will not come up and noise at any other time.
func deviceLogger(log *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug("wireguard: " + fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			log.Warn("wireguard: " + fmt.Sprintf(format, args...))
		},
	}
}

func shortKey(k wgtypes.Key) string {
	s := k.String()
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// PeerStatus is what the device knows about a peer right now.
type PeerStatus struct {
	Endpoint      string
	LastHandshake int64 // unix seconds, zero if there has never been one
	RXBytes       uint64
	TXBytes       uint64
}

// Status reads the device's own view of its peers.
//
// LastHandshake is the field that matters when a tunnel will not carry traffic:
// zero means the two ends never agreed on keys, which separates "the path is
// not working" from "the path works and something above it does not".
func (d *Device) Status() (map[string]PeerStatus, error) {
	raw, err := d.dev.IpcGet()
	if err != nil {
		return nil, err
	}

	out := map[string]PeerStatus{}
	var cur string
	var st PeerStatus
	flush := func() {
		if cur != "" {
			out[cur] = st
		}
		st = PeerStatus{}
	}
	for line := range strings.SplitSeq(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 32 {
				cur = ""
				continue
			}
			cur = wgtypes.Key(b).String()
		case "endpoint":
			st.Endpoint = v
		case "last_handshake_time_sec":
			fmt.Sscanf(v, "%d", &st.LastHandshake)
		case "rx_bytes":
			fmt.Sscanf(v, "%d", &st.RXBytes)
		case "tx_bytes":
			fmt.Sscanf(v, "%d", &st.TXBytes)
		}
	}
	flush()
	return out, nil
}
