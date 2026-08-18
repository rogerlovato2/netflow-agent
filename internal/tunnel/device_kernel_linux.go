//go:build linux

package tunnel

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NewKernelDevice uses the WireGuard in the kernel.
//
// Preferred over the one in this process wherever it exists, and not only for
// the throughput. A userspace device needs /dev/net/tun, and an unprivileged
// LXC container is not given that node — while `ip link add type wireguard`
// works there, because it goes through netlink and the module belongs to the
// host. Containers are a large share of where a Linux agent runs, so choosing
// userspace first meant failing in the common case for a reason nobody could
// act on from inside.
func NewKernelDevice(name string, addrs []netip.Addr, mtu int, log *slog.Logger) (*Device, error) {
	if name == "" {
		name = DefaultTUNName
	}

	// Removed first: a link left behind by a killed agent keeps the name, and
	// the next start is usually the restart meant to fix things.
	_ = run("ip", "link", "del", "dev", name)

	if err := run("ip", "link", "add", "dev", name, "type", "wireguard"); err != nil {
		return nil, fmt.Errorf("tunnel: the kernel would not create a wireguard interface "+
			"(is the wireguard module loaded?): %w", err)
	}
	if err := configureInterface(name, addrs, mtu); err != nil {
		_ = run("ip", "link", "del", "dev", name)
		return nil, err
	}

	client, err := wgctrl.New()
	if err != nil {
		_ = run("ip", "link", "del", "dev", name)
		return nil, fmt.Errorf("tunnel: opening the wireguard control socket: %w", err)
	}

	log.Info("tunnel: interface up", "name", name, "addrs", addrs, "mtu", mtu, "kernel", true)
	return &Device{
		ctrl:  &kernelControl{client: client, iface: name},
		name:  name,
		log:   log,
		peers: map[string]netip.AddrPort{},
		addrs: addrs,
	}, nil
}

// kernelControl translates the uapi format into wgctrl calls.
//
// The translation exists so that everything above this speaks one shape. uapi
// is what wireguard-go accepts natively and what wg(8) itself uses over its
// socket, so it is the format both ends already agree on rather than a third
// one invented here.
type kernelControl struct {
	client *wgctrl.Client
	iface  string
}

func (c *kernelControl) close() {
	_ = c.client.Close()
	// The link goes with the process. Left behind it holds an address and a
	// name that the next start has to clear, and it would keep routes pointing
	// at an interface nothing is carrying.
	_ = run("ip", "link", "del", "dev", c.iface)
}

func (c *kernelControl) apply(uapi string) error {
	cfg, err := parseUAPI(uapi)
	if err != nil {
		return err
	}
	return c.client.ConfigureDevice(c.iface, cfg)
}

// parseUAPI reads the subset this project writes.
//
// Deliberately not a general parser: it handles exactly the keys device.go
// emits, and refuses anything else rather than ignoring it. A key silently
// dropped here would be a peer configured differently from what the caller
// asked for, which is the kind of difference that surfaces as a tunnel that
// works for everything except one subnet.
func parseUAPI(uapi string) (wgtypes.Config, error) {
	var cfg wgtypes.Config
	var peer *wgtypes.PeerConfig

	flush := func() {
		if peer != nil {
			cfg.Peers = append(cfg.Peers, *peer)
			peer = nil
		}
	}

	for line := range strings.SplitSeq(strings.TrimSpace(uapi), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("tunnel: uapi line without a value: %q", line)
		}

		switch key {
		case "private_key":
			k, err := keyFromHex(value)
			if err != nil {
				return cfg, err
			}
			cfg.PrivateKey = &k
		case "listen_port":
			n, err := strconv.Atoi(value)
			if err != nil {
				return cfg, fmt.Errorf("tunnel: listen_port %q: %w", value, err)
			}
			cfg.ListenPort = &n
		case "public_key":
			flush()
			k, err := keyFromHex(value)
			if err != nil {
				return cfg, err
			}
			peer = &wgtypes.PeerConfig{PublicKey: k}
		case "preshared_key":
			if peer == nil {
				return cfg, fmt.Errorf("tunnel: preshared_key outside a peer")
			}
			k, err := keyFromHex(value)
			if err != nil {
				return cfg, err
			}
			peer.PresharedKey = &k
		case "endpoint":
			if peer == nil {
				return cfg, fmt.Errorf("tunnel: endpoint outside a peer")
			}
			addr, err := net.ResolveUDPAddr("udp", value)
			if err != nil {
				return cfg, fmt.Errorf("tunnel: endpoint %q: %w", value, err)
			}
			peer.Endpoint = addr
		case "allowed_ip":
			if peer == nil {
				return cfg, fmt.Errorf("tunnel: allowed_ip outside a peer")
			}
			_, n, err := net.ParseCIDR(value)
			if err != nil {
				return cfg, fmt.Errorf("tunnel: allowed_ip %q: %w", value, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, *n)
		case "persistent_keepalive_interval":
			if peer == nil {
				return cfg, fmt.Errorf("tunnel: keepalive outside a peer")
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				return cfg, fmt.Errorf("tunnel: keepalive %q: %w", value, err)
			}
			d := time.Duration(n) * time.Second
			peer.PersistentKeepaliveInterval = &d
		case "replace_allowed_ips":
			if peer == nil {
				return cfg, fmt.Errorf("tunnel: replace_allowed_ips outside a peer")
			}
			peer.ReplaceAllowedIPs = value == "true"
		case "update_only":
			if peer == nil {
				return cfg, fmt.Errorf("tunnel: update_only outside a peer")
			}
			peer.UpdateOnly = value == "true"
		case "remove":
			if peer == nil {
				return cfg, fmt.Errorf("tunnel: remove outside a peer")
			}
			peer.Remove = value == "true"
		default:
			return cfg, fmt.Errorf("tunnel: unhandled uapi key %q", key)
		}
	}
	flush()
	return cfg, nil
}

// dump writes the device back out in the same format, so Status and ListenPort
// read one shape whichever implementation is underneath.
func (c *kernelControl) dump() (string, error) {
	dev, err := c.client.Device(c.iface)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "listen_port=%d\n", dev.ListenPort)
	for _, p := range dev.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
		}
		fmt.Fprintf(&b, "last_handshake_time_sec=%d\n", handshakeSeconds(p.LastHandshakeTime))
		fmt.Fprintf(&b, "rx_bytes=%d\n", p.ReceiveBytes)
		fmt.Fprintf(&b, "tx_bytes=%d\n", p.TransmitBytes)
	}
	return b.String(), nil
}

// handshakeSeconds is zero when there has never been one, which is what the
// rest of the code reads as "the tunnel never came up".
func handshakeSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func keyFromHex(s string) (wgtypes.Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("tunnel: key %q: %w", s, err)
	}
	return wgtypes.NewKey(b)
}
