// Package tunnel runs WireGuard over the paths that package p2p negotiates.
//
// WireGuard has no idea any of this is happening. It is told the peer lives at
// a port on loopback, it sends its encrypted packets there, and a proxy carries
// them over the ICE connection. Nothing about the tunnel — the keys, the
// handshake, the encryption — changes because the transport underneath it did.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
)

// maxPacket bounds one read.
//
// A WireGuard packet is the tunnel MTU plus 32 bytes of its own header, so at
// the usual 1420 it never exceeds about 1452. 2048 leaves room for a larger MTU
// without a second thought, and a datagram longer than the buffer would be
// truncated rather than split — a corruption that surfaces much later, as a
// tunnel that works until somebody sends a big packet.
const maxPacket = 2048

// Proxy carries WireGuard's packets over one negotiated path.
//
//	WireGuard(:wgPort) <--UDP--> Proxy(127.0.0.1:n) <--ICE--> the peer
//
// The socket is bound and not connected, which matters more than it looks.
//
// A connected socket makes the kernel drop every datagram whose source is not
// the exact address it was connected to, and wireguard-go does not have one
// exact address: its bind keeps separate IPv4 and IPv6 sockets and may answer
// from either, so a reply can arrive from ::ffff:127.0.0.1 rather than from
// 127.0.0.1. Connected, those replies are discarded by the kernel before
// anything here sees them — and the symptom is a tunnel where handshake
// initiations cross fine, responses vanish, and the counters show bytes moving
// while no handshake ever completes.
type Proxy struct {
	path net.Conn // the ICE connection
	sock *net.UDPConn
	// wgAddr is where packets from the path are delivered.
	wgAddr *net.UDPAddr
	log    *slog.Logger

	closeOnce sync.Once
	closed    chan struct{}
}

// NewProxy connects a path to the local WireGuard instance.
func NewProxy(path net.Conn, wgPort int, log *slog.Logger) (*Proxy, error) {
	if path == nil {
		return nil, errors.New("tunnel: no path to proxy")
	}
	if wgPort <= 0 || wgPort > 65535 {
		return nil, fmt.Errorf("tunnel: %d is not a usable WireGuard port", wgPort)
	}

	// Loopback: this hop never leaves the machine, and binding it anywhere else
	// would expose a socket that forwards straight into the tunnel to whoever
	// found it.
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("tunnel: opening the local socket: %w", err)
	}

	return &Proxy{
		path:   path,
		sock:   sock,
		wgAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgPort},
		log:    log,
		closed: make(chan struct{}),
	}, nil
}

// Endpoint is what WireGuard has to be told the peer's address is.
func (p *Proxy) Endpoint() netip.AddrPort {
	return p.sock.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Run pumps in both directions until ctx ends, the path dies, or Close is
// called. It returns the reason.
func (p *Proxy) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unblocks the two reads below, which have no other way out: a blocked
	// ReadFrom does not notice a cancelled context.
	go func() {
		select {
		case <-ctx.Done():
		case <-p.closed:
		}
		_ = p.sock.SetDeadline(deadlineNow())
		_ = p.path.SetDeadline(deadlineNow())
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- p.wgToPath() }()
	go func() { errCh <- p.pathToWG() }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// wgToPath carries what the local WireGuard sends out over the path.
//
// Datagram boundaries are the whole point of reading one at a time: a WireGuard
// packet is meaningless if it arrives merged with the next one or split across
// two, which is exactly what io.Copy would eventually do.
//
// The source of each datagram is deliberately not checked beyond being on
// loopback. It is whichever of wireguard-go's sockets happened to send, and
// pinning it to one address is the bug this shape exists to avoid.
func (p *Proxy) wgToPath() error {
	buf := make([]byte, maxPacket)
	for {
		n, from, err := p.sock.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("tunnel: wg->path read: %w", err)
		}
		if n == 0 {
			continue
		}
		if from != nil && !from.IP.IsLoopback() {
			// Nothing off this machine has any business here.
			p.log.Debug("tunnel: ignored a packet from outside", "from", from)
			continue
		}
		if _, err := p.path.Write(buf[:n]); err != nil {
			// One failed write is not a dead path. WireGuard retries its
			// handshake and the data above it has its own recovery, so a
			// dropped datagram costs a retransmit; tearing the session down
			// would cost a full renegotiation.
			p.log.Debug("tunnel: dropped a packet", "dir", "wg->path", "err", err)
		}
	}
}

// pathToWG delivers what arrived from the peer to the local WireGuard.
func (p *Proxy) pathToWG() error {
	buf := make([]byte, maxPacket)
	for {
		n, err := p.path.Read(buf)
		if err != nil {
			return fmt.Errorf("tunnel: path->wg read: %w", err)
		}
		if n == 0 {
			continue
		}
		if _, err := p.sock.WriteToUDP(buf[:n], p.wgAddr); err != nil {
			p.log.Debug("tunnel: dropped a packet", "dir", "path->wg", "err", err)
		}
	}
}

// Close stops the proxy. It is safe to call more than once, and does not close
// the path: whoever negotiated it owns it.
func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		_ = p.sock.Close()
	})
	return nil
}
