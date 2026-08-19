// Package filter decides which packets arriving from the mesh are let through.
//
// A policy that says "the laptops may reach the servers, and not the other way
// round" cannot be enforced by choosing who knows whom: a WireGuard tunnel is
// not one-way, and a machine that is not told about a peer cannot receive from
// it at all. Direction only means something if somebody looks at the packets,
// and the somebody is whoever is receiving them.
//
// So this is the receiving side of every rule. A peer may start what its rules
// allow; anything else from it is dropped, except replies to conversations this
// machine started — which is what makes "only one side may start" a sentence
// with a meaning rather than a broken tunnel.
package filter

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Protocol is what a rule is about.
type Protocol string

const (
	All  Protocol = "all"
	TCP  Protocol = "tcp"
	UDP  Protocol = "udp"
	ICMP Protocol = "icmp"
)

// PortRange is one port or a span of them.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

func (p PortRange) contains(port int) bool { return port >= p.From && port <= p.To }

// Rule is one thing a peer may start.
type Rule struct {
	Protocol Protocol    `json:"protocol"`
	Ports    []PortRange `json:"ports,omitempty"`
}

// allows says whether this rule covers a packet.
func (r Rule) allows(proto uint8, port int) bool {
	switch r.Protocol {
	case All:
		return true
	case ICMP:
		return proto == protoICMP || proto == protoICMPv6
	case TCP:
		if proto != protoTCP {
			return false
		}
	case UDP:
		if proto != protoUDP {
			return false
		}
	default:
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p.contains(port) {
			return true
		}
	}
	return false
}

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	// How long a conversation is remembered after its last packet.
	//
	// These are the numbers every stateful firewall argues about. Short enough
	// that a table does not grow without bound, long enough that a reply to a
	// request nobody hurried does not arrive to a closed door. TCP gets longer
	// because a connection can sit idle and still be alive.
	tcpIdle   = 5 * time.Minute
	otherIdle = 60 * time.Second
)

// Filter holds the rules and remembers what this machine started.
//
// Safe for concurrent use: packets arrive on the tunnel's goroutines and rules
// change on the one that follows the network map.
type Filter struct {
	mu sync.RWMutex
	// on is whether any rule has been set. Until the server says something, a
	// machine filters nothing — an agent that has not yet been told the rules
	// must not silently become a firewall that blocks everything.
	on    bool
	rules map[netip.Addr][]Rule

	flows sync.Map // flow -> *int64 (unix nanos of the last packet)
	now   func() time.Time
}

// New makes a filter that lets everything through until it is told otherwise.
func New() *Filter {
	return &Filter{rules: map[netip.Addr][]Rule{}, now: time.Now}
}

// SetRules replaces what every peer is allowed to start.
//
// A peer with an empty list may start nothing. A peer that is not in the map at
// all is not in this mesh as far as this machine is concerned, and WireGuard has
// already dropped its packets long before they reach here.
func (f *Filter) SetRules(rules map[netip.Addr][]Rule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = rules
	f.on = true
}

// Enabled reports whether rules have ever been set.
func (f *Filter) Enabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.on
}

// flow is one conversation, from the point of view of this machine.
type flow struct {
	proto      uint8
	local      netip.Addr
	remote     netip.Addr
	localPort  uint16
	remotePort uint16
}

// Outbound records a packet this machine is sending into the tunnel.
//
// Everything this machine starts is allowed — the rules are about what others
// may start — and remembering it is what lets the answer back in.
func (f *Filter) Outbound(packet []byte) {
	p, ok := parse(packet)
	if !ok {
		return
	}
	key := flow{
		proto: p.proto, local: p.src, remote: p.dst,
		localPort: p.srcPort, remotePort: p.dstPort,
	}
	now := f.now().UnixNano()
	if v, loaded := f.flows.Load(key); loaded {
		*(v.(*int64)) = now
		return
	}
	stamp := now
	f.flows.Store(key, &stamp)
}

// Inbound says whether a packet that arrived from the mesh may be delivered.
func (f *Filter) Inbound(packet []byte) bool {
	f.mu.RLock()
	on, rules := f.on, f.rules
	f.mu.RUnlock()
	if !on {
		return true
	}

	p, ok := parse(packet)
	if !ok {
		// Something this code does not understand — a fragment, a protocol with
		// no ports, a malformed header. It is let through: the rules are about
		// what a peer may start, WireGuard has already proved who sent it, and
		// dropping what we cannot read would break traffic nobody asked us to
		// block.
		return true
	}

	// A reply to something this machine started. Checked first because it is
	// both the common case and the one that makes one-way rules work.
	key := flow{
		proto: p.proto, local: p.dst, remote: p.src,
		localPort: p.dstPort, remotePort: p.srcPort,
	}
	if v, ok := f.flows.Load(key); ok {
		if f.now().UnixNano()-*(v.(*int64)) < int64(idleFor(p.proto)) {
			*(v.(*int64)) = f.now().UnixNano()
			return true
		}
		f.flows.Delete(key)
	}

	for _, r := range rules[p.src] {
		if r.allows(p.proto, int(p.dstPort)) {
			return true
		}
	}
	return false
}

func idleFor(proto uint8) time.Duration {
	if proto == protoTCP {
		return tcpIdle
	}
	return otherIdle
}

// Prune forgets conversations nothing has said anything on.
func (f *Filter) Prune() {
	cutoff := f.now().UnixNano()
	f.flows.Range(func(k, v any) bool {
		if cutoff-*(v.(*int64)) > int64(tcpIdle) {
			f.flows.Delete(k)
		}
		return true
	})
}

// PruneLoop keeps the table from growing without bound.
func (f *Filter) PruneLoop(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			f.Prune()
		}
	}
}

// parsed is the little of a packet this needs.
type parsed struct {
	proto            uint8
	src, dst         netip.Addr
	srcPort, dstPort uint16
}

// parse reads the addresses, the protocol and the ports.
//
// Deliberately shallow. It handles IPv4 and IPv6 with no extension headers,
// TCP, UDP and ICMP, and gives up on anything else — and giving up means "let
// it through", because this is an access rule and not a packet inspector.
func parse(b []byte) (parsed, bool) {
	if len(b) < 20 {
		return parsed{}, false
	}
	var p parsed
	var payload []byte

	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return parsed{}, false
		}
		// A fragment other than the first has no ports to read, and guessing at
		// them is how a filter passes what it meant to block.
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return parsed{}, false
		}
		p.proto = b[9]
		p.src, _ = netip.AddrFromSlice(b[12:16])
		p.dst, _ = netip.AddrFromSlice(b[16:20])
		payload = b[ihl:]
	case 6:
		if len(b) < 40 {
			return parsed{}, false
		}
		// Next header only: an extension header chain would have to be walked,
		// and this returns false rather than reading the wrong bytes as ports.
		p.proto = b[6]
		p.src, _ = netip.AddrFromSlice(b[8:24])
		p.dst, _ = netip.AddrFromSlice(b[24:40])
		payload = b[40:]
	default:
		return parsed{}, false
	}

	if !p.src.IsValid() || !p.dst.IsValid() {
		return parsed{}, false
	}
	switch p.proto {
	case protoTCP, protoUDP:
		if len(payload) < 4 {
			return parsed{}, false
		}
		p.srcPort = binary.BigEndian.Uint16(payload[0:2])
		p.dstPort = binary.BigEndian.Uint16(payload[2:4])
	case protoICMP, protoICMPv6:
		// No ports. The flow is the pair of addresses, which is enough to let a
		// ping reply back to the machine that pinged.
	default:
		return parsed{}, false
	}
	return p, true
}
