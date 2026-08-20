// Package p2p finds a direct path between two peers and keeps it.
//
// The problem it solves is that two machines behind NAT cannot address each
// other: neither knows an IP the other can reach, and neither can accept an
// unsolicited packet. ICE solves it by having both sides collect every address
// they might be reachable at — the local one, the one a STUN server sees them
// as, and a relayed one as a last resort — trade those addresses through a
// channel that already works (the signal server), and then probe every
// combination at once. The pair that answers first wins, and the probing itself
// is what punches the hole in both NATs.
//
// What this package does not do is carry traffic. It produces a net.Conn per
// peer and hands it over; what runs on top of it is WireGuard's problem.
package p2p

import (
	"net"
	"strings"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultSTUN is what a peer asks "what does the world see me as?".
//
// Two servers from two operators, because a single one that is down turns every
// peer into host-candidates-only — which works on a LAN and nowhere else, a
// failure that looks like a NAT problem and is not.
var DefaultSTUN = []string{
	"stun:stun.cloudflare.com:3478",
	"stun:stun.l.google.com:19302",
}

// Config is what an engine needs to negotiate.
type Config struct {
	// PrivateKey is this peer's WireGuard key. Its public half is this peer's
	// name everywhere in this package.
	PrivateKey wgtypes.Key

	// STUN and TURN are the servers used to discover reflexive addresses and,
	// for TURN, to relay when no direct path exists. Empty STUN falls back to
	// DefaultSTUN; empty TURN means a peer pair with no direct path simply
	// fails, which is honest and visible.
	STUN []string
	TURN []TURNServer

	// DisableHostCandidates removes the addresses this machine holds directly,
	// leaving only what a STUN server reports and what a relay offers.
	//
	// It exists to settle one question that nothing else can: whether a path was
	// found by punching through NAT, or by a route that already existed. Two
	// machines on networks that reach each other will pair host to host and
	// report success without exercising traversal at all, and from the outside
	// the two outcomes are the same line in a log. With host candidates gone,
	// a connection is proof.
	DisableHostCandidates bool

	// DisableSTUN negotiates with host candidates only.
	//
	// It is for a deployment where every peer already sits on a routable
	// network and asking a public server "what do I look like?" would be a
	// round trip to learn an address the peer already knows. Tests use it too,
	// which is how negotiation stays provable without touching the internet.
	DisableSTUN bool

	// DisableIPv6 turns off IPv6 candidate gathering.
	//
	// It exists as an escape hatch and defaults to off, because IPv6 is
	// frequently the only family that yields a direct path at all: two peers on
	// carrier-grade NAT share no reachable IPv4 address, while their IPv6
	// addresses are globally routable and need no hole punched. Turning it off
	// is throwing away the easy case.
	DisableIPv6 bool

	// IPFilter decides which addresses contribute candidates. Nil uses
	// DefaultIPFilter.
	IPFilter func(net.IP) bool

	// InterfaceFilter decides which interfaces contribute candidates. Nil uses
	// DefaultInterfaceFilter.
	//
	// This matters more than it looks. Every candidate has to be checked
	// against every candidate the peer offered, so the work is the product of
	// the two lists, and a machine with docker bridges, virtual adapters and
	// the tunnel's own device contributes a dozen addresses that can never
	// reach anybody. Worse than the cost is the tunnel interface itself: a
	// candidate gathered there invites the path to the peer to run through the
	// tunnel to the peer.
	InterfaceFilter func(name string) bool

	// IncludeLoopback gathers loopback candidates.
	//
	// Off in production, where 127.0.0.1 cannot reach another machine and only
	// adds checks that must fail. Tests turn it on so a negotiation happens
	// entirely on loopback, which is what makes them independent of the
	// machine's real interfaces and of whatever else is loading it.
	IncludeLoopback bool

	// LoggerFactory routes ICE's own logging somewhere. Nil keeps it silent.
	// Its debug level narrates candidate gathering and every connectivity
	// check, which is the only way to tell "no candidate was ever gathered"
	// apart from "candidates were gathered and none answered" — two failures
	// that look identical from outside and have nothing in common.
	LoggerFactory logging.LoggerFactory

	// FailedTimeout is how long a connection may stay unreachable before the
	// session is torn down and restarted. Zero takes the default below.
	FailedTimeout time.Duration

	// RelayWait is how long the relay is held back so a direct path can win the
	// race. Zero takes defaultRelayWait, which is where the reasoning lives.
	// Tests set it low so they do not spend eight seconds proving a fallback.
	RelayWait time.Duration

	// DisconnectedTimeout is how long a silent path is tolerated before it is
	// called disconnected. A path can go quiet for a moment without being dead —
	// a phone changing towers — so this is deliberately not the same as failed.
	DisconnectedTimeout time.Duration
}

// How long a path may be silent before it is given up on.
//
// pion's own defaults are five seconds to disconnected and twenty-five to
// failed, which are the numbers for a browser call: a person is watching, and
// half a minute of nothing is worse than starting over. A mesh is the opposite.
// Nobody is watching, the link is a home connection or a phone or a shop in
// another state, and half a minute of loss is a Tuesday. Giving up costs a full
// renegotiation — new credentials, new candidates, new checks — and the tunnel
// is down for all of it.
//
// So: a path is called disconnected quickly, because that costs nothing and
// makes the panel honest, and it is not failed for a minute. ICE keeps probing
// the whole time at its own two-second cadence, so a path that comes back is
// simply used again, with no renegotiation and nothing above it noticing.
const (
	defaultDisconnectedTimeout = 8 * time.Second
	defaultFailedTimeout       = 60 * time.Second
)

// defaultRelayWait is how long the relay is held back so a direct path can win.
//
// ICE picks the first pair that works, and the relay's pair always works: the
// allocation is already standing before the first check goes out, while a
// direct pair still has to punch a hole through two NATs that have never seen
// each other. Left alone, the race is not close.
//
// pion holds the relay back for two seconds for exactly this reason. Two
// seconds is enough on a quiet link and is not enough here: a mesh of eighteen
// machines negotiates its pairs in a burst, every agent punching to every other
// agent at once, and the hole punch that would have landed at 2.3 seconds
// arrives to find the question already settled.
//
// Settled permanently, which is the part that makes the number matter. Once a
// pair is selected pion never nominates another — a direct path that becomes
// available a moment later is not adopted, or reconsidered, ever. So this is
// not a wait before a decision that can be revised. It is the whole of the
// decision, and it was being made in two seconds.
//
// Eight, then. What it costs is the pairs that genuinely have no direct path:
// they now take eight seconds to fall back to the relay instead of two. They
// connect either way, and a peer that needs six more seconds once is a better
// trade than a peer that pays for every byte it ever sends.
const defaultRelayWait = 8 * time.Second

// TURNServer is a relay of last resort.
type TURNServer struct {
	URL      string
	Username string
	Password string
}

// State is where a session is in its life.
type State string

const (
	// StateIdle means nothing has been attempted yet.
	StateIdle State = "idle"
	// StateNegotiating covers gathering candidates and probing pairs: from the
	// outside they are one wait, and splitting them would report progress that
	// does not mean anything to a caller.
	StateNegotiating State = "negotiating"
	// StateConnected means there is a usable path.
	StateConnected State = "connected"
	// StateFailed means every candidate pair was tried and none answered.
	StateFailed State = "failed"
	// StateClosed means the session was torn down on purpose.
	StateClosed State = "closed"
)

// Signaller carries negotiation to a peer there is no path to yet.
//
// It is an interface rather than the signal client so that a test can drive two
// sessions against each other in memory, with no server and no sockets, and so
// that a different transport can be dropped in later without this package
// noticing.
type Signaller interface {
	SendOffer(to wgtypes.Key, ufrag, pwd string) error
	SendAnswer(to wgtypes.Key, ufrag, pwd string) error
	SendCandidate(to wgtypes.Key, candidate string) error
}

// virtualPrefixes are interface names that never lead to a peer.
//
// Docker bridges and their veth pairs, libvirt bridges, and the WireGuard
// devices themselves. The last group is the one that matters: netflow's own
// tunnel is an interface like any other by the time ICE looks at the machine,
// and a candidate gathered on it describes a path to the peer that runs through
// the tunnel to the peer.
var virtualPrefixes = []string{
	"docker", "br-", "veth", "virbr", "vmnet", "vboxnet",
	"wg", "netflow", "utun", "tun", "tap",
	// macOS. awdl and llw are Apple Wireless Direct Link and Low Latency WLAN,
	// the interfaces behind AirDrop and Sidecar. They carry only link-local
	// addresses, they reach nothing routable, and every candidate gathered from
	// them fails with "no route to host" — after being checked against every
	// candidate the peer offered. On a Mac they are the single largest source
	// of wasted negotiation.
	"awdl", "llw", "anpi", "ap1", "bridge",
}

// DefaultInterfaceFilter drops interfaces that cannot lead anywhere useful.
//
// It errs toward keeping: an unknown interface is gathered from, because a
// wrongly dropped one is a peer that never connects and a wrongly kept one is
// only a few wasted checks.
func DefaultInterfaceFilter(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(lower, p) {
			return false
		}
	}
	return true
}

// DefaultIPFilter drops addresses that cannot reach a peer on another network.
//
// Link-local is the whole of it. An fe80:: or 169.254 address is meaningful
// only on the wire it was configured on, so a candidate built from one can
// never answer a peer anywhere else — and the packets sent to find that out
// fail with "no route to host", one per pair, before the useful candidates get
// their turn.
func DefaultIPFilter(ip net.IP) bool {
	return !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

// candidateTypes is what the agent is allowed to gather.
//
// Relay is always included so a configured TURN server is actually used; with
// none configured it costs nothing, because there is no relay to gather from.
func candidateTypes(c Config) []ice.CandidateType {
	types := []ice.CandidateType{
		ice.CandidateTypeServerReflexive,
		ice.CandidateTypeRelay,
	}
	if !c.DisableHostCandidates {
		types = append([]ice.CandidateType{ice.CandidateTypeHost}, types...)
	}
	return types
}

// controls decides which side sends the offer.
//
// Both peers usually learn about each other at the same moment, and if both
// offered there would be two independent negotiations converging on different
// pairs. Comparing the two public keys is a tie-break both sides compute
// identically without exchanging anything: the greater key controls. Any total
// order would do — what matters is that it is the same order on both machines.
func controls(local, remote wgtypes.Key) bool {
	return local.String() > remote.String()
}

// agentConfig turns a Config into what pion wants.
func agentConfig(c Config) (*ice.AgentConfig, error) {
	urls := make([]*stun.URI, 0, len(c.STUN)+len(c.TURN))

	if !c.DisableSTUN {
		stunList := c.STUN
		if len(stunList) == 0 {
			stunList = DefaultSTUN
		}
		for _, raw := range stunList {
			u, err := stun.ParseURI(raw)
			if err != nil {
				return nil, err
			}
			urls = append(urls, u)
		}
	}
	for _, t := range c.TURN {
		u, err := stun.ParseURI(t.URL)
		if err != nil {
			return nil, err
		}
		u.Username = t.Username
		u.Password = t.Password
		urls = append(urls, u)
	}

	networks := []ice.NetworkType{ice.NetworkTypeUDP4}
	if !c.DisableIPv6 {
		networks = append(networks, ice.NetworkTypeUDP6)
	}

	filter := c.InterfaceFilter
	if filter == nil {
		filter = DefaultInterfaceFilter
	}
	ipFilter := c.IPFilter
	if ipFilter == nil {
		ipFilter = DefaultIPFilter
	}

	cfg := &ice.AgentConfig{
		Urls:            urls,
		NetworkTypes:    networks,
		InterfaceFilter: filter,
		IPFilter:        ipFilter,
		IncludeLoopback: c.IncludeLoopback,
		LoggerFactory:   c.LoggerFactory,
		// mDNS off. Left unset, pion resolves remote candidates through
		// multicast DNS and opens a multicast socket for every agent to do it.
		//
		// The feature exists so a web page cannot learn the local IP addresses
		// of whoever visits it. Nothing here is a web page: candidates travel
		// sealed between two machines that already know each other's keys, so
		// there is no address being hidden from anyone. What it does buy is a
		// dependency on multicast working, on every network the agent ever runs
		// on, before any peer can connect.
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
		// Relay is included so a TURN server, when one is configured, is
		// actually used. With no TURN configured it costs nothing: there is no
		// relay to gather from.
		CandidateTypes: candidateTypes(c),
	}
	failed := c.FailedTimeout
	if failed <= 0 {
		failed = defaultFailedTimeout
	}
	cfg.FailedTimeout = &failed

	disconnected := c.DisconnectedTimeout
	if disconnected <= 0 {
		disconnected = defaultDisconnectedTimeout
	}
	cfg.DisconnectedTimeout = &disconnected

	// Only when there is somewhere to fall back to. With no TURN configured
	// there is no relay candidate to hold back, and holding one back would mean
	// every pair that fails waits eight seconds to learn it has failed.
	if len(c.TURN) > 0 {
		relayWait := c.RelayWait
		if relayWait <= 0 {
			relayWait = defaultRelayWait
		}
		cfg.RelayAcceptanceMinWait = &relayWait
	}

	return cfg, nil
}
