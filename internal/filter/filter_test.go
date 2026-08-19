package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// ipv4 builds a packet with just enough header to be read.
func ipv4(t *testing.T, src, dst string, proto uint8, srcPort, dstPort uint16) []byte {
	t.Helper()
	b := make([]byte, 20+8)
	b[0] = 0x45
	b[9] = proto
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	return b
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

const (
	me   = "10.90.0.2"
	them = "10.90.0.3"
)

// Until the server has said anything, nothing is filtered. An agent that has
// not been told the rules must not quietly become a firewall that blocks
// everything.
func TestNothingIsFilteredBeforeTheRulesArrive(t *testing.T) {
	f := New()
	if !f.Inbound(ipv4(t, them, me, protoTCP, 5000, 22)) {
		t.Error("a packet was dropped before any rule existed")
	}
	if f.Enabled() {
		t.Error("the filter claims to be configured")
	}
}

// The plain case: a peer may start what its rules allow and nothing else.
func TestAPeerMayStartOnlyWhatTheRulesAllow(t *testing.T) {
	f := New()
	f.SetRules(map[netip.Addr][]Rule{
		addr(them): {{Protocol: TCP, Ports: []PortRange{{22, 22}, {8000, 8100}}}},
	})

	allowed := []struct {
		port uint16
		want bool
	}{
		{22, true},
		{8000, true},
		{8050, true},
		{8100, true},
		{23, false},
		{7999, false},
		{8101, false},
	}
	for _, c := range allowed {
		if got := f.Inbound(ipv4(t, them, me, protoTCP, 5000, c.port)); got != c.want {
			t.Errorf("tcp/%d = %v, want %v", c.port, got, c.want)
		}
	}
	// The same ports on another protocol are not the same rule.
	if f.Inbound(ipv4(t, them, me, protoUDP, 5000, 22)) {
		t.Error("udp/22 was allowed by a tcp rule")
	}
	// And a machine with no rules at all may start nothing.
	if f.Inbound(ipv4(t, "10.90.0.9", me, protoTCP, 5000, 22)) {
		t.Error("a peer with no rules was allowed to start something")
	}
}

// The half that makes one-way rules mean anything: the side that may not start
// still gets its answers back.
func TestRepliesComeBackToWhoeverStarted(t *testing.T) {
	f := New()
	// The peer may start nothing at all.
	f.SetRules(map[netip.Addr][]Rule{addr(them): {}})

	if f.Inbound(ipv4(t, them, me, protoTCP, 443, 51000)) {
		t.Fatal("the peer started a conversation it is not allowed to start")
	}

	// This machine starts one.
	f.Outbound(ipv4(t, me, them, protoTCP, 51000, 443))
	if !f.Inbound(ipv4(t, them, me, protoTCP, 443, 51000)) {
		t.Error("the answer to a conversation this machine started was dropped")
	}
	// Only that conversation, though.
	if f.Inbound(ipv4(t, them, me, protoTCP, 443, 51001)) {
		t.Error("a different port rode in on the same conversation")
	}
	if f.Inbound(ipv4(t, them, me, protoUDP, 443, 51000)) {
		t.Error("a different protocol rode in on the same conversation")
	}
}

// A ping is a conversation too, and it has no ports to remember it by.
func TestPingGetsItsReply(t *testing.T) {
	f := New()
	f.SetRules(map[netip.Addr][]Rule{addr(them): {}})

	if f.Inbound(ipv4(t, them, me, protoICMP, 0, 0)) {
		t.Fatal("the peer pinged a machine that does not allow it")
	}
	f.Outbound(ipv4(t, me, them, protoICMP, 0, 0))
	if !f.Inbound(ipv4(t, them, me, protoICMP, 0, 0)) {
		t.Error("the reply to a ping this machine sent was dropped")
	}
}

// A conversation is forgotten when nothing has been said on it for a while,
// and the reply that arrives after that is a stranger.
func TestAnOldConversationIsForgotten(t *testing.T) {
	f := New()
	f.SetRules(map[netip.Addr][]Rule{addr(them): {}})

	now := time.Now()
	f.now = func() time.Time { return now }
	f.Outbound(ipv4(t, me, them, protoUDP, 51000, 53))

	now = now.Add(otherIdle / 2)
	if !f.Inbound(ipv4(t, them, me, protoUDP, 53, 51000)) {
		t.Error("a reply within the window was dropped")
	}

	now = now.Add(otherIdle * 2)
	if f.Inbound(ipv4(t, them, me, protoUDP, 53, 51000)) {
		t.Error("a reply long after the question was let through")
	}
}

// Rules with no ports, and the protocol that has none.
func TestProtocolsWithoutPorts(t *testing.T) {
	f := New()
	f.SetRules(map[netip.Addr][]Rule{
		addr(them): {{Protocol: ICMP}, {Protocol: UDP}},
	})
	if !f.Inbound(ipv4(t, them, me, protoICMP, 0, 0)) {
		t.Error("icmp was dropped by an icmp rule")
	}
	if !f.Inbound(ipv4(t, them, me, protoUDP, 5000, 12345)) {
		t.Error("udp on any port was dropped by a portless udp rule")
	}
	if f.Inbound(ipv4(t, them, me, protoTCP, 5000, 22)) {
		t.Error("tcp was allowed by rules that do not mention it")
	}

	// And "all" is all of it.
	f.SetRules(map[netip.Addr][]Rule{addr(them): {{Protocol: All}}})
	for _, proto := range []uint8{protoTCP, protoUDP, protoICMP} {
		if !f.Inbound(ipv4(t, them, me, proto, 1, 1)) {
			t.Errorf("protocol %d was dropped by an 'all' rule", proto)
		}
	}
}

// What cannot be read is let through: this is an access rule, not a packet
// inspector, and dropping what it does not understand would break traffic
// nobody asked it to block.
func TestUnreadablePacketsAreNotDropped(t *testing.T) {
	f := New()
	f.SetRules(map[netip.Addr][]Rule{addr(them): {}})

	// A later fragment, which has no ports in it to read.
	frag := ipv4(t, them, me, protoTCP, 5000, 22)
	binary.BigEndian.PutUint16(frag[6:8], 0x0001)
	if !f.Inbound(frag) {
		t.Error("a fragment was dropped")
	}
	// Something that is not IP at all.
	if !f.Inbound(make([]byte, 24)) {
		t.Error("an unreadable packet was dropped")
	}
	// A protocol with no notion of ports.
	other := ipv4(t, them, me, 47, 0, 0) // GRE
	if !f.Inbound(other) {
		t.Error("a protocol this does not parse was dropped")
	}
}

// The table does not grow without bound.
func TestOldFlowsAreSweptAway(t *testing.T) {
	f := New()
	now := time.Now()
	f.now = func() time.Time { return now }
	for i := range 100 {
		f.Outbound(ipv4(t, me, them, protoUDP, uint16(40000+i), 53))
	}
	now = now.Add(tcpIdle * 2)
	f.Prune()

	count := 0
	f.flows.Range(func(any, any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("%d conversations survived the sweep", count)
	}
}
