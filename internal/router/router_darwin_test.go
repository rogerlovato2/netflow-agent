//go:build darwin

package router

import (
	"net/netip"
	"strings"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// The anchor, read as a whole. The nat rule has to name the interface the
// traffic actually leaves by, and has to match only what arrived over the mesh.
func TestTheAnchorRewritesOnlyMeshTraffic(t *testing.T) {
	got := buildAnchor("netflow0", p("100.90.0.0/22"), sorted([]Route{
		{Network: p("192.168.1.0/24"), Masquerade: true},
		{Network: p("10.20.0.0/16"), Masquerade: false},
	}), func(netip.Prefix) string { return "en5" })

	want := "nat on en5 from 100.90.0.0/22 to 192.168.1.0/24 -> (en5)"
	if !strings.Contains(got, want) {
		t.Errorf("the anchor is missing %q:\n%s", want, got)
	}
	// The network that asked not to be rewritten is passed and not natted.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "nat") && strings.Contains(line, "10.20.0.0/16") {
			t.Errorf("a network that asked not to be masqueraded was natted: %q", line)
		}
	}
	if !strings.Contains(got, "pass in on netflow0 from 100.90.0.0/22 to 10.20.0.0/16") {
		t.Errorf("the network is not passed:\n%s", got)
	}
}

// An interface the routing table cannot name produces no rule at all.
//
// A nat rule on the wrong interface does nothing and looks exactly like the
// feature being broken, so writing none is the honest failure: the traffic is
// still forwarded, it simply arrives with its mesh address, which somebody can
// see and diagnose.
func TestNoInterfaceMeansNoNatRule(t *testing.T) {
	got := buildAnchor("netflow0", p("100.90.0.0/22"),
		[]Route{{Network: p("192.168.1.0/24"), Masquerade: true}},
		func(netip.Prefix) string { return "" })
	if strings.Contains(got, "nat on") {
		t.Errorf("a nat rule was written for an unknown interface:\n%s", got)
	}
	if !strings.Contains(got, "pass in on netflow0") {
		t.Errorf("the pass rules went missing too:\n%s", got)
	}
}
