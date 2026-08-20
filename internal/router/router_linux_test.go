//go:build linux

package router

import (
	"net/netip"
	"strings"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// The ruleset, read as a whole. What matters is not the exact text but the
// three claims it makes: only traffic off the mesh interface is forwarded, only
// towards the networks this machine was given, and rewriting happens only for
// the ones that asked for it.
func TestTheRulesetForwardsOnlyWhatItWasGiven(t *testing.T) {
	got := buildRouterRuleset("netflow0", sorted([]Route{
		{Network: p("192.168.1.0/24"), Masquerade: true},
		{Network: p("10.20.0.0/16"), Masquerade: false},
	}))

	for _, want := range []string{
		`iifname "netflow0" ip daddr { 10.20.0.0/16, 192.168.1.0/24 } accept`,
		"ct state established,related accept",
		"type nat hook postrouting priority srcnat",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the ruleset is missing %q:\n%s", want, got)
		}
	}

	// The network that said no to masquerading is not in the nat rule, and the
	// one that said yes is. Getting this backwards silently rewrites traffic
	// somebody deliberately asked to leave alone.
	nat := got[strings.Index(got, "postrouting"):]
	if !strings.Contains(nat, "192.168.1.0/24") {
		t.Error("a network that asked to be masqueraded is not in the nat rule")
	}
	if strings.Contains(nat, "10.20.0.0/16") {
		t.Error("a network that asked not to be masqueraded is in the nat rule")
	}
}

// No network asking to be rewritten means no nat chain at all, rather than an
// empty one: an empty set is a syntax error in nft, and a chain that exists to
// hold nothing is a thing to explain later.
func TestNoMasqueradeMeansNoNatChain(t *testing.T) {
	got := buildRouterRuleset("netflow0", []Route{{Network: p("10.0.0.0/8")}})
	if strings.Contains(got, "postrouting") {
		t.Errorf("a nat chain was written for nothing:\n%s", got)
	}
}

// The same routes in a different order produce the same ruleset, so a diff of
// the firewall means the routes changed and not that a map arrived.
func TestTheRulesetIsStable(t *testing.T) {
	a := buildRouterRuleset("netflow0", sorted([]Route{
		{Network: p("192.168.1.0/24"), Masquerade: true},
		{Network: p("10.20.0.0/16"), Masquerade: true},
	}))
	b := buildRouterRuleset("netflow0", sorted([]Route{
		{Network: p("10.20.0.0/16"), Masquerade: true},
		{Network: p("192.168.1.0/24"), Masquerade: true},
	}))
	if a != b {
		t.Errorf("the order of the routes changed the ruleset:\n%s\n---\n%s", a, b)
	}
}
