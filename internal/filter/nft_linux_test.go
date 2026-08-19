//go:build linux

package filter

import (
	"net/netip"
	"strings"
	"testing"
)

// The ruleset is the whole design, so it is worth reading in a test: replies
// pass, each peer that may start something says what, everything else on the
// mesh interface is dropped, and nothing outside the interface is touched.
func TestTheRulesetSaysWhatItShould(t *testing.T) {
	// Built through the same path the agent uses, minus running nft.
	rules := map[netip.Addr][]Rule{
		netip.MustParseAddr("10.90.0.3"): {{Protocol: TCP, Ports: []PortRange{{22, 22}, {8000, 8100}}}},
		netip.MustParseAddr("10.90.0.4"): {{Protocol: All}},
		netip.MustParseAddr("10.90.0.5"): {},
	}
	set := buildRuleset("netflow0", rules)

	for _, want := range []string{
		`iifname != "netflow0" accept`,
		"ct state established,related accept",
		"ip saddr 10.90.0.3 tcp dport { 22, 8000-8100 } accept",
		"ip saddr 10.90.0.4 accept",
		"drop",
	} {
		if !strings.Contains(set, want) {
			t.Errorf("the ruleset has no %q:\n%s", want, set)
		}
	}
	// A peer that may start nothing is not mentioned: the drop at the end is
	// its answer.
	if strings.Contains(set, "10.90.0.5") {
		t.Errorf("a peer with no rules got a rule:\n%s", set)
	}
	// And the same rules produce the same file, so it can be diffed.
	if buildRuleset("netflow0", rules) != set {
		t.Error("two runs produced different rulesets")
	}
}
