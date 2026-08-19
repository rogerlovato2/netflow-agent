//go:build linux

package filter

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// On Linux the kernel usually holds the WireGuard interface, which means the
// packet is decrypted and delivered before this process could look at it. The
// rules are the same rules; the place they are applied is the kernel's own
// firewall.
//
// The ruleset is written whole every time and replaces whatever was there. An
// incremental update would have to know what it changed from, and a firewall
// that is a little bit wrong is worse than one that is rebuilt.

const nftTable = "netflow"

// NFTablesAvailable reports whether this machine can enforce rules in the
// kernel.
func NFTablesAvailable() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// ApplyNFTables writes the ruleset for one interface.
//
// The shape is the whole design in five lines: replies always pass, each peer
// that may start something gets a rule saying what, and everything else
// arriving on the mesh interface is dropped. A peer that may start nothing
// simply has no rule — it is not mentioned, and the drop at the end is its
// answer.
//
// Only traffic on the mesh interface is touched. Nothing here can affect the
// rest of the machine, which matters: this runs as root on somebody's server.
func ApplyNFTables(iface string, rules map[netip.Addr][]Rule) error {
	return nftRun(buildRuleset(iface, rules))
}

// buildRuleset is the ruleset as text, which is what the test reads.
func buildRuleset(iface string, rules map[netip.Addr][]Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", nftTable)
	fmt.Fprintf(&b, "delete table inet %s\n", nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	fmt.Fprintf(&b, "  chain input {\n")
	fmt.Fprintf(&b, "    type filter hook input priority filter; policy accept;\n")
	fmt.Fprintf(&b, "    iifname != \"%s\" accept\n", iface)
	fmt.Fprintf(&b, "    ct state established,related accept\n")

	// Sorted so that the same rules produce the same ruleset: a file that
	// changes only when the rules do is a file somebody can diff.
	peers := make([]netip.Addr, 0, len(rules))
	for addr := range rules {
		peers = append(peers, addr)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Less(peers[j]) })

	for _, addr := range peers {
		family := "ip"
		if addr.Is6() {
			family = "ip6"
		}
		for _, r := range rules[addr] {
			switch r.Protocol {
			case All:
				fmt.Fprintf(&b, "    %s saddr %s accept\n", family, addr)
			case ICMP:
				proto := "icmp"
				if addr.Is6() {
					proto = "icmpv6"
				}
				fmt.Fprintf(&b, "    %s saddr %s meta l4proto %s accept\n", family, addr, proto)
			case TCP, UDP:
				if len(r.Ports) == 0 {
					fmt.Fprintf(&b, "    %s saddr %s meta l4proto %s accept\n",
						family, addr, r.Protocol)
					continue
				}
				fmt.Fprintf(&b, "    %s saddr %s %s dport %s accept\n",
					family, addr, r.Protocol, nftPorts(r.Ports))
			}
		}
	}

	fmt.Fprintf(&b, "    drop\n")
	fmt.Fprintf(&b, "  }\n}\n")

	return b.String()
}

// RemoveNFTables takes the ruleset away, for an agent that is stopping or one
// whose rules were withdrawn.
func RemoveNFTables() error {
	// Created first so that deleting it cannot fail for not existing, which is
	// nft's own idiom for "make sure this is gone".
	return nftRun(fmt.Sprintf("table inet %s\ndelete table inet %s\n", nftTable, nftTable))
}

func nftPorts(ports []PortRange) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.From == p.To {
			parts = append(parts, fmt.Sprint(p.From))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d", p.From, p.To))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func nftRun(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var out bytes.Buffer
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
