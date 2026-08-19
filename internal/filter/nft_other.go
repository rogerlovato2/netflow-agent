//go:build !linux

package filter

import (
	"errors"
	"net/netip"
)

// Everywhere but Linux the agent owns the data path — it is this process that
// writes the decrypted packet to the interface — so the rules are applied in
// Go, and there is no kernel firewall to program.

func NFTablesAvailable() bool { return false }

func ApplyNFTables(string, map[netip.Addr][]Rule) error {
	return errors.New("nftables is a Linux thing")
}

func RemoveNFTables() error { return nil }
