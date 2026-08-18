package main

import (
	"bufio"
	"os"
	"strings"
)

// systemName is what this machine calls itself, for the panel to show.
//
// /etc/os-release is the one file every distribution agrees on, and PRETTY_NAME
// is the line meant to be read by a person — "Debian GNU/Linux 13 (trixie)".
// Anything derived from the kernel version instead would say the same thing for
// a container and its host, which is exactly the pair somebody is trying to
// tell apart when they read this column.
func systemName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, value, ok := strings.Cut(sc.Text(), "=")
		if !ok || name != "PRETTY_NAME" {
			continue
		}
		if v := strings.Trim(strings.TrimSpace(value), `"`); v != "" {
			return v
		}
	}
	return "Linux"
}
