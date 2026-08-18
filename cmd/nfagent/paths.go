package main

import (
	"os"
	"path/filepath"
	"runtime"
)

// defaultConfigPath is where an installed agent keeps its identity.
//
// A fixed place, so `netflow up` and `netflow status` and the service unit all
// mean the same file without anyone passing a path. The directory differs by
// platform because that is where each expects daemon state to live, and putting
// it somewhere else is how a machine ends up with two identities after an
// upgrade.
//
// It falls back to the working directory when there is no root: a developer
// running this without privilege should get a file, not an error about a
// directory they were never going to be allowed to create.
func defaultConfigPath() string {
	dir := systemConfigDir()
	if dir == "" {
		return "netflow.json"
	}
	return filepath.Join(dir, "netflow.json")
}

func systemConfigDir() string {
	switch runtime.GOOS {
	case "linux":
		return "/etc/netflow"
	case "darwin":
		return "/usr/local/etc/netflow"
	case "windows":
		if d := os.Getenv("ProgramData"); d != "" {
			return filepath.Join(d, "netflow")
		}
		return ""
	default:
		return ""
	}
}

// ensureConfigDir creates the directory the configuration lives in.
//
// 0700 because the file inside holds this machine's private key and its token:
// anything readable by other users on the machine hands them the tunnel.
func ensureConfigDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}
