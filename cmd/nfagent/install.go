package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// installedBinary is where the service will expect to find this program.
//
// Copied there rather than pointed at wherever it was run from: a service unit
// referring to a binary in somebody's downloads folder works until the folder
// is tidied, and then fails at the next boot with an error nobody connects to
// the tidying.
const installedBinary = "/usr/local/bin/nfagent"

// install puts this machine on the mesh and keeps it there across reboots.
//
// One command, because it is one intention. Enrolling, writing a service and
// starting it were three, and every one of them was a step somebody could stop
// at and be left with a machine that looks installed and joins nothing.
func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	setupKey := fs.String("setup-key", "", "the key an administrator created")
	server := fs.String("server", "", "the management server")
	name := fs.String("name", "", "what to call this machine")
	path := fs.String("config", defaultConfigPath(), "where the identity is kept")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("install needs root: it writes a service and creates a network interface")
	}

	// Enrolling first, so a wrong key fails before anything is written to the
	// system. The reverse order leaves a service installed for a machine that
	// never joined, which starts, fails, restarts, and fills the log.
	cfg, err := loadConfig(*path)
	if err != nil || cfg.PrivateKey == "" {
		if *setupKey == "" || *server == "" {
			return errors.New("this machine has not joined a mesh yet: install needs --setup-key and --server")
		}
		if cfg, err = enrol(*server, *setupKey, *name, *path); err != nil {
			return err
		}
	} else {
		fmt.Printf("already a member as %s\n", cfg.Address)
	}

	binary, err := copySelf()
	if err != nil {
		return err
	}
	if err := writeService(binary); err != nil {
		return err
	}

	fmt.Printf("installed and started as %s\n", serviceName)
	fmt.Printf("  address  %s\n", cfg.Address)
	fmt.Printf("  identity %s\n", *path)
	fmt.Printf("  binary   %s\n", binary)
	return nil
}

// uninstall stops the service and removes it.
//
// The identity is left behind unless asked for: a machine that is being
// reinstalled should come back as itself, keeping the address the mesh already
// associates with it, rather than arriving as a stranger and leaving its old
// address held by nobody.
func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "also delete this machine's identity")
	path := fs.String("config", defaultConfigPath(), "where the identity is kept")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("uninstall needs root")
	}

	if err := removeService(); err != nil {
		return err
	}
	fmt.Printf("removed %s\n", serviceName)

	if *purge {
		if err := os.Remove(*path); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Printf("removed %s\n", *path)
		fmt.Println("the machine is still listed in the panel; remove it there too")
	} else {
		fmt.Printf("kept %s, so reinstalling comes back as the same machine\n", *path)
	}
	return nil
}

// copySelf puts this binary where the service will look for it.
func copySelf() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return "", err
	}
	if self == installedBinary {
		return installedBinary, nil
	}

	data, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(installedBinary), 0o755); err != nil {
		return "", err
	}
	// Written beside and renamed: replacing a running binary in place fails
	// with "text file busy", and reinstalling over a running service is exactly
	// when that happens.
	tmp := installedBinary + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, installedBinary); err != nil {
		return "", err
	}
	return installedBinary, nil
}
