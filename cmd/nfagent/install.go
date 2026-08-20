package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	noUpdate := fs.Bool("no-remote-update", false,
		"never replace this machine's binary, whatever the panel says")
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
	switch {
	case err != nil || cfg.PrivateKey == "":
		if *setupKey == "" || *server == "" {
			return errors.New("this machine has not joined a mesh yet: install needs --setup-key and --server")
		}
		if cfg, err = enrol(*server, *setupKey, *name, *path); err != nil {
			return err
		}

	case *setupKey != "" && !stillAMember(cfg):
		// There is an identity, a key was given, and the server does not know
		// this machine any more.
		//
		// That last part is the whole test. Reinstalling normally should come
		// back as the same machine — same address, same place in everybody's
		// policies — so an identity is not thrown away because somebody passed
		// a key. But an identity the server has forgotten is not an identity:
		// its token is refused, no map ever arrives, and the machine sits there
		// talking to a mesh that has moved on. Which is exactly what happened
		// after the mesh here was rebuilt, and the way out was to know about
		// `uninstall --purge`.
		fmt.Printf("the server no longer knows this machine (%s); joining again\n", cfg.Address)
		if cfg, err = enrol(*server, *setupKey, *name, *path); err != nil {
			return err
		}

	default:
		fmt.Printf("already a member as %s\n", cfg.Address)
	}

	// Written whether or not it was asked for, so that turning it off later is
	// the same operation as turning it on.
	if cfg.NoRemoteUpdate != *noUpdate {
		cfg.NoRemoteUpdate = *noUpdate
		if err := saveConfig(*path, cfg); err != nil {
			return fmt.Errorf("saving the update setting: %w", err)
		}
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

// stillAMember asks the server whether this machine's identity is any good.
//
// Only ever used to decide whether to enrol again, and only when a setup key
// was given — so a server that is down, or a laptop with no network, answers
// "yes, still a member" and nothing is thrown away. Being wrong in that
// direction costs a reinstall that does nothing; being wrong in the other
// costs the machine its address and its place in every policy.
func stillAMember(cfg *Config) bool {
	if cfg.Server == "" || cfg.Token == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := fetchMap(ctx, cfg); err == nil {
		return true
	} else if !strings.Contains(err.Error(), "401") {
		// Anything that is not a refusal is not an answer: the server may be
		// unreachable, and an identity is too expensive to discard on a guess.
		return true
	}
	return false
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
