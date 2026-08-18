//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const serviceUnit = "/Library/LaunchDaemons/cc.netflow.agent.plist"

const serviceName = "cc.netflow.agent"

// writeService installs a launchd daemon that runs the agent.
//
// A LaunchDaemon and not a LaunchAgent: the agent has to be running before
// anyone logs in, and it needs root to create the interface. An agent would run
// as the user, at login, and could do neither.
//
// KeepAlive rather than RunAtLoad alone, for the same reason systemd gets
// Restart=always: everything it depends on can be missing at boot and come
// back, and a machine that gave up on the first try would never rejoin.
func writeService(binary string) error {
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>up</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/netflow-agent.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/netflow-agent.log</string>
</dict>
</plist>
`, serviceName, binary)

	if err := os.WriteFile(serviceUnit, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", serviceUnit, err)
	}

	// Reinstalling over a running daemon is the common case, not the unusual
	// one, and it is the case this used to get wrong: bootout was issued and
	// bootstrap followed immediately, into a label launchd had not finished
	// tearing down yet. It answers that with "Bootstrap failed: 5: Input/output
	// error", which says nothing about what happened and is what an upgrade
	// looked like from the outside.
	//
	// So: if the daemon is loaded, restart it in place. The plist is the same
	// file with the same program in it — only the binary underneath it changed,
	// and kickstart is the operation for exactly that.
	if loaded() {
		return sh("launchctl", "kickstart", "-k", "system/"+serviceName)
	}

	_ = exec.Command("launchctl", "bootout", "system/"+serviceName).Run()
	// And when it does have to be booted out — a first install after a failed
	// one, a plist written by an older version — wait for the label to actually
	// go before asking for it back.
	for range 50 {
		if !loaded() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return sh("launchctl", "bootstrap", "system", serviceUnit)
}

// loaded says whether launchd currently has the daemon.
func loaded() bool {
	return exec.Command("launchctl", "print", "system/"+serviceName).Run() == nil
}

func removeService() error {
	_ = exec.Command("launchctl", "bootout", "system/"+serviceName).Run()
	if err := os.Remove(serviceUnit); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func sh(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
