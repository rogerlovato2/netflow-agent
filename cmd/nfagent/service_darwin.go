//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
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
	// Unloaded first because launchctl refuses to load a label that is already
	// there, and reinstalling over an older version is the common case.
	_ = exec.Command("launchctl", "bootout", "system/"+serviceName).Run()
	return sh("launchctl", "bootstrap", "system", serviceUnit)
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
