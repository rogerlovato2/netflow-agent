//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const serviceUnit = "/etc/systemd/system/netflow-agent.service"

// serviceName is what an administrator will type at it.
const serviceName = "netflow-agent"

// writeService installs a systemd unit that runs the agent.
//
// Restart=always and a delay, because everything this agent depends on can be
// missing at boot and come back: the management server, the signal server, the
// network itself. Exiting on any of them and staying dead would mean a machine
// that reboots in the wrong order never rejoins.
//
// After=network-online.target rather than network.target: the first means an
// address exists, the second only means the stack is loaded, and an agent that
// starts before it has an address gathers no candidates worth having.
func writeService(binary string) error {
	// The group that may read the control socket. Made here because there is no
	// conventional one to borrow on Linux: a machine's human accounts are not
	// all in any single group the way they are on macOS, so the choice has to be
	// made explicitly and an administrator has to put people in it. Until
	// somebody is added, the socket is root's alone, which is the right default
	// for a group that means "may see this mesh".
	if err := sh("groupadd", "-f", "netflow"); err != nil {
		fmt.Fprintf(os.Stderr, "could not create the netflow group (%v); the "+
			"control socket will stay root-only\n", err)
	}

	unit := fmt.Sprintf(`[Unit]
Description=netflow mesh agent
Documentation=https://github.com/rogerlovato2/netflow
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s up
Restart=always
RestartSec=5
# The agent creates an interface and writes routes, which is all it needs.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
# Nothing else on this machine is its business.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/etc/netflow %s
# The second path is the directory the binary lives in, and it is here for one
# reason: replacing itself. ProtectSystem=strict makes /usr read-only for this
# service, which is right for everything the agent does except the one thing it
# is asked to do from the panel — and the failure it produced said only "read-
# only file system", from a process that had just downloaded and verified a
# release it then could not install.
# systemd creates /run/netflow before start and removes it after, which is
# where the control socket lives. Without it ProtectSystem=strict above leaves
# /run read-only and the socket cannot be bound — the hardening would quietly
# cost the agent the one channel a graphical client has to it.
RuntimeDirectory=netflow
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
`, binary, filepath.Dir(binary))

	if err := os.WriteFile(serviceUnit, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", serviceUnit, err)
	}
	if err := sh("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := sh("systemctl", "enable", serviceName); err != nil {
		return err
	}
	return sh("systemctl", "restart", serviceName)
}

func removeService() error {
	_ = sh("systemctl", "disable", "--now", serviceName)
	if err := os.Remove(serviceUnit); err != nil && !os.IsNotExist(err) {
		return err
	}
	return sh("systemctl", "daemon-reload")
}

func sh(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
