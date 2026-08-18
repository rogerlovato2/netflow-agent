//go:build !linux && !darwin

package main

import (
	"fmt"
	"runtime"
)

const serviceName = "netflow-agent"

func writeService(string) error {
	return fmt.Errorf("nfagent: installing a service on %s is not supported yet", runtime.GOOS)
}

func removeService() error {
	return fmt.Errorf("nfagent: installing a service on %s is not supported yet", runtime.GOOS)
}
