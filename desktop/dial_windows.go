//go:build windows

package main

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// On Windows the agent listens on a named pipe. It is the same idea as a unix
// socket — local, addressed by name, with permissions on it — and the only
// reason this file exists is that the standard library does not dial one.
func dialAgent(ctx context.Context, path string) (net.Conn, error) {
	timeout := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	return winio.DialPipe(path, &timeout)
}

func isPermission(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "access is denied")
}

func isMissing(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "cannot find the file")
}
