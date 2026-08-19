//go:build !windows

package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"syscall"
)

func dialAgent(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

func isPermission(err error) bool { return errors.Is(err, fs.ErrPermission) }

// Missing means there was nothing to talk to: no socket file, or a socket file
// left behind by an agent that is gone.
func isMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.ECONNREFUSED)
}
