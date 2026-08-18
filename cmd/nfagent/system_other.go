//go:build !linux && !darwin

package main

import (
	"runtime"
	"strings"
)

// systemName falls back to the name Go knows. Windows will replace this with
// something a person recognises when it is supported properly.
func systemName() string {
	return strings.ToUpper(runtime.GOOS[:1]) + runtime.GOOS[1:]
}
