package main

import "syscall"

// systemName is the macOS version, as a person would say it.
//
// kern.osproductversion rather than the Darwin kernel version: "26.6.1" is what
// About This Mac shows and what somebody comparing two machines expects to see.
func systemName() string {
	if v, err := syscall.Sysctl("kern.osproductversion"); err == nil && v != "" {
		return "macOS " + v
	}
	return "macOS"
}
