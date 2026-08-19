//go:build !darwin

package main

// onMainThread runs f where it is.
//
// Only macOS insists that its status item be created on the main thread; the
// Windows implementation makes a window of its own on a thread of its own and
// does not care which one called it.
func onMainThread(f func()) { f() }
