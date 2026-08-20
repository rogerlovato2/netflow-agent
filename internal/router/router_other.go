//go:build !linux && !darwin && !windows

package router

func newRouter() Router {
	return unsupported{why: "carrying a network is not supported on this system"}
}

func available() (bool, string) {
	return false, "carrying a network is not supported on this system"
}
