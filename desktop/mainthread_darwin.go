package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation
#include <dispatch/dispatch.h>

extern void netflowMainThunk(void *);

static void netflowOnMain(void) {
	dispatch_async_f(dispatch_get_main_queue(), 0, netflowMainThunk);
}
*/
import "C"

// Running something on the main thread.
//
// AppKit will not create a status item anywhere else — it throws, and the
// process is gone before the window has drawn once. Wails owns the main thread
// and has no way to lend it, so this asks the same queue AppKit itself uses.
//
// The queue below is what the C callback reads from. It is buffered because
// the call that fills it must not block: it is made from wails' startup, which
// runs before the main loop is turning and would deadlock waiting for it.
var mainQueue = make(chan func(), 8)

// onMainThread arranges for f to run on the main thread, and returns
// immediately.
func onMainThread(f func()) {
	mainQueue <- f
	C.netflowOnMain()
}

//export netflowMainThunk
func netflowMainThunk(_ *C.void) {
	select {
	case f := <-mainQueue:
		f()
	default:
		// The queue is drained one call per dispatch, so this can only happen
		// if the two ever got out of step. Doing nothing is correct.
	}
}
