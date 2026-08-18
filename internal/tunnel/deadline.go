package tunnel

import "time"

// deadlineNow is a deadline already in the past, which is how a blocked Read is
// unblocked. A zero time means "no deadline" and would do nothing at all, which
// is the mistake this exists to avoid making twice.
func deadlineNow() time.Time {
	return time.Unix(1, 0)
}
