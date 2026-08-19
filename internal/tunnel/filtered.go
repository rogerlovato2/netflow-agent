package tunnel

import (
	"github.com/rogerlovato2/netflow-agent/internal/filter"
	"golang.zx2c4.com/wireguard/tun"
)

// filteredTUN is where an access rule is applied on every platform whose
// WireGuard runs in this process.
//
// It sits between wireguard-go and the operating system's interface, which is
// exactly the point where a decrypted packet exists and nothing has acted on it
// yet. Read is what leaves this machine; Write is what arrives from a peer and
// is about to be delivered.
//
// A dropped packet is dropped silently, the way a firewall drops things. The
// caller is told everything was written because from its side everything was:
// there is no error here and nothing to retry.
type filteredTUN struct {
	tun.Device
	f *filter.Filter
}

func (t filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	// Recorded on the way out: this is how the reply is recognised later, and
	// it is what makes a one-way rule a rule rather than a broken tunnel.
	for i := 0; i < n; i++ {
		t.f.Outbound(bufs[i][offset : offset+sizes[i]])
	}
	return n, err
}

func (t filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	keep := bufs[:0]
	for _, b := range bufs {
		if t.f.Inbound(b[offset:]) {
			keep = append(keep, b)
		}
	}
	if len(keep) == 0 {
		return len(bufs), nil
	}
	if _, err := t.Device.Write(keep, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}
