package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// realm is what the relay announces and what a credential is computed against.
// One value, fixed on both sides, because there is one relay and nothing about
// it varies per machine.
const realm = "netflow"

// ProbeRelay finds out whether this machine can actually use the relay.
//
// "The relay is configured" and "this machine can allocate on it" are different
// questions, and only the first was ever asked. The second is the one that
// matters: a machine whose outbound UDP to 3478 is blocked, or whose
// credentials the relay rejects, gathers no relay candidate and then fails
// against every peer it cannot reach directly — with a status page saying the
// relay is configured, which it is.
//
// The whole exchange is one allocation and its release. It costs a handful of
// packets and answers in under a second on a working path.
func ProbeRelay(ctx context.Context, server TURNServer) error {
	if server.URL == "" {
		return errors.New("no relay is configured")
	}
	u, err := stun.ParseURI(server.URL)
	if err != nil {
		return fmt.Errorf("the relay address %q does not parse: %w", server.URL, err)
	}
	addr := net.JoinHostPort(u.Host, strconv.Itoa(u.Port))

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("opening a socket to probe the relay: %w", err)
	}
	defer conn.Close()

	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: addr,
		TURNServerAddr: addr,
		Conn:           conn,
		Username:       server.Username,
		Password:       server.Password,
		Realm:          realm,
	})
	if err != nil {
		return fmt.Errorf("preparing to probe the relay: %w", err)
	}
	defer c.Close()

	if err := c.Listen(); err != nil {
		return fmt.Errorf("listening to probe the relay: %w", err)
	}

	// Bounded by the caller's context, and by a deadline of its own so a relay
	// that accepts packets and never answers cannot hold this forever.
	done := make(chan error, 1)
	go func() {
		relayed, err := c.Allocate()
		if err != nil {
			done <- fmt.Errorf("the relay refused an allocation: %w", err)
			return
		}
		// Released immediately. Holding it would tie up a port on the relay for
		// ten minutes for every machine that ever asked this question.
		_ = relayed.Close()
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("the relay did not answer: %w", ctx.Err())
	case err := <-done:
		return err
	case <-time.After(probeTimeout):
		return errors.New("the relay did not answer within ten seconds")
	}
}

// probeTimeout is generous on purpose: this is not on any hot path, and a
// relay on the other side of the country on a bad afternoon is still a working
// relay.
const probeTimeout = 10 * time.Second
