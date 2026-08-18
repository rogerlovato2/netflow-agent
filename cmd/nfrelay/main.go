// Command nfrelay carries traffic between two machines that cannot reach each
// other directly.
//
// It is the answer to the case ICE cannot solve. Hole punching works when at
// least one of the two NATs is predictable enough to aim at; a symmetric NAT
// gives every destination a different external port, so there is nothing to
// aim at and no amount of retrying helps. Those pairs need somebody in the
// middle, and this is it.
//
// The cost is real and worth stating: every byte crosses this machine twice,
// and its bandwidth becomes the pair's bandwidth. That is why the panel draws
// direct and relayed differently — a fleet drifting onto the relay is a fleet
// quietly getting slower and more expensive, and it looks like nothing from a
// status line.
//
// What it cannot do is read any of it. WireGuard's encryption is end to end
// between the two machines, and this sees ciphertext addressed to somebody
// else.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", envOr("NFRELAY_LISTEN", "0.0.0.0:3478"),
		"address to listen on")
	public := flag.String("public-ip", os.Getenv("NFRELAY_PUBLIC_IP"),
		"the address peers should be told to send to")
	realm := flag.String("realm", envOr("NFRELAY_REALM", "netflow"), "TURN realm")
	flag.Parse()

	secret := os.Getenv("NFRELAY_SECRET")
	if secret == "" {
		// Only an environment variable, never a flag: it would otherwise be
		// readable in `ps` by every user on the machine. It has to be the same
		// string the management server holds, because that is the whole of the
		// authentication — the server issues a credential, this recomputes it,
		// and neither ever talks to the other.
		return errors.New("NFRELAY_SECRET is required, and has to match the management server's")
	}
	if *public == "" {
		return errors.New("-public-ip is required: it is the address peers are told to send to, " +
			"and this process cannot know which of its addresses that is")
	}
	ip := net.ParseIP(*public)
	if ip == nil {
		return fmt.Errorf("%q is not an address", *public)
	}

	level := slog.LevelInfo
	if v, ok := os.LookupEnv("NFRELAY_DEBUG"); ok && v != "" && v != "0" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	conn, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *listen, err)
	}
	defer conn.Close()

	logf := logging.NewDefaultLoggerFactory()
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		// The credential is a timestamp and an HMAC of it, so this can accept a
		// machine it has never heard of and reject one whose credential has
		// expired, without holding a list of anybody. There is no user database
		// here and nothing to keep in step with the panel.
		AuthHandler: turn.NewLongTermAuthHandler(secret, logf.NewLogger("turn")),
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: conn,
			// The address peers are told to send to. It is given rather than
			// discovered because this process sees a private address behind
			// NAT, and handing that out sends every peer somewhere useless.
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: ip,
				Address:      "0.0.0.0",
			},
		}},
		LoggerFactory: logf,
	})
	if err != nil {
		return fmt.Errorf("starting the relay: %w", err)
	}

	log.Info("nfrelay is up", "listen", *listen, "public", ip.String(), "realm", *realm)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Info("shutting down")
	return srv.Close()
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
