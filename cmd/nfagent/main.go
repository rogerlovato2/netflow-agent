// Command nfagent is one machine's side of the mesh.
//
// It is deliberately configured from a file rather than from a management
// server, because there is not one yet. The file holds what a management server
// will eventually push: this machine's key and address, where to signal, and
// who its peers are. Everything below that — negotiation, the tunnel, the
// reconnects — is already the real implementation, so what this proves on two
// machines is what will run on a thousand.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/rogerlovato2/netflow-agent/internal/filter"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pion/logging"
	"github.com/rogerlovato2/netflow-agent/internal/engine"
	"github.com/rogerlovato2/netflow-agent/internal/p2p"
	"github.com/rogerlovato2/netflow-agent/internal/router"
	"github.com/rogerlovato2/netflow-agent/internal/tunnel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// version is stamped at build time by the release workflow. "dev" means a
// binary somebody built themselves, which is worth being able to tell apart
// when a machine misbehaves.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `nfagent — one machine in the netflow mesh

  nfagent install --setup-key <key> --server <url>
                                                join, and keep joining across reboots
  nfagent uninstall [--purge]                   stop and remove the service
  nfagent up --setup-key <key> --server <url>   join the mesh and stay, in the foreground
  nfagent up                                    start again, already enrolled
  nfagent status                                what this machine sees
  nfagent pause                                 take the tunnels down, keep the agent
  nfagent resume                                put them back
  nfagent version                               which build this is
  nfagent key                                   print a key pair, for a hand-written setup

flags for `+"`up`"+`:
  --setup-key <k>  the key an administrator created; only needed the first time
  --server <url>   the management server, e.g. https://manage.example.com
  --name <name>    what to call this machine (default: its hostname)
  --config <file>  where the identity is kept (default: `+defaultConfigPath()+`)
  --interface <n>  interface to create (default: `+tunnel.DefaultTUNName+`; macOS names its own)
  --userspace      keep the stack inside this process: no interface, no route,
                   no privilege — and nothing outside this process reaches the
                   mesh. For tests, not for a client.
  --echo           answer inside the tunnel, so another machine can prove it got through
  --probe <addr>   dial that address inside the tunnel every few seconds
  --debug          narrate everything, including ICE checks and WireGuard handshakes
  --prove-nat      refuse this machine's own addresses as candidates, so connecting
                   is proof the NAT was traversed and not that a route existed
`)
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}

	switch os.Args[1] {
	case "key":
		return printKey()
	case "install":
		return install(os.Args[2:])
	case "uninstall":
		return uninstall(os.Args[2:])
	case "up":
		return up(os.Args[2:])
	case "status":
		return status(os.Args[2:])
	case "pause":
		return setPaused(true)
	case "resume":
		return setPaused(false)
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func printKey() error {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	fmt.Printf("privateKey: %s\n", k.String())
	fmt.Printf("publicKey:  %s\n", k.PublicKey().String())
	fmt.Fprintln(os.Stderr, "\nThe private key goes in this machine's config and nowhere else.")
	fmt.Fprintln(os.Stderr, "The public key is what the other machines list as a peer.")
	return nil
}

// Config is what the file holds.
//
// Server and Token are what an enrolled machine has: with them the peer list is
// fetched and kept current, and the Peers below are only a cache of the last
// answer. Without them the file is the whole truth, which is what makes the
// mesh testable before there is a server to ask.
type Config struct {
	PrivateKey string `json:"privateKey"`
	Address    string `json:"address"`
	// Subnet is the whole mesh, routed into the interface with one entry
	// instead of one per peer. Empty means a server too old to say, and the
	// agent falls back to a route per peer.
	Subnet    string       `json:"subnet,omitempty"`
	SignalURL string       `json:"signalUrl"`
	Server    string       `json:"server,omitempty"`
	Token     string       `json:"token,omitempty"`
	STUN      []string     `json:"stun,omitempty"`
	Relay     *RelayConfig `json:"relay,omitempty"`
	Peers     []PeerConfig `json:"peers"`
	// Generation is the last reconnect request this machine acted on. Kept in
	// the file so a restart does not act on the same one again.
	Generation int64 `json:"generation,omitempty"`
	// NoRemoteUpdate refuses to replace this machine's binary, whatever the
	// server says.
	//
	// The switch in the panel is policy: it decides what the fleet does, and
	// whoever holds the panel can turn it back on. This one is on the machine
	// and nothing on the network can reach it — it is for the machine that must
	// never change under you, and it is why the flag exists separately from the
	// setting rather than as a mirror of it.
	NoRemoteUpdate bool `json:"noRemoteUpdate,omitempty"`
}

// RelayConfig is a relay and a credential for it, both issued by the server.
type RelayConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type PeerConfig struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIPs"`
	// Name is what the panel calls that machine. Nothing here acts on it — it
	// exists so a graphical client can say "supabase" where the command line
	// says a public key, and so the answer comes from the one place that is
	// allowed to name things.
	Name string `json:"name,omitempty"`
	// Address is the peer's own address in the mesh, which is what an access
	// rule is written against. It is the first of the allowed IPs today, and
	// carried separately so that stays an implementation detail rather than an
	// assumption spread through the code.
	Address string `json:"address,omitempty"`
	// Inbound is what this peer may start against this machine. Empty means
	// nothing may be started: the peer is here because this machine may start
	// something against it, and the replies get back because the filter that
	// enforces this has state.
	Inbound []filter.Rule `json:"inbound,omitempty"`
}

func up(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath(), "where the identity is kept")
	setupKey := fs.String("setup-key", "", "the key an administrator created")
	server := fs.String("server", "", "the management server")
	name := fs.String("name", "", "what to call this machine")
	iface := fs.String("interface", "", "interface to create")
	userspace := fs.Bool("userspace", false, "keep the stack inside this process")
	echo := fs.Bool("echo", false, "answer inside the tunnel")
	probe := fs.String("probe", "", "address to dial inside the tunnel")
	debug := fs.Bool("debug", false, "narrate everything")
	proveNAT := fs.Bool("prove-nat", false,
		"refuse addresses this machine holds directly, so a connection proves NAT traversal")
	if err := fs.Parse(args); err != nil {
		return err
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Enrolling and starting are one command.
	//
	// They were two, and the split was an accident of how this was built: a
	// person setting up a machine wants it on the mesh, not a configuration
	// file. With a setup key it enrols and starts; without one it starts with
	// the identity it already has, and says plainly what to do when it has
	// none.
	cfg, err := loadConfig(*path)
	if err != nil || cfg.PrivateKey == "" {
		if *setupKey == "" {
			usage()
			return fmt.Errorf("this machine has not joined a mesh yet: run with --setup-key and --server")
		}
		if *server == "" {
			return errors.New("--setup-key needs --server")
		}
		if cfg, err = enrol(*server, *setupKey, *name, *path); err != nil {
			return err
		}
	} else if *setupKey != "" {
		log.Info("already enrolled; the setup key was ignored", "config", *path)
	}

	priv, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("privateKey: %w", err)
	}
	addr, err := netip.ParseAddr(cfg.Address)
	if err != nil {
		return fmt.Errorf("address: %w", err)
	}

	peers, err := parsePeers(cfg.Peers)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One route for the whole mesh rather than one per peer. A machine that
	// joined before the server said what the subnet is keeps the old behaviour
	// until its next map, which is the only safe way to be wrong here: a route
	// too many delivers packets, a route too few does not.
	var subnet netip.Prefix
	if cfg.Subnet != "" {
		if p, perr := netip.ParsePrefix(cfg.Subnet); perr == nil {
			subnet = p
		} else {
			log.Warn("the mesh subnet does not parse; routing per peer instead",
				"subnet", cfg.Subnet, "err", perr)
		}
	}

	eng, err := engine.New(engine.Config{
		PrivateKey: priv,
		Addresses:  []netip.Addr{addr},
		Subnet:     subnet,
		SignalURL:  cfg.SignalURL,
		Userspace:  *userspace,
		TUNName:    *iface,
		P2P: p2p.Config{
			STUN:                  cfg.STUN,
			DisableHostCandidates: *proveNAT,
			LoggerFactory:         iceLogger(*debug),
		},
	}, log)
	if err != nil {
		return err
	}

	log.Info("nfagent is up",
		"address", addr, "interface", eng.Device().Name(),
		"signal", cfg.SignalURL, "peers", len(peers),
		"publicKey", priv.PublicKey().String())

	// The engine gets its own context so that shutting down has two steps in a
	// definite order: say goodbye to the peers while the signal connection is
	// still up, and only then stop the engine that owns it. Handing it ctx
	// directly would tear the connection down at the same instant the message
	// needed to leave on it.
	engCtx, stopEngine := context.WithCancel(context.Background())
	defer stopEngine()

	done := make(chan error, 1)
	go func() { done <- eng.Run(engCtx) }()

	// The peers in the file are applied first, always, before anything is asked
	// of the management server.
	//
	// They are the last map this machine was given, and they are what lets it
	// come back up without one. A machine that reboots on a train, or while the
	// panel is down, or — as happened here — somewhere the management server's
	// address does not resolve, still has to rebuild the tunnels it already
	// knew about. Waiting for the map first turns "new machines cannot join"
	// into "nothing connects at all", which is a much worse outage from the
	// same cause.
	if cfg.Relay != nil {
		eng.SetRelay(cfg.Relay.URL, cfg.Relay.Username, cfg.Relay.Password)
	}
	if len(peers) > 0 {
		eng.SetPeers(ctx, peers)
	}

	// What this machine carries for the rest of the mesh, if anything. Closed
	// on the way out: a machine that stops being an agent should stop being a
	// router in the same breath, rather than leaving forwarding switched on and
	// a NAT rule pointing at an interface that is gone.
	rt := router.New()
	defer func() {
		if err := rt.Close(); err != nil {
			log.Warn("could not put the routing rules back", "err", err)
		}
	}()

	if cfg.Server != "" && cfg.Token != "" {
		log.Info("following the network map", "server", cfg.Server, "cached_peers", len(peers))
		go followTheMap(ctx, eng, cfg, rt, *path, log)
		go reportToServer(ctx, eng, cfg, log)
	}

	if *echo {
		go serveEcho(ctx, eng, addr, log)
	}
	if *probe != "" {
		go runProbe(ctx, eng, *probe, log)
	}
	go reportStatus(ctx, eng, peers, log)
	// The map carries the policy and is polled often; this is only what makes a
	// machine left alone for a long time eventually catch up.
	go watchForUpdates(ctx, eng, cfg, UpdatePolicy, log)
	go serveControl(ctx, eng, cfg, log)

	<-ctx.Done()
	log.Info("shutting down")
	eng.Goodbye()
	stopEngine()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return nil
	}
}

// iceLogger turns on ICE's own narration under -debug. It is the only thing
// that distinguishes "no candidate was ever gathered" from "candidates were
// gathered and none answered", two failures that look identical from outside.
func iceLogger(debug bool) logging.LoggerFactory {
	if !debug {
		return nil
	}
	return &logging.DefaultLoggerFactory{
		Writer:          os.Stderr,
		DefaultLogLevel: logging.LogLevelDebug,
	}
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if c.SignalURL == "" {
		return nil, errors.New("signalUrl is empty")
	}
	return &c, nil
}

func parsePeers(in []PeerConfig) ([]engine.Peer, error) {
	out := make([]engine.Peer, 0, len(in))
	for i, p := range in {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %d publicKey: %w", i, err)
		}
		if len(p.AllowedIPs) == 0 {
			return nil, fmt.Errorf("peer %d has no allowedIPs", i)
		}
		var nets []netip.Prefix
		for _, s := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("peer %d allowedIPs %q: %w", i, s, err)
			}
			nets = append(nets, pfx)
		}
		out = append(out, engine.Peer{PublicKey: pub, AllowedIPs: nets})
	}
	return out, nil
}

// echoPort is where -echo listens and -probe dials. Inside the tunnel, so it is
// not reachable from anywhere else.
const echoPort = 7777

// serveEcho answers inside the tunnel. It is what turns "the state says
// connected" into something a person on the other machine can see.
func serveEcho(ctx context.Context, eng *engine.Engine, addr netip.Addr, log *slog.Logger) {
	ln, err := eng.Device().Net.ListenTCPAddrPort(netip.AddrPortFrom(addr, echoPort))
	if err != nil {
		log.Error("nfagent: cannot listen inside the tunnel", "err", err)
		return
	}
	defer ln.Close()
	log.Info("nfagent: answering inside the tunnel", "addr", netip.AddrPortFrom(addr, echoPort))

	go func() { <-ctx.Done(); _ = ln.Close() }()

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 512)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			host, _ := os.Hostname()
			fmt.Fprintf(c, "%s answered by %s", buf[:n], host)
		}()
	}
}

// runProbe dials a peer inside the tunnel and reports the round trip. Its
// failures are as informative as its successes, which is why they are logged
// rather than retried quietly.
func runProbe(ctx context.Context, eng *engine.Engine, target string, log *slog.Logger) {
	addr, err := netip.ParseAddr(target)
	if err != nil {
		log.Error("nfagent: -probe is not an address", "target", target, "err", err)
		return
	}
	dst := netip.AddrPortFrom(addr, echoPort)

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		start := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		conn, err := eng.Device().Net.DialContextTCPAddrPort(dialCtx, dst)
		cancel()
		if err != nil {
			log.Warn("probe failed", "to", dst, "err", err)
			continue
		}

		host, _ := os.Hostname()
		_, _ = fmt.Fprintf(conn, "hello from %s", host)
		_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			log.Warn("probe sent but got no answer", "to", dst, "err", err)
			continue
		}
		log.Info("probe ok", "to", dst, "rtt", time.Since(start).Round(time.Millisecond),
			"answer", string(buf[:n]))
	}
}

// reportStatus prints what each peer is doing, which is the only view an
// operator has until there is a management server to ask.
func reportStatus(ctx context.Context, eng *engine.Engine, peers []engine.Peer, log *slog.Logger) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		st, err := eng.Device().Status()
		if err != nil {
			log.Warn("reading the device", "err", err)
			continue
		}
		for _, p := range peers {
			key := p.PublicKey.String()
			s := st[key]
			handshake := "never"
			if s.LastHandshake > 0 {
				handshake = time.Since(time.Unix(s.LastHandshake, 0)).Round(time.Second).String() + " ago"
			}
			log.Info("peer",
				"key", key[:8], "state", eng.PeerState(p.PublicKey),
				"endpoint", s.Endpoint, "handshake", handshake,
				"rx", s.RXBytes, "tx", s.TXBytes,
				"signal", eng.SignalConnected())
		}
	}
}
