package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/rogerlovato2/netflow-agent/internal/engine"
)

// controlSocket is where a running agent answers questions about itself.
//
// A unix socket rather than a port: the agent runs as root and whatever asks it
// runs as the user, and a socket is the one channel between them that cannot be
// reached from another machine by accident.
func controlSocket() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/run/netflow-agent.sock"
	case "windows":
		return `\\.\pipe\netflow-agent`
	default:
		// Inside a directory rather than loose in /run, because that is what
		// systemd's RuntimeDirectory gives the service write access to, and
		// what it cleans up when the service stops.
		return "/run/netflow/agent.sock"
	}
}

// giveToClients hands the socket to the group that may read it.
//
// The group differs by system because the question does: macOS puts every human
// account in staff and its service accounts elsewhere, which is exactly the line
// worth drawing. Linux has no such group by convention, so the installer makes
// one, and if it is not there the socket stays root-only rather than being
// opened to everything on the machine.
func giveToClients(path string) error {
	name := clientGroup()
	if name == "" {
		return nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return fmt.Errorf("looking up the %s group: %w", name, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("the %s group has an unusable id %q: %w", name, g.Gid, err)
	}
	// -1 leaves the owner alone: the agent owns the socket and should keep it.
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("giving the socket to %s: %w", name, err)
	}
	return nil
}

func clientGroup() string {
	switch runtime.GOOS {
	case "darwin":
		return "staff"
	case "windows":
		// A named pipe is not a file and its permissions are not a mode.
		return ""
	default:
		return "netflow"
	}
}

// ControlStatus is what a running agent says about itself.
type ControlStatus struct {
	Address   string        `json:"address"`
	Interface string        `json:"interface"`
	PublicKey string        `json:"publicKey"`
	Server    string        `json:"server"`
	SignalURL string        `json:"signalUrl"`
	Signal    bool          `json:"signalConnected"`
	Relay     bool          `json:"relayConfigured"`
	Peers     []ControlPeer `json:"peers"`
	// Paused is whether the tunnels are down because somebody at this machine
	// asked for it, which is the one state that looks like a fault and is not.
	Paused bool `json:"paused"`
	// StartedAt is when this agent came up, in unix seconds.
	//
	// The agent restarts itself to apply some changes from the server, so this
	// is not the same as how long the machine has been on the mesh — which is
	// the more honest thing to show: a number that resets when something went
	// wrong is a number worth seeing reset.
	StartedAt int64 `json:"startedAt"`
	// Version is the agent's, which is not the window's. Two programs updated
	// separately will disagree, and the one that matters for a tunnel is this.
	Version string `json:"agentVersion"`
}

// ControlPeer is one peer, as the agent sees it right now.
type ControlPeer struct {
	PublicKey string `json:"publicKey"`
	// Name and Address come from the map rather than from the tunnel: the
	// device knows keys and prefixes, and a person reading a window knows
	// neither.
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
	State     string `json:"state"`
	Path      string `json:"path"`
	RTTMillis int    `json:"rttMs"`
	RX        uint64 `json:"rx"`
	TX        uint64 `json:"tx"`
	Handshake int64  `json:"handshake"`
}

// serveControl answers on the socket for as long as ctx lives.
//
// It reads, and it can stop and start the tunnels. Nothing here changes what
// this machine is: joining, leaving and which mesh are decisions with a
// credential behind them, and exposing them on a local socket would mean a
// process running as any logged-in user could move the machine between meshes.
//
// Pausing is a different kind of decision and belongs to whoever is sitting at
// the machine. It takes nothing away that the person could not take away by
// pulling the cable, it is not remembered across a restart, and the panel sees
// the machine go quiet either way.
func serveControl(ctx context.Context, eng *engine.Engine, cfg *Config, log *slog.Logger) {
	path := controlSocket()
	// A socket left behind by a killed agent blocks the next one from binding,
	// and the next one is usually the restart that was supposed to fix things.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Debug("control: could not clear the old socket", "path", path, "err", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Warn("control: could not create the socket directory", "err", err)
		return
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Warn("control: could not listen", "path", path, "err", err)
		return
	}
	// 0660: a client on this machine may read the mesh's state, and a stranger
	// who lands on the machine as a service account may not. Nothing here is a
	// secret, but who talks to whom is worth keeping to the people who are
	// already meant to know.
	//
	// 0660 alone would mean root and nobody else, since that is who the agent
	// runs as. The group is what makes the mode useful: give the socket away to
	// the group the machine's human accounts are in, and the window a person
	// opens can read it without any of them being root.
	if err := os.Chmod(path, 0o660); err != nil {
		log.Debug("control: could not set the socket mode", "err", err)
	}
	if err := giveToClients(path); err != nil {
		// Not fatal. The agent's own job is unaffected; what is lost is the
		// graphical client, and saying so here is the only warning anybody
		// will get before it says it cannot talk to the agent.
		log.Warn("control: the socket stays root-only; a client running as a "+
			"user will not be able to read it", "err", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(collectControlStatus(eng, cfg))
	})
	// ctx and not the request's: a request ends the moment it is answered, and
	// the peers started from it would be cancelled with it.
	mux.HandleFunc("POST /pause", func(w http.ResponseWriter, _ *http.Request) {
		log.Info("control: pausing on request")
		Pause(ctx, eng)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /resume", func(w http.ResponseWriter, _ *http.Request) {
		log.Info("control: resuming on request")
		Resume(ctx, eng, log)
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = os.Remove(path)
	}()

	log.Info("control socket", "path", path)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Warn("control: stopped", "err", err)
	}
}

// startedAt is when this process came up. Set once, read by the control socket.
var startedAt = time.Now()

func collectControlStatus(eng *engine.Engine, cfg *Config) ControlStatus {
	st := ControlStatus{
		StartedAt: startedAt.Unix(),
		Version:   version,
		Paused:    Paused(),
		Address:   cfg.Address,
		Interface: eng.Device().Name(),
		PublicKey: eng.PublicKey().String(),
		Server:    cfg.Server,
		SignalURL: cfg.SignalURL,
		Signal:    eng.SignalConnected(),
		Relay:     eng.RelayConfigured(),
	}
	dev, err := eng.Device().Status()
	if err != nil {
		return st
	}
	for _, key := range eng.PeerKeys() {
		id := key.String()
		path := eng.PeerPath(key)
		d := dev[id]
		// What the server last said about this peer, so the list can be read
		// by somebody who has never seen a public key.
		known := peerFromMap(id)
		st.Peers = append(st.Peers, ControlPeer{
			PublicKey: id,
			Name:      known.Name,
			Address:   known.Address,
			State:     string(eng.PeerState(key)),
			Path:      path.Kind,
			RTTMillis: int(path.RTT.Milliseconds()),
			RX:        d.RXBytes,
			TX:        d.TXBytes,
			Handshake: d.LastHandshake,
		})
	}
	return st
}

// controlClient speaks HTTP over the socket.
//
// The dialer ignores the address and opens the socket instead, which is the
// least surprising way to do this: the URL is a formality and the path is the
// real destination.
func controlClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", controlSocket())
			},
		},
		Timeout: 5 * time.Second,
	}
}

// tellControl asks a running agent to do something. Nothing comes back but
// whether it was done.
func tellControl(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent"+path, nil)
	if err != nil {
		return err
	}
	resp, err := controlClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("the agent answered %s", resp.Status)
	}
	return nil
}

// askControl reads the status from a running agent.
//
// The http client is given a dialer that ignores the address and opens the
// socket instead, which is the least surprising way to speak HTTP over a unix
// socket: the URL is a formality and the path is the real destination.
func askControl(ctx context.Context) (ControlStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/status", nil)
	if err != nil {
		return ControlStatus{}, err
	}
	resp, err := controlClient().Do(req)
	if err != nil {
		return ControlStatus{}, err
	}
	defer resp.Body.Close()

	var st ControlStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return ControlStatus{}, err
	}
	return st, nil
}
