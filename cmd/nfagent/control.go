package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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
}

// ControlPeer is one peer, as the agent sees it right now.
type ControlPeer struct {
	PublicKey string `json:"publicKey"`
	State     string `json:"state"`
	Path      string `json:"path"`
	RTTMillis int    `json:"rttMs"`
	RX        uint64 `json:"rx"`
	TX        uint64 `json:"tx"`
	Handshake int64  `json:"handshake"`
}

// serveControl answers on the socket for as long as ctx lives.
//
// Read-only, deliberately. Everything that changes this machine's membership —
// joining, leaving, which mesh — is a decision with a credential behind it, and
// exposing it here would mean a local socket that can move a machine between
// meshes. What a graphical client needs is to show what is happening, and that
// is all this gives it.
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
	if err := os.Chmod(path, 0o660); err != nil {
		log.Debug("control: could not set the socket mode", "err", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(collectControlStatus(eng, cfg))
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

func collectControlStatus(eng *engine.Engine, cfg *Config) ControlStatus {
	st := ControlStatus{
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
		st.Peers = append(st.Peers, ControlPeer{
			PublicKey: id,
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

// askControl reads the status from a running agent.
//
// The http client is given a dialer that ignores the address and opens the
// socket instead, which is the least surprising way to speak HTTP over a unix
// socket: the URL is a formality and the path is the real destination.
func askControl(ctx context.Context) (ControlStatus, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", controlSocket())
			},
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/status", nil)
	if err != nil {
		return ControlStatus{}, err
	}
	resp, err := client.Do(req)
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
