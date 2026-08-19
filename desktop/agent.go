package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"
)

// What the agent's control socket answers.
//
// Declared here rather than imported from the agent: this is a separate program
// speaking to another over a socket, and sharing a struct across that line
// would make two programs look like one. The wire format is the contract, and a
// field this does not know about is a field it ignores.
type Status struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	PublicKey string `json:"publicKey"`
	Server    string `json:"server"`
	SignalURL string `json:"signalUrl"`
	Signal    bool   `json:"signalConnected"`
	Relay     bool   `json:"relayConfigured"`
	Peers     []Peer `json:"peers"`

	// Reachable is this program's own reading, not the agent's: it is false
	// when there was nobody to ask.
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
	Version   string `json:"version,omitempty"`
}

type Peer struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
	Address   string `json:"address"`
	State     string `json:"state"`
	Path      string `json:"path"`
	RTTMillis int    `json:"rttMs"`
	Handshake int64  `json:"handshake"`
	RX        uint64 `json:"rx"`
	TX        uint64 `json:"tx"`
}

func socketPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/run/netflow-agent.sock"
	case "windows":
		return `\\.\pipe\netflow-agent`
	default:
		return "/run/netflow/agent.sock"
	}
}

// client speaks to whatever the agent listens on, which is a unix socket
// everywhere except Windows, where it is a named pipe. Both are local and
// neither is a network address — the URL below exists only because this speaks
// HTTP over it.
func client() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialAgent(ctx, socketPath())
			},
		},
	}
}

func fetchStatus(ctx context.Context) Status {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/status", nil)
	if err != nil {
		return Status{Error: err.Error()}
	}
	resp, err := client().Do(req)
	if err != nil {
		// The ordinary case, and not an error worth shouting about: the agent
		// is not running, or this user may not talk to it.
		return Status{Error: friendly(err)}
	}
	defer resp.Body.Close()

	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return Status{Error: fmt.Sprintf("the agent answered something unreadable: %v", err)}
	}
	st.Reachable = true
	return st
}

// friendly turns a dial error into the thing to go and do.
func friendly(err error) string {
	switch {
	case isPermission(err):
		return "this account is not allowed to talk to the agent"
	case isMissing(err):
		return "the agent is not running"
	default:
		return err.Error()
	}
}
