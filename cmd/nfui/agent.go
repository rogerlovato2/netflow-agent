package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"time"
)

// agentStatus and agentPeer mirror what the agent's control socket answers.
//
// Declared here rather than imported from the agent: this is a separate program
// that speaks to another over a socket, and sharing a struct across that line
// makes it look like one program in two files. The wire format is the contract,
// and a field this does not know about is one it ignores.
type agentStatus struct {
	Address   string      `json:"address"`
	Interface string      `json:"interface"`
	Signal    bool        `json:"signalConnected"`
	Relay     bool        `json:"relayConfigured"`
	Peers     []agentPeer `json:"peers"`
}

type agentPeer struct {
	PublicKey string `json:"publicKey"`
	State     string `json:"state"`
	Path      string `json:"path"`
	RTTMillis int    `json:"rttMs"`
	Handshake int64  `json:"handshake"`
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

// askAgent reads the current status.
//
// A short timeout, because this runs on a two second loop and a request that
// outlives its own interval would pile up behind itself. An agent that cannot
// answer in a second is one this should be drawing as unreachable anyway.
func askAgent() (agentStatus, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath())
			},
		},
		Timeout: time.Second,
	}
	resp, err := client.Get("http://agent/status")
	if err != nil {
		return agentStatus{}, err
	}
	defer resp.Body.Close()

	var st agentStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return agentStatus{}, err
	}
	return st, nil
}
