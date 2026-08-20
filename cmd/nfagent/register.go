package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rogerlovato2/netflow-agent/internal/filter"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rogerlovato2/netflow-agent/internal/engine"
	"github.com/rogerlovato2/netflow-agent/internal/router"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// mapEvery is how often an enrolled agent asks who else is in the mesh.
//
// Polling rather than a push, for now: a poll that is a few seconds late costs
// a few seconds before a new machine is reachable, while a push needs a second
// long-lived connection per agent and a way to recover the updates missed while
// it was down. The interval is what a person waits after enrolling a machine
// before expecting to reach it, which is the only latency that matters here.
const mapEvery = 20 * time.Second

// reportEvery is how often a machine tells the server what it sees.
//
// The server carries none of the mesh's traffic, so this is the only way it
// learns anything: without it the panel can say who enrolled and nothing about
// whether any of them reach each other. Thirty seconds is chosen against how
// long a person stares at a status screen before deciding something is wrong.
const reportEvery = 30 * time.Second

// peerReport is one machine's view of one peer, as the server stores it.
type peerReport struct {
	PeerKey   string `json:"peerKey"`
	State     string `json:"state"`
	Path      string `json:"path"`
	RTTMillis int    `json:"rttMs"`
	RX        uint64 `json:"rx"`
	TX        uint64 `json:"tx"`
	Handshake int64  `json:"handshake"`
}

// reportToServer tells the server what this machine sees, for as long as it runs.
//
// Failures are logged and dropped. A report is a snapshot with a fresh one
// coming in thirty seconds, so retrying a stale one would only overwrite better
// information with worse.
func reportToServer(ctx context.Context, eng *engine.Engine, cfg *Config, log *slog.Logger) {
	t := time.NewTicker(reportEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		rows, err := collectReport(eng)
		if err != nil {
			log.Debug("could not collect the status report", "err", err)
			continue
		}
		if err := postReport(ctx, cfg, rows); err != nil && ctx.Err() == nil {
			log.Debug("could not send the status report", "err", err)
		}
	}
}

// collectReport asks the engine, not the configuration file.
//
// The file is the last map that was written down; the engine is what is
// actually being negotiated and carried. Reading the file here also meant two
// goroutines touching the same slice — one writing it on every map update, the
// other reading it on every report — which is a data race that would have gone
// unnoticed until it corrupted a report.
func collectReport(eng *engine.Engine) ([]peerReport, error) {
	dev, err := eng.Device().Status()
	if err != nil {
		return nil, err
	}
	keys := eng.PeerKeys()
	out := make([]peerReport, 0, len(keys))
	for _, key := range keys {
		id := key.String()
		path := eng.PeerPath(key)
		st := dev[id]
		out = append(out, peerReport{
			PeerKey:   id,
			State:     string(eng.PeerState(key)),
			Path:      path.Kind,
			RTTMillis: int(path.RTT.Milliseconds()),
			RX:        st.RXBytes,
			TX:        st.TXBytes,
			Handshake: st.LastHandshake,
		})
	}
	return out, nil
}

// machineFacts is what only this machine knows: which build is running, what
// it is running on, and what it calls itself.
//
// Sent with every report rather than once at enrolment, because all three
// change without the machine rejoining — an upgrade, a distribution upgrade, a
// rename — and a panel showing the value from the day it joined would be
// confidently wrong.
func machineFacts() map[string]string {
	host, _ := os.Hostname()
	return map[string]string{
		"version":  version,
		"system":   systemName(),
		"hostname": host,
		// Empty when the last attempt was fine, which is also what a machine
		// that has never tried reports.
		"updateError":   updateError(),
		"firewallError": firewallError(),
		// Why this machine could not carry the networks it was given, in its
		// own words. A router that silently fails to forward is one somebody
		// debugs from the far end, wondering why a printer stopped answering.
		"routingError": RoutingError(),
	}
}

func postReport(ctx context.Context, cfg *Config, rows []peerReport) error {
	body, err := json.Marshal(map[string]any{"peers": rows, "machine": machineFacts()})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.Server+"/api/mesh/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the server refused the report: %s", resp.Status)
	}
	return nil
}

// enrol joins the mesh and writes the identity this machine will keep.
//
// The key pair is generated here and the private half never leaves: the server
// is given the public one, allocates an address, and hands back a token. That
// is what keeps a compromised panel from being a compromised tunnel — it can
// list machines and revoke them, and it cannot read a byte of what they say.
func enrol(server, setupKey, name, out string) (*Config, error) {
	if name == "" {
		host, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		name = host
	}

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]string{
		"setupKey":  setupKey,
		"publicKey": priv.PublicKey().String(),
		"name":      name,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server = strings.TrimRight(server, "/")
	url := server + "/api/mesh/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching %s: %w", url, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the server refused the registration: %s: %s",
			resp.Status, strings.TrimSpace(string(raw)))
	}

	var answer struct {
		Address   string       `json:"address"`
		Token     string       `json:"token"`
		SignalURL string       `json:"signalUrl"`
		Relay     *RelayConfig `json:"relay"`
		Peers     []PeerConfig `json:"peers"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("the server's answer did not parse: %w", err)
	}
	if answer.SignalURL == "" {
		return nil, errors.New("the server did not say where to signal; set it in the panel, under settings")
	}

	cfg := &Config{
		PrivateKey: priv.String(),
		Address:    answer.Address,
		SignalURL:  answer.SignalURL,
		Server:     server,
		Token:      answer.Token,
		Relay:      answer.Relay,
		Peers:      answer.Peers,
	}
	if err := ensureConfigDir(out); err != nil {
		return nil, fmt.Errorf("creating %s: %w", out, err)
	}
	if err := saveConfig(out, cfg); err != nil {
		return nil, err
	}

	fmt.Printf("joined the mesh as %s\n", answer.Address)
	return cfg, nil
}

// networkMap is what the server answers.
type networkMap struct {
	Address   string       `json:"address"`
	Subnet    string       `json:"subnet,omitempty"`
	SignalURL string       `json:"signalUrl"`
	Relay     *RelayConfig `json:"relay,omitempty"`
	Peers     []PeerConfig `json:"peers"`
	// Generation is bumped by the server to ask for everything to be
	// negotiated again. Compared with what was last acted on rather than
	// consumed as an event: an agent that was offline while it changed still
	// sees it when it returns.
	Generation int64 `json:"generation"`
	// Update is what the panel says about replacing this binary. The server
	// can ask; it cannot say where the binary comes from, and it cannot make an
	// unsigned one acceptable. Absent means no.
	Update *updatePolicy `json:"update,omitempty"`
	// Advertise is the networks this machine carries for the rest of the mesh.
	// Empty for almost every machine: being a router is a job somebody gives
	// one of them, in the panel.
	Advertise []advertisedRoute `json:"advertise,omitempty"`
}

// advertisedRoute is one network this machine forwards for.
type advertisedRoute struct {
	Network string `json:"network"`
	// Masquerade rewrites the source as traffic leaves towards the network.
	// Almost always on: the machines behind it have never heard of the mesh and
	// would answer a mesh address by asking their gateway, which has not heard
	// of it either.
	Masquerade bool `json:"masquerade"`
}

// updatePolicy is the whole of what the server is allowed to decide.
type updatePolicy struct {
	Enabled bool `json:"enabled"`
	// Version is a tag, or empty for the newest release. It cannot be a URL,
	// and there is nowhere in this struct to put one.
	Version string `json:"version,omitempty"`
}

// lastMap is what the most recent network map said about the peers, kept for
// the control socket to read.
//
// A copy rather than a pointer into the config: the config is rewritten by the
// goroutine that follows the map, and the control socket answers on another.
var lastMap struct {
	sync.Mutex
	byKey map[string]PeerConfig
	all   []PeerConfig
}

func setLastMap(peers []PeerConfig) {
	byKey := make(map[string]PeerConfig, len(peers))
	for _, p := range peers {
		byKey[p.PublicKey] = p
	}
	lastMap.Lock()
	defer lastMap.Unlock()
	lastMap.byKey = byKey
	lastMap.all = append([]PeerConfig(nil), peers...)
}

// lastMapPeers is the whole of the last map, for reconnecting without waiting
// for the next poll.
func lastMapPeers() []PeerConfig {
	lastMap.Lock()
	defer lastMap.Unlock()
	return append([]PeerConfig(nil), lastMap.all...)
}

// paused is whether somebody at this machine asked it to leave the mesh alone.
//
// Not a setting and not remembered: it lives as long as the process does, and
// an agent that comes back after a restart comes back connected. A machine
// that quietly stayed off the mesh across a reboot is a machine somebody will
// spend an afternoon debugging.
var paused atomic.Bool

// Paused says whether the tunnels are down by request.
func Paused() bool { return paused.Load() }

// Pause takes every tunnel down and leaves the agent running.
//
// Goodbye first, so the peers drop this machine now rather than discovering it
// when their negotiation times out. Then an empty peer list, which is the same
// path a machine removed from the map takes: the sessions close, the routes go,
// and WireGuard is left with nothing it will accept a packet from.
func Pause(ctx context.Context, eng *engine.Engine) {
	paused.Store(true)
	eng.Goodbye()
	eng.SetPeers(ctx, nil)
}

// Resume puts back what the last map said, without waiting for the next poll.
func Resume(ctx context.Context, eng *engine.Engine, log *slog.Logger) {
	paused.Store(false)
	peers, err := parsePeers(lastMapPeers())
	if err != nil {
		log.Warn("could not restore the peer list", "err", err)
		return
	}
	eng.SetPeers(ctx, peers)
}

// peerFromMap is what the server last said about one peer. The zero value is
// the honest answer before the first map arrives.
func peerFromMap(publicKey string) PeerConfig {
	lastMap.Lock()
	defer lastMap.Unlock()
	return lastMap.byKey[publicKey]
}

// lastPolicy is what the most recent map said about updates, for the periodic
// check to read. The map is polled every twenty seconds and the check runs
// every six hours; without this the check would have to ask the server itself,
// which is a second way for the same answer to arrive and disagree.
var lastPolicy struct {
	sync.Mutex
	value *updatePolicy
}

func setPolicy(p *updatePolicy) {
	lastPolicy.Lock()
	defer lastPolicy.Unlock()
	lastPolicy.value = p
}

// UpdatePolicy is what the server last asked for.
func UpdatePolicy() *updatePolicy {
	lastPolicy.Lock()
	defer lastPolicy.Unlock()
	return lastPolicy.value
}

// followTheMap keeps the engine's peer list in step with the server's.
//
// A failed poll is logged and nothing else: the peers already configured keep
// working, which is the behaviour worth having — a management server that is
// down should cost new machines, not existing tunnels.
func followTheMap(ctx context.Context, eng *engine.Engine, cfg *Config, rt router.Router, path string, log *slog.Logger) {
	t := time.NewTicker(mapEvery)
	defer t.Stop()

	// Seeded from what was already applied, so an unchanged map after a restart
	// is not announced as news.
	last := mapFingerprint(cfg.Peers)
	setLastMap(cfg.Peers)
	for {
		m, err := fetchMap(ctx, cfg)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("could not fetch the network map", "err", err)
			}
		} else {
			// The signal server can be moved on the server without this agent
			// noticing: the client was built with the URL it started with, and
			// rebuilding it would mean tearing down every negotiation in flight.
			// Saying so is what turns a fleet that silently stops connecting
			// into one line in a log.
			if m.SignalURL != "" && m.SignalURL != cfg.SignalURL {
				log.Warn("the server moved the signal server; this agent is still using the old one",
					"running", cfg.SignalURL, "configured", m.SignalURL,
					"fix", "restart the agent, or re-register it")
			}
			// Applied on every map and not only when the peer list changes: the
			// credential expires, so a machine holding the first one it was
			// given would lose the ability to relay a day later — and would
			// look like a NAT problem when it did.
			//
			// Kept in the file too. That copy is worth exactly one day of the
			// management server being unreachable, which is precisely when a
			// machine most needs the relay it already knows about.
			if m.Relay != nil {
				eng.SetRelay(m.Relay.URL, m.Relay.Username, m.Relay.Password)
				if cfg.Relay == nil || *cfg.Relay != *m.Relay {
					cfg.Relay = m.Relay
					if err := saveConfig(path, cfg); err != nil {
						log.Debug("could not save the relay credential", "err", err)
					}
				}
			}

			setPolicy(m.Update)
			// Acted on as it arrives, not only on the six-hourly tick: a
			// request made in the panel is somebody watching the row and
			// waiting for it to change.
			go considerUpdate(ctx, eng, cfg, m.Update, log)

			// Two things the server can change about this machine that it
			// cannot adopt in place.
			//
			// Its own address is written into the interface and into every
			// peer's AllowedIPs on the other side; changing it means rebuilding
			// the interface, which means starting over. The generation is the
			// server asking for exactly that for its own reasons. Both are
			// handled the same way, and the same way `up` would handle them:
			// stop, and let the service manager start again. A process that
			// tried to rebuild itself in place would be reimplementing what the
			// service manager already does correctly.
			// The subnet is written into the routing table when the interface
			// comes up, so a change to it is the same kind of change as the
			// address: not adoptable in place.
			if m.Subnet != "" && m.Subnet != cfg.Subnet {
				log.Info("the server changed the mesh subnet; restarting",
					"from", cfg.Subnet, "to", m.Subnet)
				cfg.Subnet = m.Subnet
				if err := saveConfig(path, cfg); err != nil {
					log.Warn("could not save the new subnet", "err", err)
				}
				restart(eng)
				return
			}
			if m.Address != "" && m.Address != cfg.Address {
				log.Info("the server moved this machine; restarting",
					"from", cfg.Address, "to", m.Address)
				cfg.Address = m.Address
				// The generation from this same map is adopted here, not left
				// for the next process to discover. Moving a machine bumps it,
				// so a restart that carried only the address came back up, read
				// the identical map, found a generation it had never recorded
				// and restarted a second time — two service restarts and the
				// delay between them for one change, while every peer sat
				// negotiating with a machine that kept disappearing.
				if m.Generation > cfg.Generation {
					cfg.Generation = m.Generation
				}
				if err := saveConfig(path, cfg); err != nil {
					log.Warn("could not save the new address", "err", err)
				}
				restart(eng)
				return
			}
			if m.Generation > cfg.Generation {
				log.Info("the server asked for a reconnect; restarting",
					"generation", m.Generation)
				cfg.Generation = m.Generation
				if err := saveConfig(path, cfg); err != nil {
					log.Warn("could not save the generation", "err", err)
				}
				restart(eng)
				return
			}

			peers, perr := parsePeers(m.Peers)
			if perr != nil {
				log.Warn("the network map did not parse", "err", perr)
			} else {
				// Compared before applying, so an unchanged map is not reported
				// as an event every twenty seconds. SetPeers is a reconcile and
				// would do no harm; the log would.
				// The access rules go in with the peer list and from the same
				// map, so that what a machine allows and who it talks to can
				// never be two different versions of the truth.
				applyAccessRules(eng, m.Peers, log)
				setLastMap(m.Peers)

				if fingerprint := mapFingerprint(m.Peers); fingerprint != last {
					log.Info("network map updated", "peers", len(peers))
					last = fingerprint
					// Written back so the next start has it. A cache that is
					// never refreshed goes stale exactly when it is needed:
					// after the machine has been away long enough for the mesh
					// to have moved on.
					cfg.Peers = m.Peers
					if err := saveConfig(path, cfg); err != nil {
						log.Warn("could not save the network map", "err", err)
					}
				}
				applyAdvertised(rt, eng, cfg, m.Advertise, log)

				if paused.Load() {
					// The map is still followed and still saved — only not
					// applied. Reconnecting then costs nothing but a call.
					eng.SetPeers(ctx, nil)
				} else {
					eng.SetPeers(ctx, peers)
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func fetchMap(ctx context.Context, cfg *Config) (networkMap, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Server+"/api/mesh/map", nil)
	if err != nil {
		return networkMap{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return networkMap{}, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return networkMap{}, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var m networkMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return networkMap{}, err
	}
	return m, nil
}

// saveConfig rewrites the file with the peer list it now holds.
//
// Written whole rather than patched: the file is small, and a partial write
// that lost the private key would cost the machine its identity.
func saveConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// mapFingerprint is enough to tell one peer list from another.
func mapFingerprint(peers []PeerConfig) string {
	var b strings.Builder
	for _, p := range peers {
		b.WriteString(p.PublicKey)
		b.WriteByte(' ')
		b.WriteString(strings.Join(p.AllowedIPs, ","))
		b.WriteByte(' ')
		b.WriteString(p.Name)
		b.WriteByte('\n')
	}
	return b.String()
}

// restart ends this process so the service manager starts a fresh one.
//
// Rebuilding an interface, its address and every tunnel from inside a running
// process is possible and is a great deal of state to get right — and both
// systemd and launchd already do it correctly, on every platform, with backoff.
// Exiting non-zero is how a program asks them to.
//
// A machine running `nfagent up` by hand does not get restarted, and sees the
// reason on the way out.
func restart(eng *engine.Engine) {
	// Said before going, so the peers drop this machine now instead of checking
	// against an agent that is already gone until their negotiation times out.
	eng.Goodbye()
	fmt.Fprintln(os.Stderr,
		"restarting to apply a change from the server; the service manager will start it again")
	os.Exit(1)
}

// lastFirewallError is what this machine says about applying its rules.
//
// Reported rather than only logged: a machine that cannot apply a rule is a
// machine where a one-way policy is two-way, and the panel is where somebody
// would look to find out which machine that is.
var lastFirewallError struct {
	sync.Mutex
	text string
}

func setFirewallError(err error) {
	lastFirewallError.Lock()
	defer lastFirewallError.Unlock()
	if err == nil {
		lastFirewallError.text = ""
		return
	}
	lastFirewallError.text = err.Error()
}

func firewallError() string {
	lastFirewallError.Lock()
	defer lastFirewallError.Unlock()
	return lastFirewallError.text
}

// applyAccessRules hands the engine what each peer may start.
// applyAdvertised makes this machine forward for what the server asked, and
// stop forwarding for anything it did not.
//
// The whole list every time, including an empty one. A machine that was a
// router and is not any more has to stop being one, and the only way to know
// that from a list of what it should carry is to act on the whole list.
func applyAdvertised(rt router.Router, eng *engine.Engine, cfg *Config,
	advertised []advertisedRoute, log *slog.Logger) {
	routes := make([]router.Route, 0, len(advertised))
	for _, a := range advertised {
		prefix, err := netip.ParsePrefix(a.Network)
		if err != nil {
			log.Warn("the server sent a network that does not parse",
				"network", a.Network, "err", err)
			continue
		}
		routes = append(routes, router.Route{Network: prefix, Masquerade: a.Masquerade})
	}

	// Nothing asked for and nothing configured: the common case, and worth not
	// touching the firewall for.
	if len(routes) == 0 && !routing.Load() {
		return
	}

	mesh, err := netip.ParsePrefix(cfg.Subnet)
	if err != nil {
		// Without the mesh's own prefix there is no way to tell traffic that
		// arrived over the tunnel from this machine's own, and rules that
		// cannot tell them apart would rewrite both.
		log.Warn("cannot carry a network without knowing the mesh subnet",
			"subnet", cfg.Subnet, "err", err)
		return
	}

	if err := rt.Apply(eng.Device().Name(), mesh, routes); err != nil {
		setRoutingError(err)
		log.Warn("could not carry the networks the server asked for", "err", err)
		return
	}
	setRoutingError(nil)
	routing.Store(len(routes) > 0)
	if len(routes) > 0 {
		log.Info("carrying networks for the mesh", "count", len(routes))
	} else {
		log.Info("no longer carrying any network for the mesh")
	}
}

// routing is whether this machine currently forwards for anything, so that
// going back to none is applied once rather than on every poll.
var routing atomic.Bool

// lastRoutingError is why this machine could not carry what it was asked to,
// in its own words, for the panel to show. A machine that silently fails to
// forward is one somebody debugs from the far end.
var lastRoutingError struct {
	sync.Mutex
	value string
}

func setRoutingError(err error) {
	lastRoutingError.Lock()
	defer lastRoutingError.Unlock()
	if err == nil {
		lastRoutingError.value = ""
		return
	}
	lastRoutingError.value = err.Error()
}

// RoutingError is the last reason this machine could not carry a network.
func RoutingError() string {
	lastRoutingError.Lock()
	defer lastRoutingError.Unlock()
	return lastRoutingError.value
}

func applyAccessRules(eng *engine.Engine, peers []PeerConfig, log *slog.Logger) {
	rules := make(map[netip.Addr][]filter.Rule, len(peers))
	for _, p := range peers {
		addr := p.Address
		if addr == "" && len(p.AllowedIPs) > 0 {
			// An older server sends only the allowed IPs, whose first entry is
			// the peer's own address.
			addr, _, _ = strings.Cut(p.AllowedIPs[0], "/")
		}
		a, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		// Nil and empty mean different things here: a peer with no rules may
		// start nothing, and it has to be in the map for the filter to know
		// that rather than fall through to "not mentioned".
		if p.Inbound == nil {
			rules[a] = []filter.Rule{}
			continue
		}
		rules[a] = p.Inbound
	}

	if err := eng.SetAccessRules(rules); err != nil {
		setFirewallError(err)
		log.Warn("could not apply the access rules", "err", err)
		return
	}
	setFirewallError(nil)
}
