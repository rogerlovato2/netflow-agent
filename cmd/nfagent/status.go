package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// status reports what this machine last told the server.
//
// It reads the file rather than asking the running agent, which means it says
// who the peers are and not whether they are reachable right now. Asking the
// agent needs a control socket, and a socket is a thing to secure, name and
// keep compatible — worth doing when there is something to ask that the file
// cannot answer.
func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath(), "where the identity is kept")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A running agent is asked first. It knows what the file cannot: whether
	// each peer is actually reachable this second, by what path, and how far
	// away it is. The file only ever says who the peers are supposed to be.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if live, err := askControl(ctx); err == nil {
		return printLive(live)
	}

	cfg, err := loadConfig(*path)
	if err != nil {
		return fmt.Errorf("this machine has not joined a mesh yet (%s)", *path)
	}
	fmt.Println("the agent is not running; this is the last configuration it was given")
	fmt.Println()
	fmt.Printf("address    %s\n", cfg.Address)
	fmt.Printf("server     %s\n", cfg.Server)
	fmt.Printf("signal     %s\n", cfg.SignalURL)
	fmt.Printf("peers      %d\n", len(cfg.Peers))
	return nil
}

// setPaused asks a running agent to take its tunnels down, or put them back.
//
// It is not a setting: nothing is written, and an agent that restarts comes
// back connected. A machine that quietly stayed off the mesh across a reboot is
// a machine somebody will spend an afternoon debugging.
func setPaused(pause bool) error {
	what := "resume"
	if pause {
		what = "pause"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tellControl(ctx, "/"+what); err != nil {
		return fmt.Errorf("the agent did not answer (%w); is it running?", err)
	}
	if pause {
		fmt.Println("the tunnels are down; `nfagent resume` puts them back")
	} else {
		fmt.Println("back on the mesh")
	}
	return nil
}

func printLive(st ControlStatus) error {
	if st.Paused {
		fmt.Println("paused: the tunnels are down by request (`nfagent resume` puts them back)")
		fmt.Println()
	}
	fmt.Printf("address    %s\n", st.Address)
	fmt.Printf("interface  %s\n", orNone(st.Interface, "userspace, invisible to this machine"))
	fmt.Printf("signal     %s\n", connected(st.Signal))
	fmt.Printf("relay      %s\n", configured(st.Relay))
	fmt.Printf("server     %s\n", st.Server)

	if len(st.Peers) == 0 {
		fmt.Println("\nno peers yet")
		return nil
	}
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PEER\tADDRESS\tSTATE\tPATH\tRTT\tHANDSHAKE\tRX\tTX")
	for _, p := range st.Peers {
		// The name the panel gave it, and the key when the agent has not seen a
		// map yet. A truncated key identifies a peer to the machine and to
		// nobody else.
		key := p.Name
		if key == "" {
			key = p.PublicKey
			if len(key) > 12 {
				key = key[:12] + "\u2026"
			}
		}
		rtt := "-"
		if p.RTTMillis > 0 {
			rtt = fmt.Sprintf("%dms", p.RTTMillis)
		}
		hs := "never"
		if p.Handshake > 0 {
			hs = time.Since(time.Unix(p.Handshake, 0)).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			key, orNone(p.Address, "-"), p.State, orNone(p.Path, "-"), rtt, hs, p.RX, p.TX)
	}
	return w.Flush()
}

func orNone(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func connected(b bool) string {
	if b {
		return "connected"
	}
	return "not connected"
}

func configured(b bool) string {
	if b {
		return "configured"
	}
	return "none: a pair with no direct path will fail"
}
