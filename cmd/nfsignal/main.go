// Command nfsignal is the signalling server: it forwards sealed envelopes
// between peers that are trying to find a path to each other.
//
// It holds no database, no keys and no state that survives a restart. A peer
// that was connected reconnects and renegotiates, which is the same thing it
// does after any network change — so restarting this process costs a few
// seconds of reconnect and nothing else.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	// os/signal is aliased, not this package: `signal.NewServer` is what the
	// rest of the file is about, and it should read as itself.
	ossignal "os/signal"

	"github.com/rogerlovato2/netflow-agent/internal/signal"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", envOr("NFSIGNAL_LISTEN", "0.0.0.0:8081"),
		"address to listen on")
	flag.Parse()

	level := slog.LevelInfo
	if v, ok := os.LookupEnv("NFSIGNAL_DEBUG"); ok && v != "" && v != "0" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := ossignal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := signal.NewServer(log)

	mux := http.NewServeMux()
	mux.Handle("GET /signal", srv.Handler())
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprintf(w, `{"ok":true,"peers":%d}`+"\n", srv.Peers())
	})

	hs := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: every connection here is a long-lived WebSocket, and
		// a write deadline would cut them at a fixed age for no reason.
	}

	log.Info("nfsignal is up", "listen", *listen)

	errCh := make(chan error, 1)
	go func() {
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
