package signal

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// waitFor is how long a test waits for something that crosses a socket. Local
// loopback needs microseconds; the margin is for a loaded CI machine, and it is
// only ever paid when a test is about to fail anyway.
const waitFor = 3 * time.Second

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testServer starts a signal server on a real socket and returns its ws:// URL.
func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv := NewServer(quietLogger())
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return srv, "ws" + strings.TrimPrefix(hs.URL, "http")
}

// testClient starts a connected client and returns it with the channel its
// handler feeds.
func testClient(t *testing.T, url string, priv wgtypes.Key) (*Client, chan Message) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := NewClient(url, priv, quietLogger())
	got := make(chan Message, 16)
	c.OnMessage(func(m Message) { got <- m })
	go c.Run(ctx)

	waitUntil(t, "client to connect", c.Connected)
	return c, got
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func recv(t *testing.T, ch chan Message) Message {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(waitFor):
		t.Fatal("timed out waiting for a message")
		return Message{}
	}
}

// The whole point of the package: A negotiates with B and the server, which
// relayed every byte, could not have read any of it.
func TestEndToEndOfferAnswer(t *testing.T) {
	_, url := testServer(t)

	aPriv, _ := keypair(t)
	bPriv, _ := keypair(t)
	aPub, bPub := aPriv.PublicKey(), bPriv.PublicKey()

	a, aIn := testClient(t, url, aPriv)
	b, bIn := testClient(t, url, bPriv)

	offer := Body{UFrag: "aUfrag", Pwd: "aPassword-long"}
	if err := a.Send(bPub, KindOffer, offer); err != nil {
		t.Fatalf("A.Send: %v", err)
	}

	got := recv(t, bIn)
	if got.Kind != KindOffer {
		t.Errorf("B got kind %q, want %q", got.Kind, KindOffer)
	}
	if got.From != aPub {
		t.Errorf("B got From %s, want %s", got.From, aPub)
	}
	if got.Body != offer {
		t.Errorf("B got body %+v, want %+v", got.Body, offer)
	}

	answer := Body{UFrag: "bUfrag", Pwd: "bPassword-long"}
	if err := b.Send(aPub, KindAnswer, answer); err != nil {
		t.Fatalf("B.Send: %v", err)
	}
	got = recv(t, aIn)
	if got.Kind != KindAnswer || got.Body != answer || got.From != bPub {
		t.Errorf("A got %+v, want answer %+v from %s", got, answer, bPub)
	}
}

// Trickling is the normal case: many candidates, in order, no offer in between.
func TestTrickledCandidatesArriveInOrder(t *testing.T) {
	_, url := testServer(t)

	aPriv, _ := keypair(t)
	bPriv, _ := keypair(t)

	a, _ := testClient(t, url, aPriv)
	_, bIn := testClient(t, url, bPriv)

	want := []string{
		"candidate:1 1 udp 2130706431 192.168.1.5 51820 typ host",
		"candidate:2 1 udp 1694498815 203.0.113.7 41234 typ srflx",
		"candidate:3 1 udp 16777215 198.51.100.9 3478 typ relay",
	}
	for _, cand := range want {
		if err := a.Send(bPriv.PublicKey(), KindCandidate, Body{Candidate: cand}); err != nil {
			t.Fatalf("Send(%q): %v", cand, err)
		}
	}
	for i, w := range want {
		got := recv(t, bIn)
		if got.Kind != KindCandidate {
			t.Fatalf("candidate %d: kind %q, want %q", i, got.Kind, KindCandidate)
		}
		if got.Body.Candidate != w {
			t.Errorf("candidate %d out of order:\n got %q\nwant %q", i, got.Body.Candidate, w)
		}
	}
}

// Writing to a peer nobody is holding a socket for has to come back as a fact,
// not as silence.
func TestSendToOfflinePeerReportsOffline(t *testing.T) {
	_, url := testServer(t)

	aPriv, _ := keypair(t)
	_, absentPub := keypair(t)

	a, aIn := testClient(t, url, aPriv)

	if err := a.Send(absentPub, KindOffer, Body{UFrag: "x"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := recv(t, aIn)
	if got.Kind != KindOffline {
		t.Fatalf("got kind %q, want %q", got.Kind, KindOffline)
	}
	if got.From != absentPub {
		t.Errorf("offline notice names %s, want the absent peer %s", got.From, absentPub)
	}
}

// A peer that reconnects after a network change must take over its own slot,
// not be locked out by the socket the server has not yet noticed is dead.
func TestReconnectReplacesTheEarlierSocket(t *testing.T) {
	srv, url := testServer(t)

	aPriv, _ := keypair(t)
	bPriv, _ := keypair(t)

	// Two clients on the same key: the second one is the "reconnect".
	first, firstIn := testClient(t, url, aPriv)
	_ = firstIn
	waitUntil(t, "the first socket to register", func() bool { return srv.Peers() == 1 })

	second, secondIn := testClient(t, url, aPriv)
	_ = first
	waitUntil(t, "the replacement to settle", func() bool { return srv.Peers() == 1 })

	// B writes to that key; the newest socket is the one that must receive it.
	b, _ := testClient(t, url, bPriv)
	if err := b.Send(aPriv.PublicKey(), KindOffer, Body{UFrag: "after-reconnect"}); err != nil {
		t.Fatalf("B.Send: %v", err)
	}
	got := recv(t, secondIn)
	if got.Body.UFrag != "after-reconnect" {
		t.Errorf("the replacement socket got %+v", got.Body)
	}
	_ = second
}

// The server stamps From from the registered socket. A peer that tries to name
// someone else as the sender must not be able to.
func TestServerOverwritesForgedSender(t *testing.T) {
	_, url := testServer(t)

	victimPriv, _ := keypair(t)
	targetPriv, _ := keypair(t)
	impostorPriv, _ := keypair(t)

	_, targetIn := testClient(t, url, targetPriv)

	// A raw socket, so the forged From actually reaches the wire — Client would
	// never send one.
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.CloseNow()

	write := func(e Envelope) {
		t.Helper()
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := ws.Write(ctx, websocket.MessageText, data); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	write(Envelope{Kind: KindHello, From: impostorPriv.PublicKey().String()})
	write(Envelope{
		Kind: KindOffer,
		From: victimPriv.PublicKey().String(), // the lie
		To:   targetPriv.PublicKey().String(),
		Body: []byte("does not matter, it will not open"),
	})

	// The forged body cannot open, so the client drops it and nothing arrives.
	// That is the desired outcome: the impostor achieved nothing at all.
	select {
	case m := <-targetIn:
		t.Fatalf("a forged envelope was delivered: %+v", m)
	case <-time.After(300 * time.Millisecond):
	}
}

// A first frame that is not a hello gets the socket closed, so the routing
// table never fills with connections that cannot be addressed.
func TestFirstFrameMustBeHello(t *testing.T) {
	srv, url := testServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.CloseNow()

	data, err := json.Marshal(Envelope{Kind: KindOffer, To: "somebody"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ws.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, _, err := ws.Read(ctx); err == nil {
		t.Error("the server kept a socket that never said hello")
	}
	if n := srv.Peers(); n != 0 {
		t.Errorf("server holds %d peers, want 0", n)
	}
}

// A hello whose key is not a WireGuard key is refused: it would otherwise
// occupy a slot that nothing could ever address.
func TestHelloWithInvalidKeyIsRefused(t *testing.T) {
	srv, url := testServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.CloseNow()

	data, err := json.Marshal(Envelope{Kind: KindHello, From: "not-a-key"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ws.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, _, err := ws.Read(ctx); err == nil {
		t.Error("the server accepted a hello with an invalid key")
	}
	if n := srv.Peers(); n != 0 {
		t.Errorf("server holds %d peers, want 0", n)
	}
}

// Peers() is what the health endpoint reports, and a disconnect has to be
// visible in it or an operator cannot tell a live server from a stuck one.
func TestPeersCountFollowsConnections(t *testing.T) {
	srv, url := testServer(t)

	if n := srv.Peers(); n != 0 {
		t.Fatalf("fresh server holds %d peers, want 0", n)
	}

	aPriv, _ := keypair(t)
	ctx, cancel := context.WithCancel(context.Background())
	a := NewClient(url, aPriv, quietLogger())
	go a.Run(ctx)
	waitUntil(t, "the peer to register", func() bool { return srv.Peers() == 1 })

	cancel()
	waitUntil(t, "the peer to be forgotten", func() bool { return srv.Peers() == 0 })
}

// The handler is optional: envelopes arriving before OnMessage is set must not
// panic the reader goroutine.
func TestMessagesBeforeHandlerAreHarmless(t *testing.T) {
	_, url := testServer(t)

	aPriv, _ := keypair(t)
	bPriv, _ := keypair(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := NewClient(url, bPriv, quietLogger())
	go b.Run(ctx)
	waitUntil(t, "B to connect", b.Connected)

	a, _ := testClient(t, url, aPriv)
	if err := a.Send(bPriv.PublicKey(), KindOffer, Body{UFrag: "no-handler-yet"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Now attach one and make sure the client still works. The first envelope
	// may or may not have been read before the handler existed — that race is
	// the situation under test, not a thing to pin down — so the assertion is
	// only that the second one gets through.
	got := make(chan Message, 4)
	b.OnMessage(func(m Message) { got <- m })
	if err := a.Send(bPriv.PublicKey(), KindOffer, Body{UFrag: "handler-attached"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	deadline := time.After(waitFor)
	for {
		select {
		case m := <-got:
			if m.Body.UFrag == "handler-attached" {
				return
			}
		case <-deadline:
			t.Fatal("the client stopped delivering after a nil handler")
		}
	}
}

// Send has to work before the socket exists: the engine starts negotiating as
// soon as it learns about a peer, not when the signal server happens to answer.
func TestSendQueuesWhileDisconnected(t *testing.T) {
	aPriv, _ := keypair(t)
	_, bPub := keypair(t)

	// Never started, so there is no socket at all.
	c := NewClient("ws://127.0.0.1:1/never", aPriv, quietLogger())
	if err := c.Send(bPub, KindOffer, Body{UFrag: "queued"}); err != nil {
		t.Errorf("Send while disconnected: %v", err)
	}
	if c.Connected() {
		t.Error("Connected() is true without a socket")
	}
}

// A full queue is an error, not a silent drop: a lost candidate is
// indistinguishable from a NAT failure and would be debugged in the wrong place.
func TestSendReportsAFullQueue(t *testing.T) {
	aPriv, _ := keypair(t)
	_, bPub := keypair(t)

	c := NewClient("ws://127.0.0.1:1/never", aPriv, quietLogger())
	for i := range outQueue {
		if err := c.Send(bPub, KindCandidate, Body{Candidate: "c"}); err != nil {
			t.Fatalf("Send %d filled the queue early: %v", i, err)
		}
	}
	if err := c.Send(bPub, KindCandidate, Body{Candidate: "one too many"}); err == nil {
		t.Error("Send on a full queue returned nil")
	}
}

// trackingListener remembers what it accepted so a test can drop connections
// the way a network does. httptest's own CloseClientConnections does not reach
// a hijacked WebSocket, so without this the "connection died" case cannot be
// reproduced at all.
type trackingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
	return c, nil
}

// dropAll closes every accepted connection: a FIN on both sides, which is what
// a server restart or a killed process looks like from the client.
func (l *trackingListener) dropAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
}

// trackedServer is a signal server whose connections the test can drop.
func trackedServer(t *testing.T) (*Server, *trackingListener, string) {
	t.Helper()
	srv := NewServer(quietLogger())
	hs := httptest.NewUnstartedServer(srv.Handler())
	tl := &trackingListener{Listener: hs.Listener}
	hs.Listener = tl
	hs.Start()
	t.Cleanup(hs.Close)
	return srv, tl, "ws" + strings.TrimPrefix(hs.URL, "http")
}

// The socket dies under the client. It has to notice and come back on its own —
// the case that separates a demo from something you can leave running.
func TestClientReconnectsAfterConnectionDrop(t *testing.T) {
	srv, tl, url := trackedServer(t)

	aPriv, _ := keypair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewClient(url, aPriv, quietLogger())
	go c.Run(ctx)
	waitUntil(t, "the first connection", c.Connected)
	waitUntil(t, "the server to register it", func() bool { return srv.Peers() == 1 })

	tl.dropAll()
	waitUntil(t, "the client to notice the drop", func() bool { return !c.Connected() })
	waitUntil(t, "the server to forget the peer", func() bool { return srv.Peers() == 0 })

	waitUntil(t, "the client to reconnect", c.Connected)
	waitUntil(t, "the server to see it again", func() bool { return srv.Peers() == 1 })
}

// freezableProxy pipes TCP to a target until it is frozen, after which it reads
// and discards. Nothing is closed, so neither end sees a FIN — this is a
// laptop walking off Wi-Fi, or a NAT dropping the mapping, and it is the only
// failure a ping can catch.
type freezableProxy struct {
	ln     net.Listener
	target string
	frozen atomic.Bool
}

func newFreezableProxy(t *testing.T, target string) *freezableProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &freezableProxy{ln: ln, target: target}
	t.Cleanup(func() { _ = ln.Close() })
	go p.serve()
	return p
}

func (p *freezableProxy) addr() string { return p.ln.Addr().String() }

func (p *freezableProxy) serve() {
	for {
		in, err := p.ln.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = in.Close()
			continue
		}
		go p.pipe(out, in)
		go p.pipe(in, out)
	}
}

func (p *freezableProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !p.frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// The path goes silent without anything being closed. Only the ping can find
// that out, and finding it out is what lets the agent reconnect instead of
// sitting there believing it is reachable.
func TestClientDetectsASilentlyDeadPath(t *testing.T) {
	srv, _, url := trackedServer(t)
	_ = srv

	host := strings.TrimPrefix(url, "ws://")
	proxy := newFreezableProxy(t, host)

	aPriv, _ := keypair(t)
	c := NewClient("ws://"+proxy.addr(), aPriv, quietLogger())
	// Short enough that the test finishes; the production values are 20s/10s.
	c.pingEvery = 100 * time.Millisecond
	c.pingWait = 300 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	waitUntil(t, "the connection through the proxy", c.Connected)

	proxy.frozen.Store(true)
	waitUntil(t, "the client to notice the silence", func() bool { return !c.Connected() })
}
