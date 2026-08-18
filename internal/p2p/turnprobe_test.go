package p2p

// A throwaway probe, run by hand against a real relay:
//
//	NETFLOW_TURN=host:3478 NETFLOW_TURN_SECRET=... go test ./internal/p2p/ -run TestProbeRelay -v
//
// It is a test only because that is the cheapest way to borrow the module's
// dependencies. It skips unless both variables are set.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

func TestProbeRelay(t *testing.T) {
	addr, secret := os.Getenv("NETFLOW_TURN"), os.Getenv("NETFLOW_TURN_SECRET")
	if addr == "" || secret == "" {
		t.Skip("no relay to probe")
	}

	// The long-term credential pion issues: the username is an expiry stamp and
	// the password is its HMAC under the shared secret.
	user := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(user))
	pass := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: addr,
		TURNServerAddr: addr,
		Conn:           conn,
		Username:       user,
		Password:       pass,
		Realm:          "netflow",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.Listen(); err != nil {
		t.Fatalf("listening: %v", err)
	}

	mapped, err := c.SendBindingRequest()
	if err != nil {
		t.Fatalf("STUN binding through %s failed: %v", addr, err)
	}
	t.Logf("STUN says this machine looks like %s", mapped)

	relayed, err := c.Allocate()
	if err != nil {
		t.Fatalf("TURN allocation on %s failed: %v", addr, err)
	}
	defer relayed.Close()
	t.Logf("TURN allocated %s", relayed.LocalAddr())
}
