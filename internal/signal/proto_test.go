package signal

import (
	"bytes"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// keypair returns a WireGuard private key and its public key.
func keypair(t *testing.T) (priv, pub wgtypes.Key) {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k, k.PublicKey()
}

func TestSealOpenRoundTrip(t *testing.T) {
	aPriv, aPub := keypair(t)
	bPriv, bPub := keypair(t)

	want := Body{UFrag: "ufrag123", Pwd: "a-password-long-enough", Candidate: "candidate:1 1 udp 2130706431 192.168.1.5 51820 typ host"}

	sealed, err := Seal(want, aPriv, bPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(sealed, bPriv, aPub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != want {
		t.Errorf("round trip changed the body:\n got %+v\nwant %+v", got, want)
	}
}

// The sealed bytes must not leak the plaintext. This is the whole reason the
// signal server can be untrusted, so it is worth asserting rather than assuming.
func TestSealHidesPlaintext(t *testing.T) {
	aPriv, _ := keypair(t)
	_, bPub := keypair(t)

	const secret = "candidate:9 1 udp 1686052607 203.0.113.7 41234 typ srflx"
	sealed, err := Seal(Body{Candidate: secret}, aPriv, bPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, []byte(secret)) {
		t.Error("the candidate appears in clear inside the sealed body")
	}
	if bytes.Contains(sealed, []byte("candidate")) {
		t.Error("the JSON field names appear in clear inside the sealed body")
	}
}

// A third peer holding a valid key of its own must not be able to open a body
// addressed to someone else.
func TestOpenRejectsWrongRecipient(t *testing.T) {
	aPriv, aPub := keypair(t)
	_, bPub := keypair(t)
	cPriv, _ := keypair(t)

	sealed, err := Seal(Body{UFrag: "secret"}, aPriv, bPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(sealed, cPriv, aPub); err != ErrOpenFailed {
		t.Errorf("a third peer opened the body: err = %v, want %v", err, ErrOpenFailed)
	}
}

// Claiming to be someone else does not work either: the body only opens against
// the real sender's public key.
func TestOpenRejectsWrongSender(t *testing.T) {
	aPriv, _ := keypair(t)
	bPriv, bPub := keypair(t)
	_, impostorPub := keypair(t)

	sealed, err := Seal(Body{UFrag: "secret"}, aPriv, bPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(sealed, bPriv, impostorPub); err != ErrOpenFailed {
		t.Errorf("the body opened against the wrong sender: err = %v, want %v", err, ErrOpenFailed)
	}
}

// A flipped bit has to fail, not decode into something plausible. Box is
// authenticated, so this is really a check that we did not strip the tag.
func TestOpenRejectsTamperedBody(t *testing.T) {
	aPriv, aPub := keypair(t)
	bPriv, bPub := keypair(t)

	sealed, err := Seal(Body{UFrag: "ufrag", Pwd: "pwd"}, aPriv, bPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed[len(sealed)-1] ^= 0x01

	if _, err := Open(sealed, bPriv, aPub); err != ErrOpenFailed {
		t.Errorf("a tampered body opened: err = %v, want %v", err, ErrOpenFailed)
	}
}

func TestOpenRejectsShortBody(t *testing.T) {
	priv, pub := keypair(t)
	for _, n := range []int{0, 1, nonceLen - 1, nonceLen} {
		if _, err := Open(make([]byte, n), priv, pub); err != ErrNotSealed {
			t.Errorf("len %d: err = %v, want %v", n, err, ErrNotSealed)
		}
	}
}

// Two seals of the same body must differ, or the nonce is not doing its job.
func TestSealIsNotDeterministic(t *testing.T) {
	aPriv, _ := keypair(t)
	_, bPub := keypair(t)

	b := Body{UFrag: "same", Pwd: "same"}
	first, err := Seal(b, aPriv, bPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := Seal(b, aPriv, bPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Error("two seals of the same body are identical; the nonce is being reused")
	}
}
