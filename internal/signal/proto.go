// Package signal exchanges ICE connection data between two peers that have no
// way to reach each other yet.
//
// The server is deliberately dumb: it holds one WebSocket per peer, indexed by
// WireGuard public key, and forwards an envelope to whoever the To field names.
// It never sees the contents — the body is sealed with NaCl box using the
// sender's WireGuard private key and the recipient's public key, which works
// because a WireGuard key *is* a Curve25519 key and that is exactly what box
// wants. Whoever runs the signal server, or breaks into one, learns who talks
// to whom and nothing else.
//
// That is the whole security model, and it is worth being explicit about what
// it does not cover: nothing here proves that the peer announcing a public key
// owns the matching private key. An impostor can occupy someone else's slot and
// deny them service, but cannot read or forge a single body — every payload it
// relays stays sealed to a key it does not have. Closing that hole is the
// management server's job: it hands each peer a token at registration, and the
// signal server checks the token before accepting the key.
package signal

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Kind is what an envelope is for.
type Kind string

const (
	// KindHello is the first frame a peer sends, and the only one whose From is
	// about the sender rather than about a conversation: it claims a slot in the
	// server's routing table. Making registration an ordinary frame instead of a
	// query parameter keeps the public key out of proxy logs and out of the URL
	// that a browser or a crash reporter would happily record.
	KindHello Kind = "hello"

	// KindOffline is the server's answer when To is nobody it holds a
	// connection for. Reporting it beats dropping the envelope: the sender
	// learns to wait for the peer to come up instead of retrying into a void,
	// and a peer that is genuinely down stops costing a negotiation timeout.
	KindOffline Kind = "offline"

	// KindOffer opens a negotiation: the sender is ready and publishes the ICE
	// credentials the other side needs to answer.
	KindOffer Kind = "offer"

	// KindAnswer accepts an offer. Keeping answer separate from offer is what
	// stops two peers that dial each other at the same instant from running two
	// independent ICE sessions and picking different pairs.
	KindAnswer Kind = "answer"

	// KindCandidate carries a single ICE candidate, sent the moment it is
	// found. Trickling matters here: waiting for gathering to finish before
	// sending anything adds the slowest STUN server's timeout to every
	// connection, and the host candidates that are usually enough on a LAN are
	// known immediately.
	KindCandidate Kind = "candidate"

	// KindBye tears the session down. Without it the other side keeps a dead
	// ICE agent alive until its own timeout, and a peer that restarts is unable
	// to reconnect until that expires.
	KindBye Kind = "bye"
)

// Envelope is what crosses the wire. Only the routing fields are readable by
// the server; Body is sealed for the peer named in To.
type Envelope struct {
	Kind Kind   `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
	Body []byte `json:"body,omitempty"`
}

// Body is the part the server cannot read.
type Body struct {
	// UFrag and Pwd are the ICE credentials. They travel on offer and answer;
	// a candidate carries them too, so a candidate that arrives before its
	// offer can be held and matched instead of dropped.
	UFrag string `json:"ufrag,omitempty"`
	Pwd   string `json:"pwd,omitempty"`

	// Candidate is one ICE candidate in the usual SDP "candidate:..." form.
	Candidate string `json:"candidate,omitempty"`
}

var (
	// ErrNotSealed means the payload is too short to even hold a nonce.
	ErrNotSealed = errors.New("signal: body is not a sealed payload")
	// ErrOpenFailed means the box did not open: wrong key, wrong sender, or a
	// body someone tampered with. The three are indistinguishable on purpose.
	ErrOpenFailed = errors.New("signal: could not open the sealed body")
)

// nonceLen is fixed by NaCl box.
const nonceLen = 24

// Seal encrypts a body for theirPublic, signed by ourPrivate in the sense that
// only the holder of the matching public key could have produced it.
//
// The nonce is random and prepended to the output. Random rather than a
// counter because the two ends negotiate concurrently and a counter would need
// state that survives a reconnect — and a repeated nonce with the same key pair
// is the one mistake NaCl does not forgive.
func Seal(b Body, ourPrivate, theirPublic wgtypes.Key) ([]byte, error) {
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("signal: encoding body: %w", err)
	}

	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("signal: generating nonce: %w", err)
	}

	priv := [32]byte(ourPrivate)
	pub := [32]byte(theirPublic)
	return box.Seal(nonce[:], plain, &nonce, &pub, &priv), nil
}

// Open reverses Seal. theirPublic must be the public key of the sender, which
// the caller knows from the envelope's From field — and which it must have
// already accepted as a peer, otherwise anyone could open a conversation.
func Open(sealed []byte, ourPrivate, theirPublic wgtypes.Key) (Body, error) {
	if len(sealed) <= nonceLen {
		return Body{}, ErrNotSealed
	}

	var nonce [nonceLen]byte
	copy(nonce[:], sealed[:nonceLen])

	priv := [32]byte(ourPrivate)
	pub := [32]byte(theirPublic)
	plain, ok := box.Open(nil, sealed[nonceLen:], &nonce, &pub, &priv)
	if !ok {
		return Body{}, ErrOpenFailed
	}

	var b Body
	if err := json.Unmarshal(plain, &b); err != nil {
		return Body{}, fmt.Errorf("signal: decoding body: %w", err)
	}
	return b, nil
}
