// Command nfsign makes and verifies the signature that guards an update.
//
// An agent that replaces its own binary is the most dangerous thing in this
// system: whoever decides what it downloads runs code as root on every machine
// in the mesh. A checksum is not enough for that — it proves the file arrived
// intact, not that it is the file you meant. So the release is signed with a
// key that lives nowhere near the panel or the server, and the agent carries
// the public half.
//
//	nfsign keygen                 make a key pair
//	nfsign sign  <file>           write <file>.sig, key from NFSIGN_KEY
//	nfsign check <file> <pubkey>  verify it
//
// Ed25519 rather than a signing tool: it is in the standard library, the whole
// implementation is the fifty lines below, and there is nothing to install in
// CI that could be swapped for something else.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "keygen":
		return keygen()
	case "sign":
		if len(args) != 2 {
			return usage()
		}
		return sign(args[1])
	case "check":
		if len(args) != 3 {
			return usage()
		}
		return check(args[1], args[2])
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: nfsign keygen | nfsign sign <file> | nfsign check <file> <pubkey>")
}

// keygen prints both halves once, and says plainly what to do with each.
func keygen() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// The seed, not the expanded private key: it is half the length and
	// ed25519.NewKeyFromSeed rebuilds the rest.
	fmt.Printf("public key (paste into internal/selfupdate/key.go):\n%s\n\n",
		base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("private key (GitHub secret NFSIGN_KEY — this is shown once):\n%s\n",
		base64.StdEncoding.EncodeToString(priv.Seed()))
	return nil
}

func sign(path string) error {
	seed := strings.TrimSpace(os.Getenv("NFSIGN_KEY"))
	if seed == "" {
		return fmt.Errorf("NFSIGN_KEY is not set")
	}
	raw, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return fmt.Errorf("NFSIGN_KEY is not base64: %w", err)
	}
	if len(raw) != ed25519.SeedSize {
		return fmt.Errorf("NFSIGN_KEY is %d bytes, want %d", len(raw), ed25519.SeedSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(raw), data)
	out := path + ".sig"
	if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", out)
	return nil
}

func check(path, pubkey string) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubkey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("that is not an ed25519 public key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rawSig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
	if err != nil {
		return fmt.Errorf("the signature is not base64: %w", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		return fmt.Errorf("the signature does not match")
	}
	fmt.Println("signature is good")
	return nil
}
