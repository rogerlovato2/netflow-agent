// Package selfupdate replaces the running agent with a newer signed release.
//
// The whole package is written around one sentence: an agent that replaces its
// own binary is remote code execution with extra steps, so the only question
// that matters is who decides what it runs. The answer here is "whoever holds
// the signing key", and nothing else — not the management server, not the
// network, not the machine's own configuration.
//
// The order below is deliberate. Everything that can fail cheaply fails before
// anything is written, and the running binary is replaced last, by a rename,
// which is the only step that cannot be half-done.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var (
	ErrNoKey       = errors.New("this build has no update key, so updates are refused")
	ErrNotSigned   = errors.New("the release is not signed by the key this build trusts")
	ErrNoAsset     = errors.New("the release has no build for this machine")
	ErrWrongDigest = errors.New("the downloaded file does not match the release's checksum")
	ErrNotNewer    = errors.New("the release is not newer than what is running")
	// ErrUnknownVersion is a running binary whose version cannot be read: a
	// hand-built one, or a tag this build predates.
	//
	// Refusing is right — replacing a binary somebody built to test would
	// quietly undo whatever it was built for — but it used to be indistinguish-
	// able from being up to date, so the panel said nothing and the button did
	// nothing. Silence is the wrong answer to "why did that not work".
	ErrUnknownVersion = errors.New("cannot tell what version is running, so refusing to replace it")
)

// httpClient has a timeout because the alternative is an update check that
// hangs for as long as the network cares to keep the socket open.
var httpClient = &http.Client{Timeout: 2 * time.Minute}

// Two seams, both unexported, both only ever written by the tests in this
// package: one to point the download at a local server, one to trust a key
// generated for the test. Nothing outside this package can reach either, which
// is what keeps them from being a way in — an exported variable for the key
// would be exactly the runtime-configurable trust root that key.go argues
// against.
var (
	testBase string
	testKey  string
)

// executable is os.Executable, named so the tests can install over a file of
// their own instead of over the test binary.
var executable = os.Executable

func base() string {
	if testBase != "" {
		return testBase
	}
	return "https://github.com/" + repo + "/releases"
}

// noKey is the tests asking what a build with no key does — which was the
// state of this package before one existed, and has to keep failing closed.
var noKey bool

func trustedKey() string {
	if noKey {
		return ""
	}
	if testKey != "" {
		return testKey
	}
	return PublicKey
}

// Enabled says whether this build can update itself at all.
func Enabled() bool { return trustedKey() != "" }

// Latest is the newest published release, found by following the redirect that
// /releases/latest answers with.
//
// The redirect rather than the API: it needs no token, it is not rate limited
// the way the API is, and the only thing it can tell us is a tag — which is all
// we want it to be able to tell us.
func Latest(ctx context.Context) (string, error) {
	url := base() + "/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	tag := loc[strings.LastIndex(loc, "/")+1:]
	if !strings.HasPrefix(tag, "v") {
		return "", fmt.Errorf("could not read a version out of %q", loc)
	}
	return tag, nil
}

// Apply installs a release over the running binary and reports whether anything
// changed. The caller restarts; this deliberately does not, because deciding
// when to disappear belongs to whoever knows what else is in flight.
func Apply(ctx context.Context, target, current string, log *slog.Logger) (bool, error) {
	if !Enabled() {
		return false, ErrNoKey
	}
	if target == "" || target == "latest" {
		found, err := Latest(ctx)
		if err != nil {
			return false, fmt.Errorf("looking for the newest release: %w", err)
		}
		target = found
	}
	// Told apart on purpose. One is a machine that is fine and the other is a
	// machine nothing will ever update, and they used to report the same
	// nothing.
	if current == "dev" || parseVersion(current) == nil {
		return false, fmt.Errorf("%w (running %q)", ErrUnknownVersion, current)
	}
	if !newer(target, current) {
		return false, ErrNotNewer
	}

	// The checksums are the thing that is signed, and every binary's digest is
	// in them. Signing one file rather than each asset means one signature to
	// verify and no way to mix an old binary with a new list.
	sums, err := fetch(ctx, assetURL(target, "SHA256SUMS"))
	if err != nil {
		return false, fmt.Errorf("fetching the checksums: %w", err)
	}
	rawSig, err := fetch(ctx, assetURL(target, "SHA256SUMS.sig"))
	if err != nil {
		return false, fmt.Errorf("fetching the signature: %w", err)
	}
	if err := verify(sums, rawSig); err != nil {
		return false, err
	}

	name := fmt.Sprintf("nfagent-%s-%s", runtime.GOOS, runtime.GOARCH)
	want, ok := digestOf(sums, name)
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrNoAsset, name)
	}

	self, err := executable()
	if err != nil {
		return false, err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return false, err
	}

	// Downloaded beside the binary it will replace, because a rename is only
	// atomic within one filesystem, and /tmp is frequently not the same one.
	tmp := self + ".new"
	if err := download(ctx, assetURL(target, name), tmp, want); err != nil {
		os.Remove(tmp)
		return false, explainWrite(err, self)
	}
	// Run before it is installed. This is what catches a build for the wrong
	// architecture, a truncated download that somehow matched, and a binary
	// that cannot start at all — all of which would otherwise be discovered by
	// the service manager, in a restart loop, with the old binary already gone.
	if err := selfTest(ctx, tmp, target); err != nil {
		os.Remove(tmp)
		return false, err
	}

	if err := os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		return false, explainWrite(fmt.Errorf("installing over %s: %w", self, err), self)
	}
	log.Info("update: installed", "from", current, "to", target, "path", self)
	return true, nil
}

func assetURL(tag, name string) string {
	return fmt.Sprintf("%s/download/%s/%s", base(), tag, name)
}

func verify(payload, rawSig []byte) error {
	pub, err := base64.StdEncoding.DecodeString(trustedKey())
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ErrNoKey
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
	if err != nil {
		return ErrNotSigned
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrNotSigned
	}
	return nil
}

// digestOf reads one line of a sha256sum file.
func digestOf(sums []byte, name string) (string, bool) {
	for line := range strings.SplitSeq(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			return fields[0], true
		}
	}
	return "", false
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	// Bounded: this is a list of checksums, and anything larger than this is
	// not one.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// download writes the asset and refuses to keep it unless it hashes to want.
func download(ctx context.Context, url, dest, want string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	sum := sha256.New()
	// 128 MB is far more than any build here and far less than a disk.
	if _, err := io.Copy(io.MultiWriter(f, sum), io.LimitReader(resp.Body, 128<<20)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		return fmt.Errorf("%w: got %s, want %s", ErrWrongDigest, got[:16], want[:16])
	}
	return nil
}

// selfTest runs the downloaded binary and insists it says what it should be.
func selfTest(ctx context.Context, path, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return fmt.Errorf("the downloaded binary does not run: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		return fmt.Errorf("the downloaded binary reports %q, not %q", got, want)
	}
	return nil
}

// newer compares two version tags, and answers no whenever it cannot tell.
//
// Refusing to go backwards is the point. An attacker who can choose which
// signed release a machine installs would otherwise pick the oldest one with a
// known hole in it — every byte of it correctly signed, because it was.
func newer(target, current string) bool {
	if current == "dev" {
		// A hand-built binary is not a version, and replacing one with a
		// release would quietly undo whatever it was built to test.
		return false
	}
	a, b := parseVersion(target), parseVersion(current)
	if a == nil || b == nil {
		return false
	}
	for i := range versionParts {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// versionParts is how many numbers a version has, at most.
//
// Four, not three. The fourth is for the release that changes one thing and
// wants to say so — v0.3.4.1 is a fix on top of v0.3.4, and calling it v0.3.5
// would claim more than happened. Three-number versions are read as if their
// fourth were zero, so v0.3.4 and v0.3.4.0 are the same release and the older
// tags keep meaning what they meant.
const versionParts = 4

func parseVersion(v string) []int {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) < 3 || len(parts) > versionParts {
		return nil
	}
	// Padded rather than rejected: the missing part is zero, which is what
	// "v0.3.4" has always meant next to "v0.3.4.1".
	out := make([]int, versionParts)
	for i, p := range parts {
		if p == "" {
			return nil
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}

// explainWrite turns "read-only file system" into the thing to go and do.
//
// The service file hardens the agent by making everything outside its own
// configuration read-only, which is right for everything it does except the one
// thing the panel can ask of it. When that is what happened, the message a
// person sees should not be four words about a filesystem from a process that
// had just downloaded and verified a release it then could not install.
func explainWrite(err error, path string) error {
	if !errors.Is(err, syscall.EROFS) {
		return err
	}
	return fmt.Errorf("%s cannot be written by this service: re-run the installer "+
		"so the service file allows it (%w)", filepath.Dir(path), err)
}
