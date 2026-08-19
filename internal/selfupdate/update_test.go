package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// release is a published release, served the way GitHub serves one.
type release struct {
	tag  string
	body []byte // what the "binary" is
	sums []byte
	sig  []byte
}

// publish builds a release and signs its checksums, optionally with the wrong
// key — which is the case the whole package exists for.
func publish(t *testing.T, tag, prints string, signWith ed25519.PrivateKey) release {
	t.Helper()
	// A script rather than a compiled binary: Apply runs it and reads what it
	// says, and what matters here is what it says.
	body := []byte("#!/bin/sh\necho " + prints + "\n")
	sum := sha256.Sum256(body)
	name := fmt.Sprintf("nfagent-%s-%s", runtime.GOOS, runtime.GOARCH)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	return release{
		tag:  tag,
		body: body,
		sums: sums,
		sig:  ed25519.Sign(signWith, sums),
	}
}

// serve stands in for GitHub: the redirect for /latest and the assets.
func serve(t *testing.T, rel release) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/latest"):
			w.Header().Set("Location", "/releases/tag/"+rel.tag)
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
			w.Write(rel.sums)
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS.sig"):
			w.Write([]byte(base64.StdEncoding.EncodeToString(rel.sig)))
		case strings.Contains(r.URL.Path, "/nfagent-"):
			w.Write(rel.body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	testBase = srv.URL + "/releases"
	t.Cleanup(func() { testBase = "" })
}

// trust makes a key pair and tells this build to trust the public half.
func trust(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { testKey = "" })
	return priv
}

// asExecutable makes the test look like a binary that can be replaced, since
// Apply installs over whatever os.Executable reports.
func asExecutable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nfagent")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho v0.1.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := executable
	executable = func() (string, error) { return path, nil }
	t.Cleanup(func() { executable = old })
	return path
}

// The ordinary case, end to end: a signed release replaces the binary.
func TestASignedReleaseIsInstalled(t *testing.T) {
	priv := trust(t)
	serve(t, publish(t, "v0.2.0", "v0.2.0", priv))
	path := asExecutable(t)

	changed, err := Apply(context.Background(), "latest", "v0.1.0", quiet())
	if err != nil {
		t.Fatalf("applying a good release: %v", err)
	}
	if !changed {
		t.Fatal("nothing was installed")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "v0.2.0") {
		t.Errorf("the binary was not replaced: %q", got)
	}
	// Nothing left behind: a half-downloaded file beside the binary would be
	// installed by the next attempt if it ever stopped being checked.
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Error("the temporary download was left on disk")
	}
}

// The case the package exists for. Everything is well-formed and the checksums
// were signed by somebody else.
func TestAReleaseSignedByAStrangerIsRefused(t *testing.T) {
	trust(t)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, publish(t, "v0.2.0", "v0.2.0", stranger))
	path := asExecutable(t)

	_, err = Apply(context.Background(), "latest", "v0.1.0", quiet())
	if !errors.Is(err, ErrNotSigned) {
		t.Fatalf("error is %v, want ErrNotSigned", err)
	}
	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), "v0.2.0") {
		t.Error("the binary was replaced anyway")
	}
}

// A binary that does not hash to what the signed list says is refused, even
// though the list itself is properly signed — which is what happens when the
// asset is swapped and the checksums are not.
func TestASwappedBinaryIsRefused(t *testing.T) {
	priv := trust(t)
	rel := publish(t, "v0.2.0", "v0.2.0", priv)
	rel.body = []byte("#!/bin/sh\necho v0.2.0\n# something else entirely\n")
	serve(t, rel)
	path := asExecutable(t)

	_, err := Apply(context.Background(), "latest", "v0.1.0", quiet())
	if !errors.Is(err, ErrWrongDigest) {
		t.Fatalf("error is %v, want ErrWrongDigest", err)
	}
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Error("the rejected download was left on disk")
	}
}

// A signed release that is not what it claims to be does not get installed:
// the binary is run before it is trusted, which is also what catches a build
// for the wrong machine.
func TestABinaryThatLiesAboutItsVersionIsRefused(t *testing.T) {
	priv := trust(t)
	serve(t, publish(t, "v0.2.0", "v0.1.5", priv))
	asExecutable(t)

	_, err := Apply(context.Background(), "latest", "v0.1.0", quiet())
	if err == nil || !strings.Contains(err.Error(), "reports") {
		t.Fatalf("error is %v, want a complaint about what it reports", err)
	}
}

// Going backwards is refused. An attacker who can pick which signed release is
// installed would otherwise pick the oldest one with a hole in it.
func TestOlderReleasesAreRefused(t *testing.T) {
	priv := trust(t)
	serve(t, publish(t, "v0.1.0", "v0.1.0", priv))
	asExecutable(t)

	if _, err := Apply(context.Background(), "latest", "v0.2.0", quiet()); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("error is %v, want ErrNotNewer", err)
	}
}

// A build with no key installs nothing, whatever it is offered.
//
// This was the default state of the source until a key was generated, and it
// has to stay true: a build made from a branch with no key, or one where it was
// removed, must fail closed rather than accept anything.
func TestNoKeyMeansNoUpdates(t *testing.T) {
	// The real constant is emptied for the length of this test, because the
	// question is about a build without one.
	saved := PublicKey
	testKey = ""
	defer func() { testKey = saved }()

	if err := withoutKey(func() error {
		if Enabled() {
			return errors.New("a build with no key says it can update")
		}
		_, err := Apply(context.Background(), "v9.9.9", "v0.1.0", quiet())
		if !errors.Is(err, ErrNoKey) {
			return fmt.Errorf("error is %v, want ErrNoKey", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// withoutKey runs f as though this build had never been given a key.
func withoutKey(f func() error) error {
	saved := noKey
	noKey = true
	defer func() { noKey = saved }()
	return f()
}

func TestVersionOrder(t *testing.T) {
	cases := []struct {
		target, current string
		want            bool
	}{
		{"v0.2.0", "v0.1.9", true},
		{"v0.1.10", "v0.1.9", true},
		{"v1.0.0", "v0.99.99", true},
		{"v0.1.0", "v0.1.0", false},
		{"v0.1.0", "v0.2.0", false},
		// A hand-built binary is not a version, and a release replacing one
		// would quietly undo whatever it was built to test.
		{"v9.9.9", "dev", false},
		{"garbage", "v0.1.0", false},
		{"v0.1", "v0.1.0", false},
	}
	for _, c := range cases {
		if got := newer(c.target, c.current); got != c.want {
			t.Errorf("newer(%q, %q) = %v, want %v", c.target, c.current, got, c.want)
		}
	}
}

// The failure that a hardened service produces, and the sentence it should turn
// into.
//
// ProtectSystem=strict makes the directory the binary lives in read-only for
// the service, which is right for everything the agent does except replacing
// itself. What came out of it was four words about a filesystem, from a process
// that had just downloaded and verified a release it then could not install.
func TestAReadOnlyDirectorySaysWhatToDo(t *testing.T) {
	err := explainWrite(&os.PathError{
		Op: "open", Path: "/usr/local/bin/nfagent.new", Err: syscall.EROFS,
	}, "/usr/local/bin/nfagent")

	if !strings.Contains(err.Error(), "/usr/local/bin") {
		t.Errorf("the message does not name the directory: %v", err)
	}
	if !strings.Contains(err.Error(), "installer") {
		t.Errorf("the message does not say what to do: %v", err)
	}
	// And the original is still in there, for whoever wants the real cause.
	if !errors.Is(err, syscall.EROFS) {
		t.Error("the underlying error was lost")
	}

	// Anything else is passed through untouched: a message invented for a
	// failure it does not fit is worse than the failure.
	other := errors.New("no space left on device")
	if got := explainWrite(other, "/usr/local/bin/nfagent"); got != other {
		t.Errorf("an unrelated error was rewritten: %v", got)
	}
}
