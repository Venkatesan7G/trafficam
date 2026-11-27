package pack

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/Venkatesan7G/trafficam/internal/blocklist"
)

// ---- minisign interop: fixtures made with the real minisign 0.11 tool ----

func TestVerifiesRealMinisignSignatures(t *testing.T) {
	pubText, _ := os.ReadFile("testdata/test.pub")
	pub, err := ParsePublicKey(string(pubText))
	if err != nil {
		t.Fatal(err)
	}
	if pub.KeyID() != "60C54BD789CA37D6" {
		t.Fatalf("key id %s", pub.KeyID())
	}
	msg, _ := os.ReadFile("testdata/msg.txt")
	for _, f := range []string{"msg.txt.minisig", "msg.txt.legacy.minisig"} {
		raw, _ := os.ReadFile("testdata/" + f)
		sig, err := ParseSignature(raw)
		if err != nil {
			t.Fatal(f, err)
		}
		if _, err := Verify([]PublicKey{pub}, msg, sig); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if _, err := Verify([]PublicKey{pub}, append(msg, '!'), sig); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s: modified message accepted", f)
		}
		sig.TrustedComment += "x"
		if _, err := Verify([]PublicKey{pub}, msg, sig); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s: modified trusted comment accepted", f)
		}
	}
}

func TestReleaseKeysParse(t *testing.T) {
	if _, err := TrustedKeys(); err != nil {
		t.Fatal(err)
	}
}

// ---- a throwaway signer for the tests (same format minisign writes) ----

type testKey struct {
	pub  PublicKey
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) testKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k PublicKey
	rand.Read(k.ID[:])
	k.Key = pub
	return testKey{k, priv}
}

func (k testKey) sign(msg []byte) []byte {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(k.priv, h[:])
	comment := "timestamp:0\tfile:manifest.json"
	global := ed25519.Sign(k.priv, append(append([]byte(nil), sig...), comment...))
	line := append(append([]byte("ED"), k.pub.ID[:]...), sig...)
	return []byte(fmt.Sprintf("untrusted comment: test\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(line), comment, base64.StdEncoding.EncodeToString(global)))
}

// ---- building ----

func writeRecipe(t *testing.T, dir string) *Recipe {
	t.Helper()
	os.WriteFile(filepath.Join(dir, "my-list.txt"), []byte("# comment\nEvil.Example.\n203.0.113.7\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "prior.tcw"), []byte("TCW1 fake weights"), 0o644)
	return &Recipe{Description: "test pack", Outputs: []Output{
		{Name: "blocklist.txt", Kind: KindBlocklist, Convert: "blocklist", Inputs: []Input{
			{Name: "local list", Path: "my-list.txt"},
			{Name: "public hosts feed", URL: "https://feed.example/hosts", Format: "hosts", Licence: "CC0"},
		}},
		{Name: "prior.tcw", Kind: KindPrior, Convert: "copy", Inputs: []Input{{Name: "head C", Path: "prior.tcw"}}},
	}}
}

func fakeGet(url string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("# hosts\n0.0.0.0 bad.example\n127.0.0.1 localhost\n0.0.0.0 evil.example\n")), nil
}

// buildSigned builds, signs and tars a pack; returns the pack file.
func buildSigned(t *testing.T, k testKey, seq uint64) string {
	t.Helper()
	dir := t.TempDir()
	r, err := Fetch(writeRecipe(t, dir), filepath.Join(dir, "cache"), fakeGet)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if _, err := Build(r, dir, filepath.Join(dir, "cache"), out, seq, "2026-11-27"); err != nil {
		t.Fatal(err)
	}
	m, _ := os.ReadFile(filepath.Join(out, ManifestName))
	os.WriteFile(filepath.Join(out, SignatureName), k.sign(m), 0o644)
	file := filepath.Join(dir, fmt.Sprintf("pack-%d.tar", seq))
	if _, err := WriteTar(out, file, []PublicKey{k.pub}); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestBuildIsReproducible(t *testing.T) {
	k := newKey(t)
	a, _ := os.ReadFile(buildSigned(t, k, 1))
	b, _ := os.ReadFile(buildSigned(t, k, 1))
	// Signatures differ only if the manifest differs (Ed25519 is deterministic).
	if !bytes.Equal(a, b) {
		t.Fatal("two builds from the same inputs differ")
	}
}

func TestMergedBlocklistLoads(t *testing.T) {
	k := newKey(t)
	data := t.TempDir()
	in, err := Install(buildSigned(t, k, 1), data, []PublicKey{k.pub})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(in.Path(KindBlocklist))
	want := "# trafficam known-bad list, built by trafficam-pack. Sources: SOURCES.md\n203.0.113.7\nbad.example\nevil.example\n"
	if string(b) != want {
		t.Fatalf("blocklist:\n%s", b)
	}
	if _, err := blocklist.Load(in.Path(KindBlocklist)); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(in.Path(KindSources))
	if !strings.Contains(string(src), "https://feed.example/hosts") || !strings.Contains(string(src), "CC0") {
		t.Fatalf("SOURCES.md:\n%s", src)
	}
}

func TestInstallLoadAndRollbackProtection(t *testing.T) {
	k := newKey(t)
	keys := []PublicKey{k.pub}
	data := t.TempDir()
	if p, err := Load(data, keys); p != nil || err != nil {
		t.Fatalf("empty: %v %v", p, err)
	}
	p2 := buildSigned(t, k, 2)
	if _, err := Install(p2, data, keys); err != nil {
		t.Fatal(err)
	}
	got, err := Load(data, keys)
	if err != nil || got.Manifest.Seq != 2 || got.SignedBy != k.pub.KeyID() {
		t.Fatalf("load: %+v %v", got, err)
	}
	if _, err := Install(buildSigned(t, k, 1), data, keys); !errors.Is(err, ErrOlder) {
		t.Fatalf("older pack: %v", err)
	}
	if _, err := Install(p2, data, keys); !errors.Is(err, ErrOlder) {
		t.Fatalf("same pack again: %v", err)
	}
	if _, err := Install(buildSigned(t, k, 3), data, keys); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(data, "packs", "previous", ManifestName)); err != nil {
		t.Fatal("previous pack not kept")
	}
	// Editing an installed file is caught at the next start.
	got, _ = Load(data, keys)
	os.WriteFile(got.Path(KindBlocklist), []byte("example.org\n"), 0o644)
	if _, err := Load(data, keys); err == nil {
		t.Fatal("modified installed file accepted")
	}
}

func TestInstallRejects(t *testing.T) {
	k, other := newKey(t), newKey(t)
	good := buildSigned(t, k, 1)

	rewrite := func(t *testing.T, edit func(name string, b []byte) (string, []byte, bool)) string {
		raw, _ := os.ReadFile(good)
		tr := tar.NewReader(bytes.NewReader(raw))
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			b, _ := io.ReadAll(tr)
			name, nb, keep := edit(h.Name, b)
			if !keep {
				continue
			}
			tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(nb)), Typeflag: tar.TypeReg})
			tw.Write(nb)
		}
		tw.Close()
		p := filepath.Join(t.TempDir(), "bad.tar")
		os.WriteFile(p, buf.Bytes(), 0o644)
		return p
	}
	cases := map[string]string{
		"unknown key": good,
		"changed file": rewrite(t, func(n string, b []byte) (string, []byte, bool) {
			if n == "files/blocklist.txt" {
				b = bytes.Replace(b, []byte("bad.example"), []byte("bad.exampl3"), 1)
			}
			return n, b, true
		}),
		"extra file": rewrite(t, func(n string, b []byte) (string, []byte, bool) {
			if n == "files/prior.tcw" {
				return "files/evil.sh", b, true
			}
			return n, b, true
		}),
		"missing file": rewrite(t, func(n string, b []byte) (string, []byte, bool) { return n, b, n != "files/prior.tcw" }),
		"edited manifest": rewrite(t, func(n string, b []byte) (string, []byte, bool) {
			if n == ManifestName {
				b = bytes.Replace(b, []byte(`"seq": 1`), []byte(`"seq": 9`), 1)
			}
			return n, b, true
		}),
		"path escape": rewrite(t, func(n string, b []byte) (string, []byte, bool) {
			if n == "files/prior.tcw" {
				return "files/../../prior.tcw", b, true
			}
			return n, b, true
		}),
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			keys := []PublicKey{k.pub}
			if name == "unknown key" {
				keys = []PublicKey{other.pub}
			}
			data := t.TempDir()
			if _, err := Install(file, data, keys); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(filepath.Join(data, "packs", "current")); err == nil {
				t.Fatal("a rejected pack was installed")
			}
		})
	}
	if m, who, err := VerifyFile(good, []PublicKey{k.pub}); err != nil || m.Seq != 1 || who != k.pub.KeyID() {
		t.Fatalf("verify good pack: %v", err)
	}
	if _, _, err := VerifyFile(cases["changed file"], []PublicKey{k.pub}); err == nil {
		t.Fatal("verify accepted a changed file")
	}
	if _, err := Install(good, t.TempDir(), nil); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("no keys: %v", err)
	}
}
