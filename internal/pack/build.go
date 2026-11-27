package pack

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/blocklist"
)

// Building a pack is reproducible: the same recipe and the same input files
// give a byte-identical manifest.json, so anyone can rebuild a released pack
// from the public sources and check that its published signature verifies on
// their own build. Nothing here signs: signing is done with minisign by the
// key holder (docs/PACKS.md).

// Recipe says how to build a pack (packs/recipe.json).
type Recipe struct {
	Description string   `json:"description"`
	Outputs     []Output `json:"outputs"`
}

// Output is one file of the pack.
type Output struct {
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	Convert string  `json:"convert"` // "copy" (one input, as is) or "blocklist" (merge, check, sort)
	Inputs  []Input `json:"inputs"`
}

// Input is a public source, pinned by hash, or a file in the repository.
type Input struct {
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`  // downloaded by "trafficam-pack fetch" only
	Path    string `json:"path,omitempty"` // relative to the recipe file
	SHA256  string `json:"sha256,omitempty"`
	Licence string `json:"licence,omitempty"`
	Format  string `json:"format,omitempty"` // blocklist inputs: "lines" (default) or "hosts"
}

// LoadRecipe reads a recipe file.
func LoadRecipe(path string) (*Recipe, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Recipe
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("recipe %s: %w", path, err)
	}
	return &r, nil
}

// CachePath is where a downloaded input with this hash is kept.
func CachePath(cache, sha string) string { return filepath.Join(cache, sha) }

// inputBytes reads an input from the repository or the download cache and
// checks its pinned hash. It never touches the network.
func inputBytes(in Input, recipeDir, cache string) ([]byte, error) {
	var b []byte
	var err error
	switch {
	case in.Path != "":
		b, err = os.ReadFile(filepath.Join(recipeDir, in.Path))
	case in.URL != "":
		if in.SHA256 == "" {
			return nil, fmt.Errorf("input %q has no pinned sha256; run trafficam-pack fetch first", in.Name)
		}
		b, err = os.ReadFile(CachePath(cache, in.SHA256))
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("input %q (sha256 %s) is not in the cache %s; run trafficam-pack fetch, or get the release's inputs archive", in.Name, in.SHA256, cache)
		}
	default:
		return nil, fmt.Errorf("input %q has neither path nor url", in.Name)
	}
	if err != nil {
		return nil, err
	}
	if in.SHA256 != "" {
		if got := sha256Hex(b); got != in.SHA256 {
			return nil, fmt.Errorf("input %q: sha256 %s, recipe pins %s", in.Name, got, in.SHA256)
		}
	}
	return b, nil
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Build writes the pack's files, SOURCES.md and manifest.json into out
// (which must be empty or missing). Sign out/manifest.json afterwards.
func Build(r *Recipe, recipeDir, cache, out string, seq uint64, created string) (*Manifest, error) {
	if seq == 0 {
		return nil, fmt.Errorf("pack: -seq must be at least 1")
	}
	if _, err := time.Parse("2006-01-02", created); err != nil {
		return nil, fmt.Errorf("pack: created must be YYYY-MM-DD: %w", err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	if ents, _ := os.ReadDir(out); len(ents) > 0 {
		return nil, fmt.Errorf("pack: output folder %s is not empty", out)
	}
	m := &Manifest{Format: Format, Seq: seq, Created: created, Description: r.Description}
	var sources strings.Builder
	sources.WriteString("# Sources of this knowledge pack\n\n")
	fmt.Fprintf(&sources, "Pack %d, built %s. Every input is pinned by SHA-256; rebuilding from the\nsame inputs gives the same manifest.json.\n", seq, created)

	for _, o := range r.Outputs {
		var data []byte
		var err error
		fmt.Fprintf(&sources, "\n## %s (%s)\n\n", o.Name, o.Kind)
		var ins [][]byte
		for _, in := range o.Inputs {
			b, err := inputBytes(in, recipeDir, cache)
			if err != nil {
				return nil, err
			}
			ins = append(ins, b)
			where := in.URL
			if where == "" {
				where = "repository: " + filepath.ToSlash(in.Path)
			}
			lic := in.Licence
			if lic == "" {
				lic = "see source"
			}
			fmt.Fprintf(&sources, "- %s\n  - from: %s\n  - licence: %s\n  - sha256: %s\n", in.Name, where, lic, sha256Hex(b))
		}
		switch o.Convert {
		case "copy":
			if len(ins) != 1 {
				return nil, fmt.Errorf("output %s: copy needs exactly one input", o.Name)
			}
			data = ins[0]
		case "blocklist":
			data, err = mergeBlocklists(o, ins)
		default:
			err = fmt.Errorf("output %s: unknown convert %q", o.Name, o.Convert)
		}
		if err != nil {
			return nil, err
		}
		if err := writeOut(out, o.Name, o.Kind, data, m); err != nil {
			return nil, err
		}
	}
	if err := writeOut(out, "SOURCES.md", KindSources, []byte(sources.String()), m); err != nil {
		return nil, err
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	if err := m.validate(); err != nil {
		return nil, err
	}
	b, err := MarshalManifest(m)
	if err != nil {
		return nil, err
	}
	return m, os.WriteFile(filepath.Join(out, ManifestName), b, 0o644)
}

// MarshalManifest is the one canonical encoding of a manifest.
func MarshalManifest(m *Manifest) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func writeOut(dir, name, kind string, data []byte, m *Manifest) error {
	m.Files = append(m.Files, File{Name: name, Kind: kind, Size: int64(len(data)), SHA256: sha256Hex(data)})
	return os.WriteFile(filepath.Join(dir, name), data, 0o644)
}

// mergeBlocklists turns public feeds into one sorted, de-duplicated list in
// trafficam's blocklist format. Every line is parsed with the same code
// trafficam uses to load it, so a pack can never ship a list that fails to
// load.
func mergeBlocklists(o Output, ins [][]byte) ([]byte, error) {
	set := map[string]bool{}
	for i, b := range ins {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			if j := strings.IndexByte(line, '#'); j >= 0 {
				line = line[:j]
			}
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			var entry string
			switch o.Inputs[i].Format {
			case "", "lines":
				entry = f[0]
			case "hosts": // "0.0.0.0 evil.example" or "127.0.0.1 evil.example"
				if len(f) < 2 {
					continue
				}
				entry = f[1]
			default:
				return nil, fmt.Errorf("input %q: unknown format %q", o.Inputs[i].Name, o.Inputs[i].Format)
			}
			entry = strings.TrimSuffix(strings.ToLower(entry), ".")
			if entry == "localhost" || entry == "" {
				continue
			}
			if err := blocklist.New().Add(entry); err != nil {
				return nil, fmt.Errorf("input %q line %d: %v", o.Inputs[i].Name, n, err)
			}
			set[entry] = true
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	lines := make([]string, 0, len(set))
	for e := range set {
		lines = append(lines, e)
	}
	sort.Strings(lines)
	var b bytes.Buffer
	b.WriteString("# trafficam known-bad list, built by trafficam-pack. Sources: SOURCES.md\n")
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// WriteTar packs a built and signed folder into a pack file. The archive is
// deterministic (fixed order, times and owners), so the same folder always
// gives the same bytes. The signature is checked first with keys.
func WriteTar(dir, out string, keys []PublicKey) (*Manifest, error) {
	manifest, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, SignatureName))
	if err != nil {
		return nil, fmt.Errorf("pack: not signed yet: %w", err)
	}
	m, _, err := verifyManifest(keys, manifest, sig)
	if err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		if err := checkFile(filepath.Join(dir, f.Name), f); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg,
			ModTime: time.Unix(0, 0), Format: tar.FormatPAX,
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := add(ManifestName, manifest); err != nil {
		return nil, err
	}
	if err := add(SignatureName, sig); err != nil {
		return nil, err
	}
	for _, f := range m.Files { // already sorted by name
		b, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			return nil, err
		}
		if err := add(filesPrefix+f.Name, b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return &m, os.WriteFile(out, buf.Bytes(), 0o644)
}

// Fetch downloads every URL input into the cache and returns the recipe
// with each input's hash pinned. get does the download (net/http in the
// tool, a fake in tests). Only the build tool calls this, never trafficam.
func Fetch(r *Recipe, cache string, get func(url string) (io.ReadCloser, error)) (*Recipe, error) {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, err
	}
	out := *r
	out.Outputs = append([]Output(nil), r.Outputs...)
	for i := range out.Outputs {
		o := &out.Outputs[i]
		o.Inputs = append([]Input(nil), o.Inputs...)
		for j := range o.Inputs {
			in := &o.Inputs[j]
			if in.URL == "" {
				continue
			}
			rc, err := get(in.URL)
			if err != nil {
				return nil, fmt.Errorf("fetch %s: %w", in.URL, err)
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxFile+1))
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("fetch %s: %w", in.URL, err)
			}
			in.SHA256 = sha256Hex(b)
			if err := os.WriteFile(CachePath(cache, in.SHA256), b, 0o644); err != nil {
				return nil, err
			}
		}
	}
	return &out, nil
}
