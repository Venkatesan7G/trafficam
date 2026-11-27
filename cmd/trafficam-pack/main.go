// Command trafficam-pack builds signed offline knowledge packs. It is a tool
// for whoever publishes packs, not part of the installed watcher; it is the
// only trafficam program that ever downloads anything, and only when you run
// "fetch". See docs/PACKS.md.
//
//	trafficam-pack fetch  -recipe packs/recipe.json -cache DIR        download sources, pin their hashes in the recipe
//	trafficam-pack build  -recipe packs/recipe.json -cache DIR -seq N -created YYYY-MM-DD -out DIR
//	minisign -S -s KEY -m DIR/manifest.json                            (sign, outside this tool)
//	trafficam-pack tar    -dir DIR -out trafficam-pack-N.tar [-pub KEY.pub]
//	trafficam-pack verify [-pub KEY.pub] FILE.tar
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/pack"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: trafficam-pack fetch|build|tar|verify [flags]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	recipe := fs.String("recipe", "packs/recipe.json", "recipe file")
	cache := fs.String("cache", "build/pack-cache", "folder for downloaded sources (named by sha256)")
	seq := fs.Uint64("seq", 0, "build: pack sequence number (must grow with every release)")
	created := fs.String("created", "", "build: date YYYY-MM-DD (part of the signed manifest)")
	out := fs.String("out", "", "build: output folder; tar: output file")
	dir := fs.String("dir", "", "tar: built and signed folder")
	pub := fs.String("pub", "", "minisign public key file (default: the key compiled into trafficam)")
	fs.Parse(args)

	keys, err := keysFrom(*pub)
	if err != nil {
		return err
	}
	switch cmd {
	case "fetch":
		r, err := pack.LoadRecipe(*recipe)
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: 2 * time.Minute}
		pinned, err := pack.Fetch(r, *cache, func(url string) (io.ReadCloser, error) {
			resp, err := client.Get(url)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return nil, fmt.Errorf("HTTP %s", resp.Status)
			}
			return resp.Body, nil
		})
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(pinned, "", "  ")
		if err := os.WriteFile(*recipe, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("sources saved in %s and pinned in %s; commit the recipe\n", *cache, *recipe)
		return nil
	case "build":
		r, err := pack.LoadRecipe(*recipe)
		if err != nil {
			return err
		}
		if *out == "" || *created == "" {
			return fmt.Errorf("build needs -out and -created")
		}
		m, err := pack.Build(r, filepath.Dir(*recipe), *cache, *out, *seq, *created)
		if err != nil {
			return err
		}
		fmt.Printf("built pack %d with %d files in %s\nnext: minisign -S -s <secret key> -m %s\n",
			m.Seq, len(m.Files), *out, filepath.Join(*out, pack.ManifestName))
		return nil
	case "tar":
		if *dir == "" || *out == "" {
			return fmt.Errorf("tar needs -dir and -out")
		}
		m, err := pack.WriteTar(*dir, *out, keys)
		if err != nil {
			return err
		}
		fmt.Printf("wrote %s (pack %d, %d files, signature checked)\n", *out, m.Seq, len(m.Files))
		return nil
	case "verify":
		if fs.NArg() != 1 {
			return fmt.Errorf("verify needs a pack file")
		}
		m, who, err := pack.VerifyFile(fs.Arg(0), keys)
		if err != nil {
			return err
		}
		fmt.Printf("OK: pack %d (%s), signed by %s\n", m.Seq, m.Created, who)
		for _, f := range m.Files {
			fmt.Printf("  %-20s %-14s %9d  %s\n", f.Name, f.Kind, f.Size, f.SHA256)
		}
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func keysFrom(pubFile string) ([]pack.PublicKey, error) {
	if pubFile == "" {
		return pack.TrustedKeys()
	}
	b, err := os.ReadFile(pubFile)
	if err != nil {
		return nil, err
	}
	k, err := pack.ParsePublicKey(string(b))
	if err != nil {
		return nil, err
	}
	return []pack.PublicKey{k}, nil
}
