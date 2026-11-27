# Knowledge packs (offline, signed updates)

trafficam never connects to a server, so it cannot update itself. Instead,
the things that do need refreshing ship as **knowledge packs**: single
`.tar` files that you download yourself (from the GitHub release page, or
copied on a USB stick) and install by hand:

    trafficam pack install trafficam-pack-7.tar
    trafficam pack status

Restart trafficam afterwards. Nothing is installed unless every check passes.

## What a pack can contain

| File | Kind | Used for | Switched on by |
|---|---|---|---|
| `blocklist.txt` | blocklist | known-bad destinations (always alert) | `-blocklist pack` (opt-in) |
| `prior.tcw` | prior | head C weights, TCW1 format (`KindPrior`) | `-prior pack` (opt-in) |
| `prior.sources.json` | prior-sources | which datasets and licences head C was trained on | informational |
| `trusted-os.json` | trusted-os | core OS programs exempt from "new destination" alerts | on by default (`-trust-os=false` turns it off) |
| `asn.csv.gz` | asn | offline table of network owners and countries | used automatically unless `-asn` is given |
| `SOURCES.md` | sources | where every byte came from, with SHA-256 | always present |

The threat list and head C stay opt-in, as agreed. Without a pack the
built-in trusted OS list (`internal/trustos/default.json`) is used.

## How it is protected

- **One signature covers everything.** `manifest.json` lists every file with
  its size and SHA-256, and only the manifest is signed (minisign, Ed25519).
  Changing one byte of any file breaks verification.
- **The public key is compiled into trafficam** (`internal/pack/keys.go`).
  It cannot be added at run time, because then malware could add its own.
- **No rollback.** A pack with a sequence number not above the installed one
  is refused, so an old pack with an old blocklist cannot be replayed.
- **Checked again at every start.** If installed files are edited on disk, the
  whole pack is ignored (with an ERROR in the log), never used partly.
- **Strict archive reading.** The signature is checked before any file is read;
  any entry not in the signed manifest (including `../` tricks) is refused,
  and the previous pack is kept in `packs/previous`.
- trafficam warns when the installed pack is more than 90 days old.

## Honest limits

- **No pack can be installed yet.** The signing key does not exist until the
  project owner creates it (below); until then `keys.go` is empty and every
  install says so. That is deliberate: a key made by anyone else would mean
  they could sign your updates.
- **If the secret key leaks, anyone can sign packs** until a trafficam
  release removes that key. There is no online revocation (no server, ever).
  Keep the secret key offline.
- Rollback protection only compares with the installed pack. A fresh install
  accepts any correctly signed pack, even an old one; `pack status` shows its
  date.
- The date in a pack is what the signer wrote; trafficam has no trusted clock.
- Nobody forces you to update, so a blocklist can go stale (hence the warning).
- Malware with administrator/root rights can replace trafficam itself, which
  makes any signature check moot. Packs protect the *download*, not the PC.
- The abuse.ch licences in `packs/recipe.json` (CC0) are what abuse.ch has
  stated; they could not be re-checked from the build environment and must
  be checked before the first release.

## Creating the signing key (project owner, once)

1. Install minisign (`apt install minisign`, `brew install minisign`, or
   `scoop install minisign` on Windows).
2. `minisign -G -p trafficam-packs.pub -s trafficam-packs.key`, with a
   strong password. Store `trafficam-packs.key` offline (USB stick, password
   manager), never in the repository.
3. Paste the second line of `trafficam-packs.pub` (starts with `RW`) into
   `releaseKeys` in `internal/pack/keys.go`, and commit the `.pub` file as
   `packs/trafficam-packs.pub`.

To rotate: add the new key next to the old one, release trafficam, sign with
the new key from then on, and remove the old key a release later.

## Making a pack (reproducible)

    go build ./cmd/trafficam-pack
    ./trafficam-pack fetch -recipe packs/recipe.json -cache build/pack-cache      # downloads, pins sha256 in the recipe
    ./trafficam-pack build -recipe packs/recipe.json -cache build/pack-cache \
        -seq 7 -created 2026-12-01 -out build/pack-7
    minisign -S -s trafficam-packs.key -m build/pack-7/manifest.json
    ./trafficam-pack tar -dir build/pack-7 -out trafficam-pack-7.tar
    ./trafficam-pack verify trafficam-pack-7.tar

`fetch` is the only step that uses the network, and `trafficam-pack` is the
only program that ever does; trafficam itself never does. Commit the pinned
recipe and attach the cache folder (the raw downloads) to the release next
to the pack, because public feeds change every few minutes.

**To check a release yourself:** download the pack and the raw inputs, run
`build` with the committed recipe and the same `-seq`/`-created`, and compare
your `manifest.json` with the one inside the pack: they must be identical, so
the published signature verifies on your own build. The archive itself is
deterministic too (fixed order, times and owners).

### Adding head C and the ASN table

When the model and ASN work land, add outputs like these to the recipe:

    {"name": "prior.tcw", "kind": "prior", "convert": "copy",
     "inputs": [{"name": "head C weights", "path": "../build/prior.tcw"}]},
    {"name": "prior.sources.json", "kind": "prior-sources", "convert": "copy",
     "inputs": [{"name": "head C training sources", "path": "../build/prior.sources.json"}]},
    {"name": "asn.csv.gz", "kind": "asn", "convert": "copy",
     "inputs": [{"name": "IPtoASN table", "path": "../build/asn.csv.gz"}]}

`prior.tcw` is the TCW1 file the trainer writes, unchanged; trafficam loads it
with `model.DecodeWeights` and `model.LoadHeadC`, exactly like `-prior FILE`.
