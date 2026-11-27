# trafficam

A quiet, local, offline watcher for your PC's network traffic. It learns what
each program normally talks to, and tells you when one starts calling somewhere
new.

trafficam is **not** an antivirus and it **never blocks anything**. It only
watches and notifies, so you get peace of mind that a bad call from a program
on your machine will be noticed.

> **Status: early development.** The shared core works end to end on synthetic
> and recorded traffic, including the learning model. Real capture on Linux
> and Windows and desktop notifications are not on `main` yet. See
> [What works today](#what-works-today) before you try it.

## Principles

- **Passive only.** No drivers, no packet-filter hooks, no proxy. If trafficam
  crashes, your network keeps working.
- **Offline.** No server, no telemetry, no account. Nothing leaves your
  machine, and there is no central service that could be abused.
- **Private.** It stores metadata only (which program, which destination,
  when, how much). It never reads packet contents.
- **Encrypted at rest.** The database is encrypted (SQLCipher) with a random
  key sealed to your machine.
- **Learns by watching.** It does not ask you to label things as good or bad.
- **Your lists, your switches.** Threat lists and TLS server-name inspection
  are opt-in. You can add your own watch and ignore lists.
- **Open source**, GPL-3.0.

## What works today

| Area | State |
|---|---|
| Event schema (versioned), per-minute rollup | Working |
| Encrypted store (SQLCipher), machine-sealed key, in-place upgrades | Working |
| Record and replay files (JSONL, optional gzip) | Working |
| Service: panic recovery, collector restart, bounded queues | Working |
| Always-alert rules (known-bad list, watch list, new program, new destination) | Working |
| Ignore list, offline blocklist, offline ASN/country table | Working |
| Baseline counters (first seen, days seen, auto-absorb after 3 days) | Working |
| Synthetic traffic generator and the `demo` command | Working |
| Anomaly model (learns each program's habits), nightly self-training, wired into the service | Working, tested on synthetic data only |
| Optional pretrained prior (head C) | Loader and trainer work; no real weights shipped yet |
| **Real capture on Linux (eBPF)** | **Not started** |
| **Real capture on Windows (ETW)** | **Not started** |
| Desktop notifications | Not started (alerts print to the log) |
| Learning ramp shown to the user | Not started |

Today you can run the whole pipeline on synthetic or recorded traffic and see
the rules and the model raise alerts. It will not yet watch your real network.

## Installation

There are no prebuilt releases yet; build from source.

**You need:**

- Go 1.24 or newer
- A C compiler (the encrypted database uses SQLCipher through cgo)
  - Linux: `gcc` (Debian/Ubuntu: `sudo apt install build-essential`)
  - Windows: a MinGW-w64 `gcc` on your `PATH` (for example from MSYS2)
  - macOS is not a target

```sh
git clone https://github.com/Venkatesan7G/trafficam
cd trafficam
go build -o trafficam ./cmd/trafficam
go test ./...
```

On Windows the binary is `trafficam.exe`. The Windows build is not yet tested
in CI, so expect rough edges.

## Usage

Everything is one binary, `trafficam`. Until real capture exists, it works from
synthetic or recorded traffic.

| Command | What it does |
|---|---|
| `trafficam demo [-n N]` | Runs the pipeline on N synthetic flows (default 600), including one suspicious connection |
| `trafficam record -out FILE [-n N]` | Saves synthetic traffic to a replay file (`.gz` compresses it) |
| `trafficam replay FILE` | Runs the pipeline on a replay file |
| `trafficam dump` | Prints what is stored in the database |

Common flags:

| Flag | Meaning |
|---|---|
| `-data DIR` | Where the encrypted database and key live (default: your user config folder, `trafficam/`) |
| `-blocklist FILE` | Known-bad snapshot. Matches always alert. Off unless given |
| `-watch FILE` | Your "alert me anyway" list |
| `-ignore FILE` | Your "ignore" list. Silences novelty alerts and the model, never blocklist or watch hits |
| `-asn FILE` | Offline table that adds network owner (ASN) and country to each row |
| `-prior FILE` | Optional pretrained prior-risk weights (head C). Off unless given |

### Try it

```sh
# Use a throwaway data folder
mkdir /tmp/tc-demo
printf 'evil-c2.example.net\n' > /tmp/tc-demo/bad.txt

./trafficam demo -data /tmp/tc-demo/data -blocklist /tmp/tc-demo/bad.txt
./trafficam dump -data /tmp/tc-demo/data | tail
```

You should see one `ALERT` line for `evil-c2.example.net`, then a summary such
as `done: flows=600 rows=201 ... alerts=1`.

Record and replay:

```sh
./trafficam record -out capture.jsonl.gz -n 300
./trafficam replay -data /tmp/tc-demo/data2 capture.jsonl.gz
```

Recordings contain program paths and host names. Read one before sharing it.

### List file format

Used by `-blocklist`, `-watch` and `-ignore`. One rule per line, `#` starts a
comment.

```text
evil.example.com            # a domain; also matches sub.evil.example.com
203.0.113.7                 # one IP address
198.51.100.0/24             # a network
cdn.example.net firefox     # applies only to the program "firefox"
```

The `-asn` file is CSV, one network per line: `cidr,asn,country`, for example
`93.184.216.0/24,15133,US`.

## How it works

```text
 collector ──▶ bounded queue ──▶ 1-minute rollup ──▶ scoring ──▶ encrypted store
 (Linux eBPF /                                        │
  Windows ETW /                                       └──▶ notifier
  replay / synthetic)
```

1. A **collector** watches TCP, UDP and DNS activity and reports which program
   talked to which destination. It only observes.
2. Flows are rolled up into **one row per minute** per program, protocol,
   direction, destination and port. Destinations are keyed by DNS name when
   known, so CDN address changes do not look like new destinations.
3. **Scoring** combines the always-alert rules and the model. If the model
   fails, the rules still answer.
4. Rows and verdicts go into the **encrypted database**.
5. Alerts go to a **notifier** (currently the log).

The always-alert rules:

1. Destination is on the known-bad list: always alerts.
2. Destination is on your watch list: always alerts.
3. A program uses the network for the first time: alerts.
4. A settled program with few destinations contacts a new one: alerts.
   Browsers and other programs with many destinations are left to the model.

Rules 3 and 4 are held back during the first 48 hours after install. A
destination seen on three separate days is treated as normal.

For the layout and the two plug-in interfaces (`Collector` for capture,
`Scorer` for the model), see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## The model

A small neural network (about 94,000 parameters, written in Go with no
external ML library) learns each program's normal behaviour from your own
traffic over a rolling 30-day window, with no labelling from you.

- **Head A** predicts which program made a connection, and **head B**
  reconstructs the connection's numeric features. A connection that is hard to
  explain is unusual for that program.
- A score is the program's own percentile of that surprise. The alert line is
  set from your machine's own history, aiming for only an alert or two a day.
- It trains itself every night in under a minute, and only keeps the new
  version if it is not worse on the last day of data.
- Until it has seen about 10,000 rows it stays in the **Listening** phase and
  does not alert; the rules still do.
- An optional pretrained **prior (head C)** can raise a score a little using
  patterns from public datasets. It never alerts on its own and is off unless
  you pass `-prior`.
- Its state is saved in `model.tcw` inside your data folder.

**Honest status:** it is tested against a PyTorch reference and on synthetic
traffic only. Its detection quality on real networks has not been measured.
Details: [docs/model.md](docs/model.md) and [docs/DATASETS.md](docs/DATASETS.md).

## Upcoming features

Roughly in order:

1. **Linux capture** with eBPF (needs root or `CAP_BPF`).
2. **Windows capture** with ETW (needs administrator; no driver).
3. **Real-traffic measurement**: volunteer recordings, planted attacks in a
   test VM, and an ablation of rules versus rules plus model.
4. **Desktop notifications** on both systems.
5. **A learning ramp** you can see: Listening, Settling in, Watching, Guarding.
6. **Stronger key sealing**: Windows DPAPI and Linux TPM2.
7. **Tamper response**: loud alert if the database or key is tampered with.
8. **Signed offline knowledge packs** for updating the blocklist and model prior
   by hand, with no update server.
9. **Real prior weights** trained on public datasets, after checking licences.
10. **Optional TLS server-name inspection** (off by default).
11. **Tuning on real traffic**, including the novelty thresholds.

Supported platforms are planned as Windows 10/11 and the latest Linux kernel.

## Known limits

- It does not watch real traffic yet.
- The portable key sealing protects against copied files, not against malware
  already running as you.
- Detection quality is unmeasured on real networks, and no real prior weights ship yet.
- It cannot see inside encrypted traffic, only who talked to whom.
- Windows builds are untested in CI.

## Contributing

Issues and pull requests are welcome. Run `go vet ./...` and `go test ./...`
before sending a change. The code is commented for people new to Go. Python
(PyTorch) is needed only for the offline model tools in `python/`; the product
itself is Go only. See [docs/model.md](docs/model.md) for how to regenerate the
test fixtures.

## Licence

GPL-3.0. See [LICENSE](LICENSE).
