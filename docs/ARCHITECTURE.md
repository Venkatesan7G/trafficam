# Architecture (shared core)

```
 collector ──emit()──▶ bounded queue ──▶ aggregator ──▶ scorer ──▶ store (SQLCipher)
 (Linux eBPF /                             (1-min rows)    │
  Windows ETW /                                            └──▶ notifier
  replay / synthetic)
```

| Package | Job |
|---|---|
| `internal/event` | `Flow` (raw observation) and `Minute` (per-minute rollup), both with a schema version. |
| `internal/collector` | **`Collector` interface** the OS capture layers implement, plus a synthetic mock. |
| `internal/collector/etw` | Windows capture via ETW, no driver. See [WINDOWS.md](WINDOWS.md). |
| `internal/replay` | Record flows to JSONL(.gz) and play them back as a collector. |
| `internal/aggregate` | Rolls flows into one row per minute per (program, proto, dir, host, port). |
| `internal/score` | **`Scorer` interface** the model implements, plus `Notifier` and a no-op scorer. |
| `internal/store` | Encrypted SQLite (SQLCipher), WAL, 32-byte raw key. |
| `internal/keyseal` | `Provider` interface for the DB key, sealed to the machine. Portable baseline included. |
| `internal/enrich` | Offline CIDR -> ASN/country table; fills `Minute.ASN`/`Country`. |
| `internal/blocklist` | Plain-text domain/IP/CIDR lists (known-bad snapshot, watch list, ignore list). |
| `internal/baseline` | Per (program, destination) counters: first seen, days seen, auto-absorb after 3 days. |
| `internal/rules` | Always-alert rules, merged with the model by one `score.Scorer`. |
| `internal/service` | Supervisor: panic recovery, collector restart with backoff, bounded queue. |

## The two stable seams

**Collector** (`Run(ctx, emit func(event.Flow)) error`): passive, `emit` never
blocks, returns on cancel. Linux and Windows threads implement only this.

**Scorer** (`Score(ctx, []event.Minute) ([]Verdict, error)`): one verdict per
row, in order; may learn from the batch; errors and panics are survivable. The
model threads (heads A, B, C) implement only this. The scorer owns the alert
threshold and the ramp phase, so the core stays model-agnostic.

## Rules next to the model

`rules.Scorer` wraps the model's `Scorer`. It alerts if either side would and
lists every reason. If the model fails or panics the rules still answer.

1. Known-bad snapshot hit: always alerts (opt-in file, `-blocklist`).
2. Your watch list hit: always alerts (`-watch`).
3. A program using the network for the first time: alerts, after the 48 h install window.
4. A settled program (>= 72 h old, <= 20 known destinations) contacting a new destination: alerts. High fan-out programs such as browsers are left to the model.

Your ignore list (`-ignore`) silences 3, 4 and the model, but never 1 or 2.
List files: one rule per line, `domain`, `ip` or `cidr`, optionally followed by a program name; `#` comments.
Baseline counters (`seen` table) are kept when old minute rows are pruned.

## Background tasks

`service.Config.Tasks` runs supervised background jobs (panic recovery, restart
with backoff). The prune job (35 days of rows) is registered in `cmd/trafficam`.
The model's nightly training registers the same way: `modelscore.Scorer.Loop(ctx)`
as a `service.Task` (see the comment in `cmd/trafficam/main.go`).

## Safety rules enforced by the service

- `emit` drops flows when the queue is full (live mode) instead of blocking capture.
- Collector, scorer, store and notifier calls are wrapped in `recover()`.
- A failing collector restarts with exponential backoff (1s → 1m).
- Scorer failure stores the batch unscored; it never stops the pipeline.
- Replay (`OneShot`) mode is lossless: it waits rather than drops.

## Known gaps (deliberately left for follow-ups)

- `keyseal.MachineIDProvider` defends against copied files, not malware running
  as you. Windows DPAPI/TPM and Linux TPM2 providers should replace it.
- Tamper handling: the store reports `ErrCannotOpen`; the loud-alert and
  self-destruct policy is not implemented yet.
- Updates come as signed offline knowledge packs (blocklist, head C, trusted OS
  list, ASN table); no signing key exists yet. Details: [PACKS.md](PACKS.md).
- No offline ASN/country data file is shipped; `-asn` takes a CSV someone builds from a public snapshot.
- The store allows one connection, so a long history read for training briefly delays inserts.
- Real notifications (desktop toasts) are per-OS; only a log notifier exists.
- `Program.Service` (schema v3) holds the Windows service / systemd unit; `Key()` appends it so services sharing svchost.exe get separate baselines.
- Cross-compiling for Windows needs a cgo toolchain (e.g. mingw) because of SQLCipher.
