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
| `internal/replay` | Record flows to JSONL(.gz) and play them back as a collector. |
| `internal/aggregate` | Rolls flows into one row per minute per (program, proto, dir, host, port). |
| `internal/score` | **`Scorer` interface** the model implements, plus `Notifier` and a no-op scorer. |
| `internal/store` | Encrypted SQLite (SQLCipher), WAL, 32-byte raw key. |
| `internal/keyseal` | `Provider` interface for the DB key, sealed to the machine. Portable baseline included. |
| `internal/service` | Supervisor: panic recovery, collector restart with backoff, bounded queue. |

## The two stable seams

**Collector** (`Run(ctx, emit func(event.Flow)) error`): passive, `emit` never
blocks, returns on cancel. Linux and Windows threads implement only this.

**Scorer** (`Score(ctx, []event.Minute) ([]Verdict, error)`): one verdict per
row, in order; may learn from the batch; errors and panics are survivable. The
model threads (heads A, B, C) implement only this. The scorer owns the alert
threshold and the ramp phase, so the core stays model-agnostic.

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
- Retention/pruning exists (`PruneBefore`) but is not scheduled yet.
- Real notifications (desktop toasts) are per-OS; only a log notifier exists.
- Cross-compiling for Windows needs a cgo toolchain (e.g. mingw) because of SQLCipher.
