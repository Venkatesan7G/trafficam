# trafficam

A quiet, local, offline watcher for your PC's network traffic. It learns what
each program normally talks to and tells you when one starts calling somewhere
new. It is **not** an antivirus and it never blocks anything.

- **Passive only.** No drivers, no packet-filter hooks, no proxy. If trafficam
  crashes, your network is unaffected.
- **Offline.** No server, no telemetry, nothing leaves your machine.
- **Private.** Metadata only (who, where, when, how much), never packet contents.
  Stored in an encrypted database with a machine-sealed key.
- **License:** GPL-3.0.

Status: shared core only. Platform capture (Linux eBPF, Windows ETW) and the
model are being built separately and plug in through two interfaces.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Try it

Needs Go 1.24+ and a C compiler (the encrypted database uses SQLCipher via cgo).

```sh
go test ./...
go run ./cmd/trafficam demo            # synthetic traffic through the whole pipeline
go run ./cmd/trafficam dump            # show what was stored (decrypted with the sealed key)
go run ./cmd/trafficam record -out c.jsonl.gz
go run ./cmd/trafficam replay c.jsonl.gz
```
