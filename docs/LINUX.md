# Linux collector (eBPF)

Code: `internal/collector/linuxebpf`. It implements `collector.Collector`, so the
rest of trafficam doesn't know or care that it runs on Linux.

## Requirements

- **Linux 6.1 or newer.** 6.1 is the first long-term-support kernel with
  everything used here: BPF ring buffer (5.8), fentry/fexit hooks on arm64 (6.0),
  and `bpf_get_func_ret` (5.17). Tested on 6.18 and 7.0. Older kernels get a clear error.
- **BTF type info** at `/sys/kernel/btf/vmlinux`. Ubuntu, Debian, Fedora, Arch,
  openSUSE and RHEL 9 all ship it.
- **root**, or the capabilities `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_RAW`.
- x86-64 or arm64.

## What it sees

| | How | Per flow |
|---|---|---|
| TCP out/in | `tp_btf/inet_sock_set_state` (every TCP state change) | PID, exe path, parent, systemd unit, local/remote address and port, direction, bytes each way, packets, duration, handshake completed or failed |
| TCP owner of inbound | `listen()` seen by the same hook; servers that were already running are read from `/proc` at start; `fentry/tcp_sendmsg`/`tcp_recvmsg` as a last resort | |
| UDP | `fexit/udp_sendmsg`, `udp_recvmsg` (+ IPv6 versions) count bytes per (socket, peer) in a kernel table; user space reads it every 5 s | same as TCP, minus handshake |
| DNS | read-only packet socket (like tcpdump) with a filter for UDP port 53; the program comes from a kernel table (local port → owner), checked again for up to 0.6 s if the packet is read before the kernel has filled it in | the name looked up; answers label later connections with the name (`Flow.DNSName`) |

When flows are reported:

- TCP: when the connection closes. If it is still open after 30 s it is also
  reported then (without byte counts), so a new long-lived connection is
  noticed within 30 s. The closing report is marked `cont` (a continuation):
  it carries the totals and only the time since the early report, and it is
  not counted as a second connection.
- UDP: within 5 s of the first packet with a new peer, then once a minute while
  active, and a last time 30 s after it goes quiet.
- DNS: as each question is sent.

Connections from the PC to itself (127.0.0.1, ::1) are left out by default.

## Safety

- Every hook is a tracing hook. It runs beside the kernel's code and cannot change
  a return value, drop, delay or redirect a packet. The DNS socket only receives copies.
- If trafficam crashes or is killed, the kernel removes the hooks itself. Nothing
  stays behind, and the network carries on as before.
- Kernel tables are LRU maps (the oldest entry goes when full) and the ring buffer
  drops events rather than wait, so a flood of traffic can't stall the kernel side.
- No packet contents are kept. DNS packets are parsed for the name and addresses,
  then thrown away.

## Known limits

- Encrypted DNS (DNS over HTTPS/TLS, such as a browser's "secure DNS") can't be
  read. Those connections still show up, by IP address only.
- DNS over TCP (rare) isn't parsed.
- Connections already open when trafficam starts are only seen once new ones start.
- TCP byte counts come from sequence numbers, so SYN/FIN can add 1–2 bytes.
- Some locked-down or virtual kernels refuse fentry/fexit hooks. Then trafficam
  logs a loud error and keeps watching TCP only, without UDP or DNS owners.

## Test it on your own Linux machine

You need Go 1.24+ and git. You don't need clang, because the compiled eBPF
bytecode is committed.

```sh
git clone https://github.com/Venkatesan7G/trafficam
cd trafficam
git checkout claude/project-thread-t7q9vg   # until the PR is merged

uname -r                          # must be 6.1 or higher
ls /sys/kernel/btf/vmlinux        # must exist

# 1. Unit tests (no root needed)
go test ./internal/collector/linuxebpf

# 2. Live tests: load the eBPF program into your kernel and check real flows
go test -c -o /tmp/ebpf.test ./internal/collector/linuxebpf
sudo TRAFFICAM_EBPF_TEST=1 /tmp/ebpf.test -test.run Live -test.v

# 3. Watch your own traffic for 60 seconds (prints one JSON line per flow)
go build -o /tmp/ebpfcheck ./cmd/ebpfcheck
sudo /tmp/ebpfcheck -for 60s
#    ...meanwhile, in another terminal: open a website, run `curl https://example.com`,
#    `sudo apt update`, etc. Check that the program names and DNS names make sense.
```

Things worth checking by eye in step 3:

- `curl` shows `"name":"curl"`, `"path":"/usr/bin/curl"`, a `"dns"` name and
  `"est":true`.
- Your browser's connections show the browser's real path, not just a short name.
- `"proto":"dns"` lines name the program that asked (often `systemd-resolved` for the
  upstream query, *and* the app itself for its question to `127.0.0.53`).
- Nothing is slow, and nothing breaks if you press Ctrl+C or `sudo kill -9` it.

If step 2 or 3 fails, paste the error into the project thread. Errors that start
with "kernel rejected the eBPF program" include the verifier's log, which says
exactly which line it didn't like.

## Changing the eBPF code

Edit `bpf/trafficam.bpf.c`, then regenerate the bytecode and Go bindings:

```sh
sudo apt install clang llvm libbpf-dev     # once
go generate ./internal/collector/linuxebpf
```

`bpf/vmlinux_min.h` declares only the kernel fields we read. Thanks to CO-RE, the
loader finds their real positions in the running kernel by name, so one compiled
file works on every supported kernel. If you read a new kernel field, add it there.

Licence: the eBPF C files are `GPL-2.0-only OR GPL-3.0-or-later`. The kernel only
loads tracing programs with a GPLv2-compatible licence, and the rest of trafficam
is GPL-3.0, so the dual licence makes the C file valid in both places.
