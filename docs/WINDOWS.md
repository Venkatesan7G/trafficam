# trafficam on Windows (ETW collector)

Code: `internal/collector/etw` (capture) and `cmd/trafficam/service_windows.go`
(Windows service). Windows 10 and 11, 64-bit (x64 or ARM64).

## What it captures

| Field | Where it comes from |
|---|---|
| PID, local/remote IP and port, TCP or UDP | Microsoft-Windows-Kernel-Network (payload PID, not the header PID) |
| Bytes in/out per connection | Sum of that provider's send/receive events for the 4-tuple |
| Direction | Connect event = outbound, accept event = inbound, else guessed from ports |
| Duration | First to last event of the connection |
| Failed connections | TCP with retries and no byte back (time-outs, black holes) |
| DNS name per connection | Microsoft-Windows-DNS-Client event 3008, matched by PID then globally |
| DNS lookups by process, incl. failures | Same event; failed lookups are DNS flows with `Established=false` |
| Process path | `QueryFullProcessImageNameW`, or the Kernel-Process start event |
| Parent | Kernel-Process start event, or a Toolhelp snapshot |
| Windows service name | Service Control Manager (`EnumServicesStatusEx`), in `Program.Service` |
| Signer | `WinVerifyTrust`, embedded or catalog signatures, offline (no revocation lookups) |

Long connections are reported every minute (bytes since the last report),
and once more when they close.

## Verified on a real Windows machine

`TestLiveCapture` runs on every push on GitHub's Windows runner (as administrator) and checks:

1. **DNS events carry the asking process's PID.** A lookup made by the test
   process shows up with the test's PID; a lookup made by `curl.exe` shows up
   with curl's PID. Both PASS.
2. **Per-connection byte counts are exact.** Sending 123,456 bytes and
   receiving 7,890 over TCP gives a flow with exactly those totals; three
   100-byte UDP datagrams give 300 bytes. PASS.
3. **Our hand-written parsing of network events matches Windows' own decoder
   (TDH)** for PID, size, addresses and ports on every event seen. PASS.
4. svchost.exe running Dnscache is reported with service `Dnscache` and signer
   `Microsoft Windows Publisher`; curl.exe with signer `Microsoft 3rd Party
   Application Component` and the right parent.

Known limits found while verifying:

- A TCP connection **refused** on 127.0.0.1 produces no Kernel-Network event
  at all, so it is not reported. Time-outs (no answer) are reported as
  failed. Refusals from remote hosts are untested.
- Programs that do their own DNS (browsers with DNS-over-HTTPS switched on)
  bypass the DNS-Client, so their connections are labelled by IP, or by a name
  another process looked up.
- Traffic between two programs on this PC (loopback) is ignored by default.

## Safety

ETW is one-way: Windows writes events into buffers and we read them. If
trafficam is slow, Windows drops events (counted as `etw_lost` in the log),
it never waits for us. If trafficam crashes, nothing happens to networking;
the service restarts after 5 s and takes over the old ETW session. No driver
is installed.

## Try it on your PC

You need [Go 1.24+](https://go.dev/dl/) and a C compiler for the encrypted
database ([MSYS2](https://www.msys2.org/) then `pacman -S mingw-w64-ucrt-x86_64-gcc`,
and add `C:\msys64\ucrt64\bin` to PATH), or skip building and download
`trafficam-windows-amd64` from the "Artifacts" box of the latest CI run on
the Actions tab.

Open **Terminal as administrator** (right-click Start, "Terminal (Admin)"), then:

```powershell
git clone https://github.com/Venkatesan7G/trafficam
cd trafficam
git checkout claude/project-thread-yrfttw   # until the PR is merged

# 1. The capture check (about 20 s). Look for "Q1 PASS" and "Q2 PASS".
go test -v -run LiveCapture ./internal/collector/etw/

# 2. Watch your own traffic in the foreground. Browse a bit, then Ctrl+C.
go build -o trafficam.exe ./cmd/trafficam
.\trafficam.exe live -data .\trial
.\trafficam.exe dump -data .\trial

# 3. Run it as a Windows service (starts at boot).
.\trafficam.exe service install
.\trafficam.exe service start
Get-Content C:\ProgramData\trafficam\trafficam.log -Wait   # Ctrl+C to stop reading
.\trafficam.exe service stop
.\trafficam.exe service uninstall
```

Note: `dump` after the service needs `-data C:\ProgramData\trafficam`, and that
folder is readable by Administrators only.

## Not done yet

- Desktop notifications: the service runs in session 0 and cannot show
  toasts; alerts go to the log until a small tray helper exists.
- Key protection is still the portable `MachineIDProvider`; DPAPI/TPM is a follow-up.
- 32-bit Windows is not supported.
