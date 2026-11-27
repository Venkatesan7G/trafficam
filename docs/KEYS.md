# How the database key is protected

trafficam's history lives in an encrypted database (SQLCipher, AES-256). The
32-byte key is random, made on first start, and never typed by anyone. This
page explains where that key is kept and, just as important, what that does
and does not protect against.

## What protects the key, per system

trafficam picks the strongest method that works on the PC, checks that it can
read back what it just wrote, and only then saves the key. The method's name
is written at the start of the key file (`db.key`), and the log prints it on
every start (`database key protected method=...`).

| System | Method (best first) | What it needs |
|---|---|---|
| Windows | `windows-tpm`: an RSA key inside the TPM chip (Microsoft Platform Crypto Provider) encrypts the database key, and DPAPI wraps the result | a TPM 2.0 chip that Windows can use (most PCs since 2016; required by Windows 11) |
| Windows | `dpapi`: Windows Data Protection API, tied to the account trafficam runs as | nothing, always present |
| Linux | `linux-tpm2`: a TPM 2.0 "sealed object" via `/dev/tpmrm0` | a TPM chip, and root (or the `tss` group) |
| Linux | `machine-id`: a key derived from `/etc/machine-id` | nothing, always present |

If a TPM appears later (enabled in the BIOS, say), the key is moved to it
automatically the next time trafficam starts. The key itself does not change,
so no history is lost.

Key files from earlier builds have no header; they are machine-id files and
are upgraded the same way.

## What each method stops

| Threat | machine-id | dpapi | TPM methods |
|---|---|---|---|
| Someone copies the trafficam folder to another PC | stopped | stopped | stopped |
| Someone copies a backup of your files | stopped | stopped | stopped |
| Someone takes the whole disk (stolen laptop, old drive sold) | **not stopped**: the machine id is on the same disk | partly: needs your Windows password or offline tools for the system account | stopped: the TPM chip stays in the PC |
| Malware running as administrator/root while the PC is on | **not stopped** | **not stopped** | **not stopped** |

The last row matters: anything that runs with the same power as trafficam can
ask the TPM or DPAPI to unseal the key, exactly as trafficam does. No key
storage can prevent that. What trafficam can do about such tampering is the
loud alert described in the tamper-response work.

## Things that will lose the key

These are rare, but they make the history unreadable. trafficam then starts
learning again from scratch:

- Clearing the TPM (a BIOS "clear TPM" option, some firmware updates, moving
  the disk to a new motherboard).
- On Windows, an administrator resetting the account's password (a normal
  password change is fine), or reinstalling Windows.
- On Linux without a TPM, regenerating `/etc/machine-id`.

## Deliberate choices

- **No boot-measurement (PCR) binding on the TPM.** Binding would also notice
  a tampered boot chain, but every kernel, bootloader or firmware update would
  lock you out of your own history. For a watcher that should be invisible,
  that trade is not worth it.
- **The Linux kernel keyring is not used.** It forgets everything at reboot,
  so it cannot keep a key at rest. TPM or nothing better.
- **The TPM owner password is assumed empty** (the default). If you have set
  one, the TPM method reports "not available" and the next method is used.
- **A TPM that is busy or missing is never treated as tampering.** Only a key
  file that the TPM positively rejects counts as "cannot be unsealed here".

## How it is tested

- Unit tests for choosing, falling back, upgrading and rejecting files.
- The Linux TPM code runs against `swtpm`, a software TPM, in CI: seal,
  unseal, a flipped byte is rejected, a blob from a different TPM is
  rejected, and a TPM that goes away is reported as "unavailable", not as
  tampering.
- DPAPI runs for real on the Windows CI runner. The Windows TPM path runs
  only on a PC that has a TPM (GitHub's runners usually do not), so it has
  **not yet been run on real hardware**. Running `go test ./internal/keyseal`
  on a Windows 11 PC will exercise it.
