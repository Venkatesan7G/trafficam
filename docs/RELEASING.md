# Releases and packages

Downloads are built by `.github/workflows/release.yml`. Nothing is built on
ordinary pushes; only a version tag starts a release build.

## Making a release

```sh
git checkout main && git pull
git tag v0.1.0
git push origin v0.1.0
```

About 10 minutes later a **draft** release appears under *Releases*. Open it,
check the files and the notes, and press **Publish release**. Until then
nobody else can see it. To throw a bad build away, delete the draft and the
tag (`git push origin :v0.1.0`), fix, and tag again.

## What gets built

| File | For | Installs to |
|---|---|---|
| `trafficam-<v>-windows-amd64-setup.exe` | Windows 10/11 (64-bit) | `C:\Program Files\trafficam`, data in `C:\ProgramData\trafficam`, registers and starts the `trafficam` service |
| `trafficam-<v>-windows-amd64.zip` | Windows, no installer | wherever you unzip it (`trafficam.exe service install` by hand) |
| `trafficam_<v>_amd64.deb`, `_arm64.deb` | Debian 12+, Ubuntu 22.04+ | `/usr/bin/trafficam`, systemd unit, lists in `/etc/trafficam`, data in `/var/lib/trafficam` |
| `trafficam-<v>-1.x86_64.rpm`, `.aarch64.rpm` | Fedora, RHEL 9+, openSUSE | same as the .deb |
| `trafficam-<v>-linux-<arch>.tar.gz` | any Linux with glibc 2.35+ | wherever you unpack it |
| `SHA256SUMS.txt` | checking a download | `sha256sum -c SHA256SUMS.txt --ignore-missing` |

Linux packages do **not** start trafficam on their own. Start it with
`sudo systemctl enable --now trafficam` and follow alerts with
`journalctl -u trafficam -f`.

Removing a package or uninstalling on Windows keeps your encrypted database,
so a reinstall carries on learning. `sudo apt purge trafficam` (or answering
"Yes" in the Windows uninstaller) deletes it too.

## Every build is tested before it is attached

- Linux: the `.deb` is installed on the runner, `trafficam version` runs, the
  systemd unit is checked with `systemd-analyze verify`, then it is purged.
- Windows: the installer runs silently, the service must reach *Running*,
  then the uninstaller must remove it.
- Tag builds also run `go vet` and `go test` first.

A pull request that touches `packaging/` or the release workflow runs the
same build and checks, but creates no release.

## Not done yet

- **Code signing.** The Windows installer is not signed, so SmartScreen shows
  "Windows protected your PC" (click *More info* then *Run anyway*). Signing
  needs a certificate; free options for open-source projects include
  SignPath Foundation. The checksum file is not signed either; signing it
  (for example with minisign or GPG) fits with the signed knowledge packs.
- **Package repositories.** There is no apt or dnf repository; you download
  the file and install it with `sudo apt install ./trafficam_*.deb` or
  `sudo dnf install ./trafficam-*.rpm`.
