# Handoff: notifications, window and lists (items 6, 11, 12)

State on 2026-11-27. Three stacked PRs, merge in order: #12 (lists) → #17 (notifications) → #21 (window).
Branches: `claude/project-thread-q4oa2c-lists`, `-notify`, `-ui`. Each later branch already has the
earlier ones merged in.

## Done
- `trafficam lists` (add/remove/edit/show), live reload, validation. Whole-program rules:
  `trafficam lists add ignore|watch -program NAME` (written as `* NAME`). NAME matches the program
  name, its path, or its service (Windows service / systemd unit). Ignoring a program never silences
  the known-bad list or the watch list (tested in internal/rules).
- Alerts stored in the DB (schema v4; repeats of an unread alert merge into one row with a count).
- Local API: Unix socket `/run/trafficam/api.sock` (SO_PEERCRED: root, own uid, `trafficam` group)
  or pipe `\\.\pipe\trafficam` (SYSTEM, Administrators, interactive user). No TCP.
- `trafficam agent`: notifications (D-Bus on Linux, toast via PowerShell on Windows), rate limit
  3/min, catch-up after login, tamper notice while `<data>/TAMPER-ALERT.txt` exists.
- The trafficam window (`trafficam ui`) on 127.0.0.1: one-time tickets, Host/Origin checks, CSP.
- `trafficam check [-json]` self-check, for installers.
- User guide with screenshots: docs/USER-GUIDE.md and the published page.

## Next steps
1. Windows check on a real desktop: `trafficam agent -test`, `trafficam agent`, `trafficam ui`,
   `trafficam check`. Nothing on Windows has been seen running yet (only unit tests and cross-vet).
2. CI is blocked by the repo's Actions setting (only actions owned by Venkatesan7G are allowed).
   Re-enable GitHub-created actions, then re-run CI on #12/#17/#21. The last real failure
   (Windows pipe name in tests) is fixed in 3aa3c1b.
3. If another PR also bumps the DB schema to v4, renumber the migrations on merge.
4. Installers (item 15) should: create the `trafficam` group and add the user (Linux), run
   `trafficam agent -autostart on` as the user, run `trafficam check -json` at the end.
5. Optional: tray icon; Windows toast buttons (needs a registered app identity).

## How to continue locally
`git fetch origin && git checkout claude/project-thread-q4oa2c-ui`, then `go test ./...`
(Linux needs a C compiler for SQLCipher; a dbus-daemon makes the D-Bus test run instead of skipping).
