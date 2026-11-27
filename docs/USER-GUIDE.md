# trafficam user guide (draft)

The full illustrated version is the published guide page. This is the short text version.

**What it is.** trafficam quietly learns which places each program on your PC normally talks to,
and shows a notification when one starts talking somewhere new. It only watches: it never blocks,
never deletes, and sends nothing off your PC. It is not an antivirus.

**Not released yet.** There is no installer yet; the features below are in pull requests #12, #17
and #21, waiting for review. Windows notifications and the window have not been tried on a real
Windows desktop yet.

## The 30-day ramp
Listening (days 0-3) → Settling in (4-10) → Watching (11-29) → Guarding (30+). Nothing to teach it.

## When you get an alert
Open it with `trafficam ui` (or click the notification). **OK** = "I know about this".
**Don't show again** = put that program + destination on the ignore list.

## Your lists
```
trafficam lists                                   # show
trafficam lists add watch example.org             # always tell me
trafficam lists add watch -program powershell.exe # tell me about everything this program does
trafficam lists add ignore -program backupd       # ignore a whole program or service (admin)
trafficam lists remove ignore example.net
```
Ignoring never silences the known-bad list or your watch list.

## Install (testers, until installers ship)
Windows (admin terminal): `trafficam.exe service install`, `trafficam.exe service start`.
Then as yourself: `trafficam.exe agent -autostart on`, `trafficam.exe agent -test`, `trafficam.exe check`.

Linux: `sudo groupadd -f trafficam && sudo usermod -aG trafficam $USER` (log out and in),
`sudo ./trafficam live`, then `./trafficam agent -autostart on`, `./trafficam check`, `./trafficam ui`.
