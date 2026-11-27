# Tamper response

trafficam watches its own files as well as your network. If its database key
or database is interfered with, it does three things, always in this order:

1. **Loud alert.** A plain-text report is written to `TAMPER-ALERT.txt` in the
   data folder, logged as an error, and (once desktop notifications exist)
   shown as a notification that stays until you dismiss it. The alert comes
   back at **every start** until you dismiss it with `trafficam tamper ack` or
   by deleting the file. It is never silent.
2. **Self-destruct.** The key file is overwritten with random bytes and deleted
   (on Windows the TPM key behind it is deleted too). The database and the
   learned model are deleted. Without the key nobody can read them anyway;
   deleting them just makes that final.
3. **Fresh start.** A new key and an empty database are made straight away, so
   the PC is never left unwatched. Learning starts again from "Listening".

`trafficam tamper status` shows the current alert, if any.

## What counts as tampering

| Seen | When |
|---|---|
| The key file cannot be unsealed on this PC (copied from elsewhere, edited, or its TPM/account no longer matches) | at start |
| The database cannot be opened with its key (replaced or edited) | at start |
| The key file was deleted but the database is still there | at start |
| The database was deleted but the key is still there (key older than 5 minutes) | at start |
| The key file changed, or the key or database file was deleted or swapped for another file | while running, checked every 30 seconds |

## What does **not** count (nothing is destroyed)

- The TPM is busy, missing, or trafficam lacks permission to use it.
- The database is locked by another trafficam, or the disk reports an I/O error.
- A first start that crashed between writing the key and the database.

trafficam reports these as ordinary errors and leaves every file alone.

## Keeping the evidence instead

Start trafficam with `-on-tamper quarantine` to move the old files into a
`tampered-<time>` folder instead of deleting them. The key is still destroyed,
so the old database stays unreadable, but the files remain for anyone who wants
to look at their sizes and timestamps.

## Honest limits

- **This cannot stop an attacker with administrator/root rights.** Such an
  attacker can stop trafficam, delete everything, and delete the alert file
  too. The response only guarantees two things: nobody reads your history
  from a tampered setup, and any tampering trafficam itself sees is announced.
- Self-destruct also erases the history of whatever caused the tampering.
  That is the cost of "unreadable"; the alert is what tells you to look.
- Overwriting the key file may not reach the old disk blocks on SSDs. That is
  acceptable because the key file only ever holds the *sealed* key.
- On Linux the TPM-sealed key cannot be revoked short of clearing the TPM, so
  an old copy of the key file stays unsealable **on this same PC** by root.
  On Windows the TPM key is deleted, which revokes old copies.
- Edits deep inside the database while trafficam runs are caught by SQLCipher
  page checks when the page is read, which shows up as store errors in the
  log, not yet as a tamper alert.
- False alarms are possible after: clearing the TPM, reinstalling the OS,
  restoring the data folder from a backup made on another PC, or deleting
  trafficam's files by hand. In each case the alert explains what happened.

## For other parts of trafficam

`TAMPER-ALERT.txt` is the contract: plain UTF-8, the first line is a headline
starting with `TRAFFICAM TAMPER ALERT: `, and the file exists exactly while an
alert is unacknowledged. The notification agent shows it; `trafficam tamper
ack` deletes it.
