# Measuring trafficam on real traffic

The question this answers: **on a real PC, used normally, how many alerts a day
does trafficam show?** On a clean machine every alert is a false alarm, so this
is the false-alarm rate. The design budget is about 1.5 alerts a day once the
install has settled.

Everything here runs on your own machine, offline. Nothing is uploaded. The
commands read the data `trafficam live` already keeps in its encrypted
database.

## How it works (the short version)

`trafficam eval` takes the minute rows recorded on a PC and **replays them
through a brand-new trafficam**, as if it had been installed at the first row:
the same rules, the same baseline counters, the same learning model, the same
nightly training at 03:00 of each replayed day. Because it is a replay, it can
run several versions side by side on exactly the same traffic:

| arm | what runs |
|---|---|
| `rules` | only the simple rules (new program, new destination for a settled program, your lists) |
| `rules+model` | the rules plus the learning model (heads A and B), which is what ships |
| `rules+model+prior` | the same plus head C (needs `-prior FILE`) |

It then counts **alerts**: one alert = the first alerted row for a program and
destination on a day. A beacon that trips 200 minute rows in a day is one
notification, so it counts once.

Two numbers matter in the report:

- **per day**: alerts divided by all days, including the quiet first days.
- **steady/day**: alerts per day after the 48 h install grace and (for arms
  with the model) after the model first trained. This is what a settled install
  feels like, and the number to compare with the 1.5/day budget.

The differences from the live watcher are small and deliberate: the clock is
the recording's own time, the baseline counters live in memory (a test checks
they count exactly like the database), and nightly training runs every
replayed night without the "only when idle and on mains power" check.

## Try it first on made-up traffic

    go build -o trafficam ./cmd/trafficam
    ./trafficam eval -synthetic 14 -train-cap 10s

That replays 14 days of a fake PC. Use it to learn the report, not to judge
trafficam: the fake PC is not a real one.

## Steps for a real multi-day run

You need: a Windows 10/11 PC or a Linux PC (kernel 6.1 or newer), used
normally, for **at least 14 days, ideally 30**. A VM you use daily counts; an
idle VM does not (it has almost no traffic, so it will look perfect).

### 1. Start the watcher and leave it running

Linux (needs root for eBPF):

    go build -o trafficam ./cmd/trafficam
    sudo install -m 755 trafficam /usr/local/bin/trafficam
    sudo systemd-run --unit=trafficam-trial --property=Restart=always \
        /usr/local/bin/trafficam live -data /var/lib/trafficam
    systemctl status trafficam-trial      # should say "active (running)"

`systemd-run` restarts it if it crashes, but not after a reboot. After a
reboot, run the `systemd-run` line again (same `-data` folder, so nothing is
lost). Proper packages with a permanent service are separate work.

Windows (PowerShell as Administrator):

    go build -o trafficam.exe ./cmd/trafficam
    .\trafficam.exe service install
    .\trafficam.exe service start

The service starts again by itself after a reboot. Its data is in
`C:\ProgramData\trafficam`.

### 2. Use the PC normally, and keep a short diary

Write down anything out of the ordinary with the date: installed or updated a
program, used a VPN, a new device on the network, travelled. When the report
lists an alert, the diary is how you tell "that was me installing Zoom" from
"I have no idea what that is".

### 3. Look at the numbers whenever you like

It is safe to do this while the watcher runs. Linux:

    sudo trafficam eval -data /var/lib/trafficam

Windows (as Administrator):

    .\trafficam.exe eval -data C:\ProgramData\trafficam

Training is replayed for every night, so a 30-day run takes a while (each
night is capped at 60 s per arm, as live). `-train-cap 15s` makes it faster
at a small cost in accuracy; `-arms rules` skips the model and is instant.

### 4. Save a copy before day 35

The database keeps 35 days. Export the rows so later runs (attack tests,
threshold tuning) can reuse them:

    sudo trafficam export -data /var/lib/trafficam -out ~/trafficam-pc1.jsonl.gz
    trafficam eval -in ~/trafficam-pc1.jsonl.gz

**The export file lists every program and destination your PC used.** Keep it
private. Do not send it to anyone unless you have read it and are happy to.

### 5. Read the report

For each arm you get a per-day table and the alerts to review. For each alert,
check your diary and write down whether it was real (something you did not
expect and do not want) or a false alarm, and why it fired (`new-program`,
`new-destination`, `model`, ...). Programs with many alerts are listed first:
they are where a threshold or a trust rule would help most.

What to record per machine, so machines can be compared:

| | |
|---|---|
| machine | e.g. "V's Windows laptop", "Ubuntu VM" |
| days recorded | |
| steady/day, each arm | from the Summary |
| worst day | from the Summary |
| real alerts found | from your review |
| top 3 noisy programs | from the alert list |

### 6. Volunteers

A volunteer follows steps 1 to 5 on their own PC and sends only the report
made with `-private`:

    trafficam eval -data ... -private > report.txt

`-private` replaces program paths and destinations with short random codes
and drops the reasons, so the report says how many alerts and why in general,
but not where the PC connects. Counts are identical. Ask them to add their
review (how many were real) as a sentence, not by sending the export file.

## Attack tests: does trafficam catch things, and does the model help?

A clean recording only shows false alarms. To see what trafficam **misses**,
attacks are planted and the arms are compared on the same traffic:

    trafficam attacks -in ~/trafficam-pc1.jsonl.gz          # plant into your recording
    trafficam attacks -synthetic 14 -train-cap 10s          # or into the fake PC

There are two ways to plant attacks.

**1. Planted into a recording (fast, any machine).** `trafficam attacks`
writes the minute rows nine attack scenarios would produce, mixes them into a
copy of the recording 75 % of the way through (`-at` to choose), and labels
them. The real recording is not changed.

| id | what it pretends | why it is there |
|---|---|---|
| `beacon-quiet` | a quiet program (few destinations) calls a new server every ~5 min | classic call-home |
| `beacon-browser` | the browser calls a new site every ~2 min | **hard for rules**: the browser visits new sites all day |
| `exfil-new` | a quiet program uploads ~600 MB to a new server | data theft |
| `exfil-known` | the same, to a server it already uses (abused cloud account) | **hard for rules**: nothing is new |
| `exfil-browser` | the browser uploads ~600 MB to a new site | **hard for rules** |
| `dga` | 300 random-looking lookups, most failing, then one connection | malware searching for its server |
| `dns-tunnel` | 2,000 long encoded names under one domain | data smuggled out through DNS |
| `scan` | 250 LAN addresses on SMB/SSH/RDP, nearly all refused | spreading inside the network |
| `dropper` | a never-seen program in a temp folder calls home | freshly dropped malware |

Quiet-program attacks take turns over the recording's quiet programs. A
program that has just looked up 300 names is no longer quiet, so if they all
used the same one, each attack would change how the next one looks.

The recording must be at least 6 days long (attacks start after day 4, when
programs count as settled). Longer is better.

**2. Real attack traffic in a VM (slower, the real thing).** `lab/vm` has
scripts that make attack-*shaped* traffic for real. They are not malware:
they call, upload to and scan a second VM that you run (`sink.py`), and they
write a labels file saying when each scenario ran and as which program.

1. Make two VMs on a host-only network: "victim" (Linux or Windows, with
   trafficam) and "sink" (any Linux with Python 3).
2. On the sink: `python3 lab/vm/sink.py`
3. On the victim, run trafficam as in step 1 above, and use the VM normally
   for at least 5 days (browse, update, install a thing or two) so the
   programs settle.
4. On the victim, run the scenarios (the whole set takes about 4 hours):

       SINK=192.168.56.20 ./lab/vm/plant.sh all                # Linux
       .\lab\vm\plant.ps1 -Sink 192.168.56.20 all             # Windows

5. Keep using the VM for a day, then compare:

       sudo trafficam attacks -data /var/lib/trafficam -labels labels.jsonl

The VM scripts run as `python3` / `powershell`, programs that already exist,
which is how a lot of real malware hides ("living off the land"). The DGA and
tunnel scenarios send junk lookups to your DNS resolver; they carry no data.
Only scan networks you own.

**Reading the result.** For each attack and arm: `caught` (at least one
alert on its rows) or `missed`, how long until the first alert, and what
raised it. Then, per arm, false alarms per steady day with the attack rows
left out, and where those false alarms came from. The last part answers your
question directly: `rules+model vs rules` lists the extra attacks the model
caught, the ones it caught sooner, anything it lost, and the false-alarm cost.
A model that adds nothing on real recordings is a model to rethink.

Caveat: planted rows are our own guess at what an attack looks like at the
minute level. The VM run is the check on that guess. On Linux, DNS lookups
often show up as made by `systemd-resolved` rather than the program that
asked, so the DNS scenarios can look different on a real Linux VM than when
planted.

## Tuning the "new destination" thresholds

Three settings decide when the rules start reporting new things:

| setting | default | what it does | flag |
|---|---|---|---|
| install grace | 48 h | no "new program" / "new destination" alerts while the install is younger | `-grace` |
| program age | 72 h | a program must be this old before its new destinations alert | `-program-age` |
| max hosts | 20 | programs with more known destinations (browsers) are left to the model | `-max-hosts` |

`trafficam tune` tries every combination on the same recording and ranks them:

    trafficam tune -in ~/trafficam-pc1.jsonl.gz                # rules only, fast
    trafficam tune -in ~/trafficam-pc1.jsonl.gz -model         # include the model's alerts
    trafficam tune -in ... -graces 24h,48h -ages 48h,72h,96h -hosts 10,20,40

It plants three waves of attacks, so the cost of waiting is measured too:
30 h after install (inside most graces), 60 h after install (programs still
young), and the full set 75 % of the way through. Ranking puts **catching
attacks first**, then fewest false alarms per day, then fewest false alarms
right after install. That follows your "low false alarms but no misses". The
report shows where the shipped default lands, and how each setting moves the
numbers on its own.

With `-model` the model runs once with the default settings and its verdicts
are reused for every combination (the thresholds don't change the model).
That keeps a sweep of 80 settings to about one model replay. The small
approximation: the model's 3-day "don't learn from rows that alerted" guard
saw the default settings' alerts.

**How to decide.** Don't change a default because of one machine. Run `tune`
on each recording (your PCs, the VM, volunteers' if they are willing to run
it themselves), and look for a setting that is in the top group on all of
them. Then change the defaults in `internal/rules/rules.go` (and the
`Default*` values in `internal/lab/tune.go`) in a PR of its own.

On the fake PC, the defaults miss every attack in the first 72 hours, by
design (grace plus program age). A 24 h program age catches the 60 h wave at no
extra false-alarm cost there. Whether that holds on a real PC, where young
programs pick up new servers all the time, is exactly what the real
recordings will tell.

## What this does not measure

- **Whether a clean recording is really clean.** Read the alert list.
- **Desktop notification behaviour.** The report counts what would be shown;
  how it is shown is separate work.
