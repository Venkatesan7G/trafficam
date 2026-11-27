# Handoff: validating the model (items 2, 3, 4, 5)

Written 2026-11-27 so the work can continue in a local agent session.

## PRs (review in this order; each is stacked on the one before)

| PR | item | branch | state |
|---|---|---|---|
| #19 | 2: `trafficam eval` / `export`, false alarms per day | `claude/project-thread-z2vpky` | done |
| #22 | 4: `trafficam attacks`, planted attacks + VM lab, rules vs rules+model | `claude/project-thread-z2vpky-attacks` | done |
| #23 | 5: `trafficam tune`, threshold sweep | `claude/project-thread-z2vpky-tuning` | done (tool); defaults unchanged |
| draft | 3: head C on CTU-13 | `claude/project-thread-z2vpky-headc` (based on `main`) | unfinished: training not yet run to the end |

## What's settled

- Licences (checked on the datasets' own pages, recorded in `python/prior/licences.py`):
  CTU-13 is **CC BY 2.0**, so it's usable with attribution. **UNSW-NB15** is out
  ("commercial use is strictly prohibited"). **CIC-IDS** is out (no licence terms).
- The "about 90 false alarms a day" seen on the fake PC was an artifact: all of
  the fake browser's sites shared `example.com`. It's fixed in #19. The real
  weakness behind it is described in the #19 PR text: the model's
  "other programs use this destination" feature can storm when a new app
  touches a domain the browser uses heavily, and the nightly gate then keeps
  rejecting retrains. Watch for it on real PCs.
- Found by #22: the rules miss big uploads to known servers or from the browser.
  A burst of 20+ new names also switches the new-destination rule off for that
  program (the max-hosts count is all-time). Both are design decisions for V.

## Unfinished: head C (item 3), exact next steps

Branch `claude/project-thread-z2vpky-headc` has:
- `cmd/priorprep`: CTU-13 binetflow to head C rows, using trafficam's own
  `modelscore.Tracker` and `model.PriorFeatures` (train/serve parity). DNS and
  signing features are written as NaN (not in flow captures).
- `python/prior/licences.py`: the licence registry. The trainer refuses anything not allowed.
- `train_prior.py`: new `features` source kind, `--dataset`, and an
  `OUT.sources.json` sidecar (licences, citations, input and weight SHA-256).
  The knowledge-pack thread agreed to this format: head C stays plain TCW1 `prior.tcw`.
- `python/prior/build_ctu13.sh`: one command, download, check, unpack, prep, train.
- A fix: the CTU-13 labels start with `flow=` (the old Python loader missed every row).

To finish, on a machine with Go, Python, numpy and torch:

    pip install numpy torch
    python/prior/build_ctu13.sh          # ~30-60 min, 2 GB download

Then:
1. Read the cross-dataset AUC table it prints. Families with very few botnet
   rows (sogou: 21, virut: 298) make the per-pair gate noisy. If the gate fails
   only on those, merge them into a "small" group or drop them, and say why in
   the PR. Don't lower `--min-auc` silently.
2. Commit `data/head_c.tcw` and `data/head_c.tcw.sources.json` only if the gate
   passes (or hand them to the knowledge-pack thread as `prior.tcw`).
3. With #22 merged, measure whether head C helps:
   `go run ./cmd/trafficam attacks -synthetic 14 -train-cap 10s -arms rules,rules+model,rules+model+prior -prior data/head_c.tcw`
   and later on real recordings (`-in FILE`).
4. Update `docs/DATASETS.md` with the licence results (they are in `licences.py`).

## Real-machine runs (items 2 and 5), V's steps

All in `docs/VALIDATION.md`. Short version:
1. Run `trafficam live` for 14 to 30 days (Linux: the `systemd-run` line;
   Windows: `trafficam service install` then `start`). Keep a diary.
2. `trafficam eval -data DIR`: alerts per day and steady/day per arm.
3. `trafficam export -data DIR -out pc1.jsonl.gz` before day 35.
4. `trafficam attacks -in pc1.jsonl.gz` and `trafficam tune -in pc1.jsonl.gz [-model]`.
5. VM lab: `lab/vm/sink.py` on a second VM, then `plant.sh` / `plant.ps1`, then `trafficam attacks -labels labels.jsonl`.
6. Change the 48 h / 72 h / 20 defaults only after `tune` agrees across several machines.

## CI

No PR here touches `.github/workflows`. All new tests take under 5 s. Long runs
(model comparison) need `TRAFFICAM_LAB_LONG=1` and never run in CI.
