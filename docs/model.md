# The model

Code: `internal/model` (the model), `internal/modelscore` (plugs it into the
core's `score.Scorer`), `python/` (offline tools). Full design: the design doc.

## What is built

| Part | Where | Status |
|---|---|---|
| Heads A and B, 94,180 parameters, hand-written Go forward and backward | `internal/model/net.go` | done, matches PyTorch |
| Feature encoder (64 inputs: hashed embeddings, one-hot, 20 standardised numerics) | `encode.go` | done |
| Nightly training: AdamW, masking, recency and inverse-sqrt weights, poison guard, feedback weights, 60 s cap | `train.go` | done |
| Per-program percentile tables, self-set alert line, scoring | `model.go`, `nightly.go` | done |
| Nightly gate: last-24 h holdout, loss within 10 %, replay within 2x alert budget | `nightly.go` | done |
| Top-feature explanations (occlusion for A, relative error for B) | `explain.go` | done |
| Head C loader and scorer, capped boost | `headc.go`, `model.go` | done |
| Head C trainer, cross-dataset gate | `python/prior` | done, **synthetic data only** |
| One weight-file format, Go and Python | `weights.go`, `python/trafficam_model/tcw.py` | done |
| Adapter to `score.Scorer`, feature tracker, nightly loop | `internal/modelscore` | done |
| Baseline counters, hard always-alert rules, blocklist | | **not in this PR** |

## Weight file (TCW1)

One format for the main model and head C: magic, kind, JSON meta, named
float32 tensors, SHA-256 trailer. Layout is documented in `weights.go` and
`tcw.py`. The trailer rejects truncated or edited files. A saved main model
carries its learned state (standardisation, program classes, percentile tables,
alert line) in meta; head C carries its standardisation constants.

## Testing against PyTorch

`python/trafficam_model/reference.py` is a PyTorch copy of the network (dev only;
the product never imports torch). `golden.py` writes random weights, a batch,
and PyTorch's loss and every parameter gradient into `internal/model/testdata`.
`TestAgainstPyTorch` loads them and checks Go's forward outputs, per-sample
losses and all 19 gradient tensors. `TestFiniteDifference` is an independent
numerical check. `golden_prior.py` does the same for head C, including feature
extraction parity.

    pip install torch numpy
    python3 -I python/trafficam_model/golden.py internal/model/testdata
    python3 -I python/prior/golden_prior.py internal/model/testdata
    go test ./internal/...

## Interface to the core

`modelscore.Scorer` implements `score.Scorer`. Rows arrive per minute; a
`Tracker` derives the model's features (first-seen, contact regularity, fan-out,
failure rate, DNS-name shape) statefully. Training replays `store.Since` through
a fresh tracker so training and live features are identical. Before the first
training (needs 10,000 rows) the scorer never alerts and reports the
`Listening` phase. `Scorer.TrainNow` and `Scorer.Loop` run the nightly job;
wiring them into `cmd/trafficam` is left to the core.

## Things the core's rows do not have yet

The model degrades gracefully, but these would help:
- Parent program and signer are not stored, so history replays without them.
  `Tracker.UseProgramMeta` is off until the store keeps them.
- ASN and country need the offline database (not built); both are empty today.
- Connection duration; packets stand in for "send events" (guess).

## Guesses (mine, to measure or confirm)

- Alert-line recipe: the score exceeded about 1.5 times a day in the training window (in-sample, so the holdout replay check is what catches optimism).
- Score = max(percentile A, percentile B) + 10 for a new destination + head C up to 15 (only when the local score is already at least 80).
- Masking: 10 % of the 20 numeric inputs are zeroed; categoricals are not masked.
- Weighting uses per-row loss weights instead of resampling (same expectation).
- Standardisation is fitted once on the first training run, then frozen.
- AdamW with decay on weight matrices and embeddings only.
- Destination key: registrable domain by a small suffix list (not the full Public Suffix List); IPs grouped by /24 or /48.
- Head C trains with missing features imputed to the training mean, plus 10 % feature dropout.

## Results so far, and what they are not

On a synthetic machine (`sim_test.go`: 7 programs, 30 days, 69k rows) the first
model trains in about 5 s on 4 cores, raises 0 alerts on a fresh normal day and
catches 20 of 20 planted beacon, exfil, generated-domain and scan flows. Normal
traffic to a **brand-new site** with ordinary byte counts is caught 0 of 5; that
case is the baseline's novelty rule and the always-alert rules, which are not
in this PR. These numbers show the machinery works, not that detection works on
real traffic. That needs the volunteer recordings and lab attacks in the design
doc, and the baseline-versus-baseline-plus-network ablation.
