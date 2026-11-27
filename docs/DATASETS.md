# Datasets and licences for head C

**Status: nothing from these datasets is downloaded, bundled or used for any
shipped weight in this repository.** `python/prior/datasets.py` has loaders
written from the public documentation (not yet run on the real files), and
`train_prior.py --synthetic` exercises the pipeline on fake data. No head C
weights are in the repo.

Before any pack containing weights trained on one of these is published, someone
must read the current terms at the source and record the result here. The
"recollection" column is what I remember, **not verified**: web search in this
session returned only links, not the licence text.

| Source | Use in head C | Recollection (unverified) | Where to read the terms |
|---|---|---|---|
| CTU-13 / Stratosphere captures | botnet and C2 flow shapes | Published by CTU Prague / Stratosphere Lab; I believe a Creative Commons licence, possibly non-commercial or share-alike. Check, because share-alike or NC could conflict with GPL-3.0 weights in a pack. | https://www.stratosphereips.org/datasets-overview , https://www.stratosphereips.org/datasets-faq , https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/README.html |
| UNSW-NB15 | lab attack flows | Academic use with citation; commercial use may need permission from UNSW. | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| CIC-IDS2017 / 2018 | lab attacks (used with care: known labelling errors) | Free for research with citation; redistribution and commercial terms unclear. | https://www.unb.ca/cic/datasets/ids-2017.html |
| Public DGA domain lists | DNS-name shape of generated domains | Varies per list. Pick lists whose licence allows derived-model use. | per list |
| Tranco top sites | benign side | Research list; read its terms. | https://tranco-list.eu |
| abuse.ch (Feodo Tracker, URLhaus) | offline known-bad snapshot (not head C training) | I believe CC0, with a platform terms-of-use page; confirm. | https://abuse.ch/terms-of-use/ |

## Why this matters for a GPL-3.0 project

Trained weights are derived from the training data. If a dataset forbids
commercial use or requires share-alike under a different licence, shipping
weights derived from it may not be allowed, or may force terms on the pack.
Options if a licence blocks us: drop that dataset, ask the owners, or generate
equivalent traffic ourselves in the validation lab VM (C2 frameworks, scanners,
planted exfil), which we own outright.

## Rules for the training script

- `train_prior.py` prints the `--source` list into the weight file's
  `provenance` meta, so every pack records what it was trained on.
- The cross-dataset gate refuses to write weights if held-out AUC is below the
  threshold.
- Transferable features only (`python/prior/features.py`): no IPs, domains,
  ports or program names ever enter head C.
