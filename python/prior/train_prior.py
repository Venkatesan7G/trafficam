"""Train head C (frozen prior-risk net, 14 -> 64 -> 64 -> 1) offline.

Development/release tool only; the product never runs this. Examples:

  python -I python/prior/train_prior.py --synthetic --out /tmp/head_c.tcw
  python -I python/prior/train_prior.py --dataset ctu13 \\
      --source neris,features,neris.csv --source rbot,features,rbot.csv --out head_c.tcw

--source is GROUP,KIND,PATH. Rows of one group are one "dataset" for the
cross-dataset gate: the net is trained on each group in turn and tested on the
others, and must clear --min-auc on every held-out group or no file is written
("a head C that doesn't transfer doesn't ship").

KIND "features" is a CSV written by `go run ./cmd/priorprep` (trafficam's own
feature code, so training and the watcher agree exactly). The older kinds
(ctu13, unsw, dga, benign) compute features in Python and are kept for
experiments.

--dataset names the public dataset(s) the sources come from; each must be
allowed in licences.py. Next to the weights, OUT.sources.json records the
datasets, their licences and citations, and the SHA-256 of every input file
and of the weights.
"""
import argparse
import csv
import hashlib
import json
import os
import sys

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prior import features as F  # noqa: E402
from trafficam_model import tcw  # noqa: E402


class PriorNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.l1, self.l2, self.l3 = nn.Linear(F.DIM, 64), nn.Linear(64, 64), nn.Linear(64, 1)

    def forward(self, x):
        return self.l3(torch.relu(self.l2(torch.relu(self.l1(x))))).squeeze(-1)  # logit


def auc(y, s):
    """Rank-based ROC AUC (no sklearn dependency)."""
    y = np.asarray(y)
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s))
    ranks[order] = np.arange(1, len(s) + 1)
    pos = y == 1
    n1, n0 = pos.sum(), (~pos).sum()
    if n1 == 0 or n0 == 0:
        return float("nan")
    return float((ranks[pos].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def fit_norm(x):
    mean = np.nanmean(x, axis=0)
    std = np.nanstd(x, axis=0)
    mean = np.where(np.isnan(mean), 0.0, mean)
    std = np.where(np.isnan(std) | (std < 1e-3), 1.0, std)
    return mean.astype("f4"), std.astype("f4")


def standardise(x, mean, std):
    z = (x - mean) / std
    return np.nan_to_num(z, nan=0.0)  # missing -> the training mean


def train(x, y, mean, std, epochs=40, seed=0, dropout=0.1):
    torch.manual_seed(seed)
    z = torch.tensor(standardise(x, mean, std), dtype=torch.float32)
    t = torch.tensor(y, dtype=torch.float32)
    net = PriorNet()
    opt = torch.optim.Adam(net.parameters(), lr=3e-3, weight_decay=1e-4)
    pw = torch.tensor(max(1.0, float((t == 0).sum()) / max(1.0, float((t == 1).sum()))))
    lossf = nn.BCEWithLogitsLoss(pos_weight=pw)
    g = torch.Generator().manual_seed(seed)
    for _ in range(epochs):
        perm = torch.randperm(len(z), generator=g)
        for i in range(0, len(z), 256):
            idx = perm[i:i + 256]
            xb = z[idx]
            # feature dropout toward the mean: robustness to sources that lack a feature (GUESS)
            xb = xb * (torch.rand_like(xb, generator=g) > dropout)
            opt.zero_grad()
            lossf(net(xb), t[idx]).backward()
            opt.step()
    return net


def score(net, x, mean, std):
    with torch.no_grad():
        return torch.sigmoid(net(torch.tensor(standardise(x, mean, std), dtype=torch.float32))).numpy()


def cross_dataset_gate(groups, min_auc, epochs):
    """groups: {name: (x, y)}. Train on one, test on every other."""
    ok, report = True, []
    names = list(groups)
    for tr in names:
        x, y = groups[tr]
        mean, std = fit_norm(x)
        net = train(x, y, mean, std, epochs)
        for te in names:
            if te == tr:
                continue
            a = auc(groups[te][1], score(net, groups[te][0], mean, std))
            report.append((tr, te, a))
            if not (a >= min_auc):
                ok = False
    return ok, report


def export(net, mean, std, path, provenance):
    sd = {k: v.detach().numpy() for k, v in net.state_dict().items()}
    tensors = [("w1", sd["l1.weight"]), ("b1", sd["l1.bias"]), ("w2", sd["l2.weight"]), ("b2", sd["l2.bias"]),
               ("w3", sd["l3.weight"]), ("b3", sd["l3.bias"])]
    tcw.write(path, tcw.KIND_PRIOR, tensors,
              {"norm_mean": [float(v) for v in mean], "norm_std": [float(v) for v in std],
               "features": F.NAMES, "provenance": provenance})


def load_features_csv(path):
    """Rows from cmd/priorprep: group,label,<14 features>; 'nan' = missing."""
    xs, ys = [], []
    with open(path, newline="") as fh:
        r = csv.reader(fh)
        head = next(r)
        if head[2:] != F.NAMES:
            sys.exit(f"{path}: columns {head[2:]} do not match features.py {F.NAMES}")
        for row in r:
            ys.append(float(row[1]))
            xs.append([float(v) for v in row[2:]])
    return np.array(xs, dtype=np.float32), np.array(ys, dtype=np.float32)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sources(out, datasets, sources, report, groups, extra):
    from prior import licences
    doc = {
        "weights": os.path.basename(out),
        "weights_sha256": sha256_file(out),
        "datasets": [dict(licences.DATASETS[d], id=d) for d in datasets],
        "excluded": [{"id": k, "name": v["name"], "reason": v["why_not"]}
                     for k, v in licences.DATASETS.items() if not v["allowed"]],
        "inputs": [{"group": g, "kind": k, "file": os.path.basename(p), "sha256": sha256_file(p)}
                   for g, k, p in sources],
        "groups": {g: {"rows": int(len(y)), "positives": int(y.sum())} for g, (_, y) in groups.items()},
        "cross_dataset_auc": [{"train": a, "test": b, "auc": round(v, 4)} for a, b, v in report],
    }
    doc.update(extra)
    with open(out + ".sources.json", "w") as f:
        json.dump(doc, f, indent=2)
    print("wrote", out + ".sources.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--synthetic", action="store_true", help="two synthetic labs; exercises the pipeline only")
    ap.add_argument("--source", action="append", default=[], help="GROUP,KIND,PATH (kind: features|ctu13|unsw|dga|benign)")
    ap.add_argument("--dataset", action="append", default=[], help="public dataset the sources come from (see licences.py)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-auc", type=float, default=0.85)
    ap.add_argument("--epochs", type=int, default=40)
    a = ap.parse_args()

    groups = {}
    sources = []
    if a.synthetic:
        from prior import synth
        for lab, seed in (("a", 1), ("b", 2)):
            rows, y = synth.make(6000, lab, seed)
            groups["synthetic-" + lab] = (F.matrix_nan(rows), y)
        prov = "SYNTHETIC DATA: pipeline test only, do not ship"
    else:
        from prior import datasets as D, licences
        if not a.dataset:
            sys.exit("name the public dataset(s) with --dataset (see python/prior/licences.py)")
        for d in a.dataset:
            licences.check(d)
        loaders = {"ctu13": D.load_ctu13_binetflow, "unsw": D.load_unsw_nb15,
                   "dga": lambda p: D.load_domain_list(p, 1), "benign": lambda p: D.load_domain_list(p, 0)}
        acc = {}
        for s in a.source:
            g, kind, path = s.split(",", 2)
            if kind == "features":
                x, y = load_features_csv(path)
            else:
                rows, y = loaders[kind](path)
                x, y = F.matrix_nan(rows), np.array(y, dtype=np.float32)
            xs, ys = acc.setdefault(g, ([], []))
            xs.append(x)
            ys.append(y)
            sources.append((g, kind, path))
        for g, (xs, ys) in acc.items():
            groups[g] = (np.concatenate(xs), np.concatenate(ys))
        prov = "datasets: " + ", ".join(licences.DATASETS[d]["name"] + " (" + licences.DATASETS[d]["licence"] + ")"
                                        for d in a.dataset) + "; groups: " + ", ".join(groups)
    if len(groups) < 2:
        sys.exit("need at least two dataset groups for the cross-dataset gate")
    ok, report = cross_dataset_gate(groups, a.min_auc, a.epochs)
    for tr, te, v in report:
        print(f"train {tr:>18} -> test {te:<18} AUC {v:.3f}")
    if not ok:
        sys.exit(f"GATE FAILED: held-out AUC below {a.min_auc}; no weights written")
    x = np.concatenate([g[0] for g in groups.values()])
    y = np.concatenate([g[1] for g in groups.values()])
    mean, std = fit_norm(x)
    net = train(x, y, mean, std, a.epochs)
    export(net, mean, std, a.out, prov)
    print("wrote", a.out)
    if not a.synthetic:
        write_sources(a.out, a.dataset, sources, report, groups, {"min_auc": a.min_auc, "epochs": a.epochs})


if __name__ == "__main__":
    main()
