"""Loaders for the public datasets head C is meant to be trained on.

NOTHING IS DOWNLOADED OR BUNDLED BY THIS REPO. Read docs/DATASETS.md first:
several of these datasets carry non-commercial or research-only terms, and the
licence review must be finished before any derived weights ship in a pack.

Each loader returns (rows, labels) in the dict schema of features.py.
Features a dataset cannot provide (flow captures have no DNS or signing
information) are set to None here; train_prior.py imputes them with the
training mean so the net neither learns nor relies on them from that source.
That is a design GUESS to be checked in the ablation.

The column layouts below are written from the public dataset documentation
and have NOT been run against the real files in this environment.
"""
import csv
import math
from collections import defaultdict

MISSING = None


def _blank():
    return dict(dns_before=MISSING, dns_entropy=MISSING, dns_len=MISSING, seen_before=MISSING, signed=MISSING)


def load_ctu13_binetflow(path, label_prefix_bad=("From-Botnet",), label_prefix_ok=("From-Normal",)):
    """CTU-13 *.binetflow (CSV). Background traffic is skipped: it is unlabelled.

    Per (SrcAddr, DstAddr) it derives interval regularity and contacts per
    hour; per SrcAddr, distinct destinations (fan-out, over the whole file as
    a rough stand-in for 60 s: GUESS, refine with windows). Failure rate comes
    from the connection State column.
    """
    rows_raw = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            lab = r["Label"].removeprefix("flow=")  # CTU-13 files write "flow=From-Botnet-..."
            if lab.startswith(label_prefix_bad):
                y = 1
            elif lab.startswith(label_prefix_ok):
                y = 0
            else:
                continue
            rows_raw.append((r, y))
    times = defaultdict(list)
    dests = defaultdict(set)
    for r, _ in rows_raw:
        times[(r["SrcAddr"], r["DstAddr"])].append(_ts(r["StartTime"]))
        dests[r["SrcAddr"]].add(r["DstAddr"])
    rows, ys = [], []
    for r, y in rows_raw:
        ts = sorted(times[(r["SrcAddr"], r["DstAddr"])])
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        cv = 0.0
        if len(gaps) >= 3:
            m = sum(gaps) / len(gaps)
            cv = (math.sqrt(sum((g - m) ** 2 for g in gaps) / len(gaps)) / m) if m > 0 else 0.0
        tot, src = float(r["TotBytes"]), float(r["SrcBytes"])
        d = _blank()
        d.update(
            bytes_out=src, bytes_in=max(tot - src, 0.0), duration=float(r["Dur"] or 0), send_events=float(r["TotPkts"]),
            interval_cv=cv, contacts_1h=float(len(ts)), fan_out=float(len(dests[r["SrcAddr"]])),
            fail_rate=1.0 if any(s in r["State"] for s in ("RST", "S_", "_S", "REJ")) else 0.0)
        rows.append(d)
        ys.append(y)
    return rows, ys


def _ts(s):
    # "2011/08/10 09:46:53.047277" -> seconds since an arbitrary epoch; only gaps matter
    from datetime import datetime
    return datetime.strptime(s[:26].strip(), "%Y/%m/%d %H:%M:%S.%f").timestamp()


def load_unsw_nb15(path):
    """UNSW-NB15 training/testing-set CSV (columns dur, spkts, sbytes, dbytes,
    ct_srv_src, state, label ...). Lab attacks; known label noise."""
    rows, ys = [], []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            d = _blank()
            d.update(bytes_out=float(r["sbytes"]), bytes_in=float(r["dbytes"]), duration=float(r["dur"]),
                     send_events=float(r["spkts"]), interval_cv=MISSING, contacts_1h=float(r.get("ct_srv_src", 1)),
                     fan_out=float(r.get("ct_dst_ltm", 1)), fail_rate=1.0 if r.get("state") in ("RST", "REQ", "INT") else 0.0)
            rows.append(d)
            ys.append(int(r["label"]))
    return rows, ys


def load_domain_list(path, label, base=None):
    """One domain per line (DGA list -> label 1; Tranco top sites -> label 0).
    Only the DNS-name features are real; everything else is missing."""
    rows, ys = [], []
    with open(path) as fh:
        for line in fh:
            name = line.strip().split(",")[-1].lower()
            if not name or name.startswith("#"):
                continue
            label_part = name.split(".")[0]
            d = _blank()
            d.update(dns_entropy=_entropy(label_part), dns_len=float(len(name)), dns_before=True)
            for k in ("bytes_out", "bytes_in", "duration", "send_events", "interval_cv", "contacts_1h", "fan_out", "fail_rate"):
                d[k] = MISSING
            rows.append(d)
            ys.append(label)
    return rows, ys


def _entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())
