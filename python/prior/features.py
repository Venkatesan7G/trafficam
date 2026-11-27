"""Head C's 14 transferable features. Must match internal/model/headc.go
PriorFeatures exactly (enforced by the golden test in headc_test.go).

Transferable means the number has the same meaning on any machine or lab:
sizes, timing, fan-out, failure rate, DNS-name shape, newness, signing. No IPs,
domains, ports or program names, which only identify one lab or one PC.
"""
import math

import numpy as np

NAMES = [
    "bytes_out", "bytes_in", "out_in_ratio", "duration", "send_events",
    "interval_cv", "contacts_1h", "fan_out", "fail_rate", "dns_before",
    "dns_entropy", "dns_len", "dest_new", "signed",
]
DIM = len(NAMES)


def _l1p(x):
    return math.log1p(x) if x > 0 else 0.0


def features(f):
    """f: dict with keys bytes_out, bytes_in, duration, send_events,
    interval_cv, contacts_1h, fan_out, fail_rate, dns_before, dns_entropy,
    dns_len, seen_before, signed. Returns a length-14 float list."""
    return [
        _l1p(f["bytes_out"]),
        _l1p(f["bytes_in"]),
        _l1p(f["bytes_out"] / (f["bytes_in"] + 1)),
        _l1p(f["duration"]),
        _l1p(f["send_events"]),
        min(max(f["interval_cv"], 0.0), 10.0),
        _l1p(f["contacts_1h"]),
        _l1p(f["fan_out"]),
        min(max(f["fail_rate"], 0.0), 1.0),
        1.0 if f["dns_before"] else 0.0,
        max(f["dns_entropy"], 0.0),
        max(f["dns_len"], 0.0),
        0.0 if f["seen_before"] else 1.0,
        1.0 if f["signed"] else 0.0,
    ]


def matrix(rows):
    return np.array([features(r) for r in rows], dtype=np.float32)


# Which output columns depend on which input key (for missing-data handling).
_DEPENDS = {
    "bytes_out": (0, 2), "bytes_in": (1, 2), "duration": (3,), "send_events": (4,), "interval_cv": (5,),
    "contacts_1h": (6,), "fan_out": (7,), "fail_rate": (8,), "dns_before": (9,), "dns_entropy": (10,),
    "dns_len": (11,), "seen_before": (12,), "signed": (13,),
}


def features_nan(f):
    """Like features(), but a key that is None (the dataset does not provide
    it) turns its columns into NaN instead of raising. Imputed later."""
    missing = [k for k in _DEPENDS if f.get(k) is None]
    g = dict(f)
    for k in missing:
        g[k] = 0
    out = features(g)
    for k in missing:
        for c in _DEPENDS[k]:
            out[c] = float("nan")
    return out


def matrix_nan(rows):
    return np.array([features_nan(r) for r in rows], dtype=np.float32)
