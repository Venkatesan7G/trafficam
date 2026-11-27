"""Synthetic labelled flows for tests and for exercising the pipeline.

NOT real data and NOT used for shipped weights. Two "labs" with different
distributions let the cross-dataset gate be tested without downloading
anything.
"""
import numpy as np


def make(n, lab, seed):
    """lab in {"a", "b"}: same attack shapes, different benign habits and
    noise, like two real datasets. Returns (list of feature dicts, labels)."""
    r = np.random.default_rng(seed)
    shift = {"a": 0.0, "b": 0.7}[lab]
    rows, y = [], []
    for _ in range(n):
        attack = r.random() < 0.3
        kind = r.integers(0, 4) if attack else -1
        f = dict(
            bytes_out=float(np.exp(r.normal(7 + shift, 1.2))), bytes_in=float(np.exp(r.normal(9 + shift, 1.5))),
            duration=float(np.exp(r.normal(1.5, 0.8))), send_events=float(r.integers(1, 12)),
            interval_cv=float(r.uniform(0.5, 1.5)), contacts_1h=float(r.integers(1, 8)),
            fan_out=float(r.integers(1, 4)), fail_rate=float(r.uniform(0, 0.05)),
            dns_before=True, dns_entropy=float(r.normal(2.9, 0.3)), dns_len=float(r.integers(8, 24)),
            seen_before=bool(r.random() < 0.9), signed=bool(r.random() < 0.9))
        if kind == 0:   # beacon
            f.update(bytes_out=float(r.uniform(100, 600)), bytes_in=float(r.uniform(100, 600)), interval_cv=float(r.uniform(0, 0.1)),
                     contacts_1h=float(r.integers(10, 60)), seen_before=False)
        elif kind == 1:  # exfiltration
            f.update(bytes_out=float(np.exp(r.normal(17, 1))), bytes_in=float(r.uniform(100, 5000)), duration=float(r.uniform(60, 600)),
                     send_events=float(r.integers(500, 5000)), seen_before=False)
        elif kind == 2:  # generated domains
            f.update(dns_entropy=float(r.normal(4.3, 0.3)), dns_len=float(r.integers(20, 40)), fail_rate=float(r.uniform(0.4, 1)),
                     fan_out=float(r.integers(10, 60)), seen_before=False)
        elif kind == 3:  # scan
            f.update(fan_out=float(r.integers(100, 800)), fail_rate=float(r.uniform(0.8, 1)), bytes_out=float(r.uniform(40, 120)),
                     bytes_in=0.0, seen_before=False, signed=False)
        rows.append(f)
        y.append(1 if attack else 0)
    return rows, np.array(y, dtype=np.float32)
