"""Fixture for Go's head C test: a tiny synthetic-trained prior plus the
features and risks PyTorch computes for a few flows.

Usage: python -I python/prior/golden_prior.py internal/model/testdata
"""
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prior import features as F, synth, train_prior as T  # noqa: E402


def main(out):
    rows, y = synth.make(3000, "a", 11)
    x = F.matrix_nan(rows)
    mean, std = T.fit_norm(x)
    net = T.train(x, y, mean, std, epochs=8)
    T.export(net, mean, std, os.path.join(out, "golden_prior.tcw"), "SYNTHETIC test fixture")
    pick = [rows[i] for i in range(24)]
    risk = T.score(net, F.matrix_nan(pick), mean, std)
    cases = []
    for r, k in zip(pick, risk):
        go = {"BytesOut": r["bytes_out"], "BytesIn": r["bytes_in"], "DurationSec": r["duration"],
              "SendEvents": r["send_events"], "IntervalCV": r["interval_cv"], "Contacts1h": r["contacts_1h"],
              "FanOut60s": r["fan_out"], "FailRate5m": r["fail_rate"], "DNSBeforeConnect": bool(r["dns_before"]),
              "DNSEntropy": r["dns_entropy"], "DNSLen": r["dns_len"], "SeenBefore": bool(r["seen_before"]),
              "Signed": bool(r["signed"])}
        cases.append({"flow": go, "features": F.features(r), "risk": float(k)})
    json.dump(cases, open(os.path.join(out, "golden_prior.json"), "w"))
    print("ok")


if __name__ == "__main__":
    main(sys.argv[1])
