"""Generate the golden fixtures that Go's gradient test checks against.

Usage: python -I python/trafficam_model/golden.py internal/model/testdata
Writes golden_main.tcw (random weights), golden_main_grads.tcw (PyTorch
gradients of the weighted loss), golden_io.json (inputs, masks, losses).
"""
import json
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from trafficam_model import reference as R  # noqa: E402
from trafficam_model import tcw  # noqa: E402


def main(out_dir):
    torch.manual_seed(1234)
    rng = np.random.default_rng(99)
    m = R.TrafficamNet()
    with torch.no_grad():  # make LN affine params non-trivial
        for p in (m.ln1.weight, m.ln2.weight):
            p.add_(torch.randn_like(p) * 0.2)
        for p in (m.ln1.bias, m.ln2.bias):
            p.add_(torch.randn_like(p) * 0.2)
        for e in m.embs:
            e.weight.mul_(0.5)
    assert R.param_count(m) == 94180, R.param_count(m)

    B = 12
    cat = np.stack([rng.integers(0, n, B) for n in R.CAT_BUCKETS], 1)
    proto = rng.integers(0, 4, B)
    num = np.clip(rng.normal(size=(B, R.NUM)), -5, 5).astype("f4")
    mask = rng.random((B, R.NUM)) < 0.1
    mask[0] = False
    cls = rng.integers(0, R.NUM_CLASSES, B)
    w = rng.uniform(0.5, 3.0, B).astype("f4")

    num_in = np.where(mask, 0.0, num).astype("f4")
    t = lambda a, d=None: torch.tensor(a, dtype=d)
    loss, ce, mse = R.weighted_loss(
        m, t(cat, torch.long), t(proto, torch.long), t(num_in),
        t(num), t(cls, torch.long), t(w))
    loss.backward()
    with torch.no_grad():
        logits, recon = m(t(cat, torch.long), t(proto, torch.long), t(num_in))
        probs = torch.softmax(logits, 1)

    os.makedirs(out_dir, exist_ok=True)
    tcw.write(os.path.join(out_dir, "golden_main.tcw"), tcw.KIND_MAIN,
              [(k, v.detach().numpy()) for k, v in m.tensors()], {"note": "golden"})
    tcw.write(os.path.join(out_dir, "golden_main_grads.tcw"), tcw.KIND_MAIN,
              [(k, v.grad.numpy()) for k, v in m.tensors()], {"note": "grads"})
    io = {
        "cat": cat.tolist(), "proto": proto.tolist(), "num": num.tolist(),
        "mask": mask.tolist(), "cls": cls.tolist(), "w": w.tolist(),
        "loss": loss.item(), "ce": ce.tolist(), "mse": mse.tolist(),
        "recon": recon.tolist(), "p_true": [float(probs[i, cls[i]]) for i in range(B)],
    }
    json.dump(io, open(os.path.join(out_dir, "golden_io.json"), "w"))
    print("ok: loss", loss.item(), "params", R.param_count(m))


if __name__ == "__main__":
    main(sys.argv[1])
