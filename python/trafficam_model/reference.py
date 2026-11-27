"""PyTorch reference of the trafficam main network (heads A and B).

This is a development-only oracle: the product never imports torch. The Go
implementation in internal/model/net.go is hand-written and is tested against
the forward outputs and gradients this module produces (see golden.py).

Shapes, init and the loss must match net.go exactly.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F

CAT_BUCKETS = (4096, 1024, 512, 256, 16)
CAT_DIMS = (16, 8, 8, 4, 4)
NUM = 20
NUM_CLASSES = 512
EMB_DIM = sum(CAT_DIMS)  # 40
INPUT_DIM = EMB_DIM + 4 + NUM  # 64
LN_EPS = 1e-5

# (name, attribute path) in the same order as the Go mainSpecs / TCW1 file.
TENSOR_ORDER = [
    "emb_dest", "emb_asn", "emb_parent", "emb_country", "emb_port",
    "w1", "b1", "ln1_g", "ln1_b", "w2", "b2", "ln2_g", "ln2_b",
    "wa", "ba", "wb1", "bb1", "wb2", "bb2",
]


class TrafficamNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.embs = nn.ModuleList(
            nn.Embedding(n, d) for n, d in zip(CAT_BUCKETS, CAT_DIMS))
        self.d1 = nn.Linear(INPUT_DIM, 64)
        self.ln1 = nn.LayerNorm(64, eps=LN_EPS)
        self.d2 = nn.Linear(64, 16)
        self.ln2 = nn.LayerNorm(16, eps=LN_EPS)
        self.head_a = nn.Linear(16, NUM_CLASSES)
        self.b1 = nn.Linear(16, 32)
        self.b2 = nn.Linear(32, NUM)

    def forward(self, cat, proto, num_in):
        """cat: (B,5) long; proto: (B,) long in 0..3; num_in: (B,20) float."""
        parts = [e(cat[:, i]) for i, e in enumerate(self.embs)]
        parts.append(F.one_hot(proto, 4).float())
        parts.append(num_in)
        x = torch.cat(parts, dim=1)
        h1 = F.relu(self.ln1(self.d1(x)))
        h2 = F.relu(self.ln2(self.d2(h1)))
        logits = self.head_a(h2)
        recon = self.b2(F.relu(self.b1(h2)))
        return logits, recon

    def tensors(self):
        m = {
            "emb_dest": self.embs[0].weight, "emb_asn": self.embs[1].weight,
            "emb_parent": self.embs[2].weight, "emb_country": self.embs[3].weight,
            "emb_port": self.embs[4].weight,
            "w1": self.d1.weight, "b1": self.d1.bias,
            "ln1_g": self.ln1.weight, "ln1_b": self.ln1.bias,
            "w2": self.d2.weight, "b2": self.d2.bias,
            "ln2_g": self.ln2.weight, "ln2_b": self.ln2.bias,
            "wa": self.head_a.weight, "ba": self.head_a.bias,
            "wb1": self.b1.weight, "bb1": self.b1.bias,
            "wb2": self.b2.weight, "bb2": self.b2.bias,
        }
        return [(k, m[k]) for k in TENSOR_ORDER]


def param_count(model):
    return sum(p.numel() for p in model.parameters())


def weighted_loss(model, cat, proto, num_in, num_target, cls, w):
    """sum(w * (CE + MSE)) / sum(w): the loss Go minimises (net.go LossGrad)."""
    logits, recon = model(cat, proto, num_in)
    ce = F.cross_entropy(logits, cls, reduction="none")
    mse = ((recon - num_target) ** 2).mean(dim=1)
    return (w * (ce + mse)).sum() / w.sum(), ce, mse
