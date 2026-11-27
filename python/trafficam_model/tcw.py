"""Reader/writer for the TCW1 weight-file format shared with the Go code.

Layout (little-endian): magic "TCW1", u8 version, u8 kind, u16 reserved,
u32 meta_len, meta JSON, u32 n_tensors, then per tensor: u16 name_len, name,
u8 ndim, ndim x u32 dims, float32 data (row-major); final 32 bytes are the
SHA-256 of everything before. See internal/model/weights.go.
"""
import hashlib
import json
import struct

import numpy as np

KIND_MAIN = 1
KIND_PRIOR = 2


def write(path, kind, tensors, meta=None):
    """tensors: list of (name, ndarray). Order is preserved."""
    meta_b = json.dumps(meta or {}, sort_keys=True, separators=(",", ":")).encode()
    out = bytearray(b"TCW1")
    out += struct.pack("<BBHI", 1, kind, 0, len(meta_b)) + meta_b
    out += struct.pack("<I", len(tensors))
    for name, arr in tensors:
        a = np.ascontiguousarray(arr, dtype="<f4")
        nb = name.encode()
        out += struct.pack("<H", len(nb)) + nb + struct.pack("<B", a.ndim)
        out += b"".join(struct.pack("<I", d) for d in a.shape)
        out += a.tobytes()
    out += hashlib.sha256(bytes(out)).digest()
    with open(path, "wb") as f:
        f.write(out)


def read(path):
    data = open(path, "rb").read()
    body, digest = data[:-32], data[-32:]
    if hashlib.sha256(body).digest() != digest:
        raise ValueError("checksum mismatch")
    if body[:4] != b"TCW1":
        raise ValueError("bad magic")
    ver, kind, _, meta_len = struct.unpack_from("<BBHI", body, 4)
    if ver != 1:
        raise ValueError("unsupported version")
    p = 12
    meta = json.loads(body[p:p + meta_len])
    p += meta_len
    (n,) = struct.unpack_from("<I", body, p)
    p += 4
    tensors = []
    for _ in range(n):
        (nl,) = struct.unpack_from("<H", body, p)
        p += 2
        name = body[p:p + nl].decode()
        p += nl
        (nd,) = struct.unpack_from("<B", body, p)
        p += 1
        shape = struct.unpack_from("<" + "I" * nd, body, p)
        p += 4 * nd
        cnt = int(np.prod(shape)) if nd else 1
        arr = np.frombuffer(body, dtype="<f4", count=cnt, offset=p).reshape(shape).copy()
        p += 4 * cnt
        tensors.append((name, arr))
    if p != len(body):
        raise ValueError("trailing bytes")
    return kind, meta, tensors
