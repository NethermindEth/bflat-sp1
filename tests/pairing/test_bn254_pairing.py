#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Differential test of src/pairing/bn254_pairing.c (EIP-197) on emulated SP1 field precompiles.

Expected results come from the algebra, not from another pairing: prod e(a_i G1, b_i G2) is 1
exactly when sum a_i b_i = 0 (mod r). Covers go-ethereum's bn256Pairing vectors, products that do
and do not hold over 1..10 pairs (more than one Miller batch), infinity in either slot, and inputs
EIP-197 rejects: coordinates at or above p, points off their curves, and twist points outside G2.
Needs py_ecc.

    test_bn254_pairing.py [--seed N]
    test_bn254_pairing.py --sp1-vectors FILE   write tests/accelerators/guest.cs vectors (kind 2) to FILE
                                               and print the output the guest must commit
"""

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "common"))
sys.path.insert(0, str(HERE.parents[1] / "src" / "pairing"))
from keccak import keccak256  # noqa: E402
from model import BN254 as C  # noqa: E402
from py_ecc import optimized_bn128 as bn  # noqa: E402

GETH = HERE.parent / "data" / "geth" / "bn256Pairing.json"


def b32(v):
    return v.to_bytes(32, "big")


def g1_bytes(p_):
    if p_ is None:
        return bytes(64)
    p_ = bn.normalize(p_)
    return b32(int(p_[0])) + b32(int(p_[1]))


def g2_raw(x, y):
    return b32(x[1]) + b32(x[0]) + b32(y[1]) + b32(y[0])


def g2_bytes(q):
    if q is None:
        return bytes(128)
    q = bn.normalize(q)
    x, y = [int(c) for c in q[0].coeffs], [int(c) for c in q[1].coeffs]
    return g2_raw(x, y)


def product(rng, terms, holds):
    """terms pairs (a_i G1, b_i G2) whose sum a_i b_i is 0 when holds, random otherwise."""
    a = [rng.randrange(1, C.r) for _ in range(terms)]
    b = [rng.randrange(1, C.r) for _ in range(terms)]
    if holds:
        s = sum(x * y for x, y in zip(a[:-1], b[:-1])) % C.r
        a[-1] = (-s * pow(b[-1], -1, C.r)) % C.r
    data = b"".join(g1_bytes(bn.multiply(bn.G1, x)) + g2_bytes(bn.multiply(bn.G2, y)) for x, y in zip(a, b))
    want = sum(x * y for x, y in zip(a, b)) % C.r == 0
    return data, ("ok", 1 if want else 0)


def twist_point_outside_g2(rng):
    while True:
        x = (rng.randrange(C.p), rng.randrange(C.p))
        rhs = C.f2add(C.f2mul(C.f2mul(x, x), x), C.b2)
        y = C.f2sqrt(rhs)
        if y is not None and C.f2mul(y, y) == rhs and not C.in_g2((x, y)):
            return x, y


def cases(rng):
    out = []
    for v in json.load(open(GETH)):
        out.append((bytes.fromhex(v["Input"]), ("ok", int(v["Expected"], 16))))
    out.append((b"", ("ok", 1)))
    for terms in (1, 2, 3, 4, 8, 9, 10):
        out.append(product(rng, terms, True))
        out.append(product(rng, terms, False))
    g1, g2 = g1_bytes(bn.G1), g2_bytes(bn.G2)
    inf1, inf2 = bytes(64), bytes(128)
    out.append((inf1 + inf2, ("ok", 1)))
    out.append((inf1 + g2, ("ok", 1)))
    out.append((g1 + inf2, ("ok", 1)))
    out.append((g1 + g2 + inf1 + g2, ("ok", 0)))
    holds, _ = product(rng, 2, True)
    out.append((inf1 + g2 + holds + g1 + inf2, ("ok", 1)))
    # Rejected inputs, alone and behind a valid pair.
    x, y = twist_point_outside_g2(rng)
    bad = [
        g1 + g2_raw(x, y),
        g1 + g2_raw((x[0], x[1]), (y[0], (C.p - y[1]) % C.p)),
        g1 + g2_raw((1, 0), (1, 0)),
        b32(1) + b32(3) + g2,
        b32(C.p) + b32(2) + g2,
        b32(1) + b32(C.p + 2) + g2,
        g1 + b32(C.p) + g2[32:],
        g1 + g2[:96] + b32(C.p),
        b32(0) + b32(1) + g2,
    ]
    for b in bad:
        out.append((b, ("fail",)))
        out.append((g1 + g2 + b, ("fail",)))
    return out


def build(workdir):
    cc = os.environ.get("CC", "cc")
    exe = Path(workdir) / "harness"
    subprocess.run([cc, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(exe),
                    str(HERE / "bn254_harness.c")], check=True)
    return exe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--sp1-vectors", type=Path)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    vectors = cases(rng)
    if args.sp1_vectors:
        data, results = bytearray(b"\x02"), bytearray()
        for b, want in vectors:
            data += len(b).to_bytes(4, "little") + b
            results += b"\x00\x00" if want[0] == "fail" else bytes([1, want[1]])
        args.sp1_vectors.write_bytes(bytes(data))
        print(keccak256(bytes(results)).hex())
        return
    with tempfile.TemporaryDirectory() as workdir:
        exe = build(workdir)
        commands = "".join(f"pair {b.hex() if b else '-'}\n" for b, _ in vectors)
        result = subprocess.run([str(exe)], input=commands, capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f"harness failed ({result.returncode}): {result.stderr.strip()}")
        failures, calls = 0, {}
        for (b, want), line in zip(vectors, result.stdout.splitlines()):
            f = line.split()
            got = ("fail",) if f[0] == "fail" else ("ok", int(f[1]))
            if got != want:
                failures += 1
                print(f"MISMATCH {len(b) // 192} pairs: got {got} want {want}")
            if got[0] == "ok":
                calls.setdefault(len(b) // 192, int(f[-1]))
        print("syscalls by pair count:", dict(sorted(calls.items())))
        print(f"{len(vectors)} vectors: {'FAILED' if failures else 'OK'} ({failures} failures)")
        sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
