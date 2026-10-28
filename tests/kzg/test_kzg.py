#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Differential test of src/pairing/bls12_381_kzg.c (EIP-4844 verify_kzg_proof) on emulated SP1
BLS12-381 precompiles.

Covers the official verify_kzg_proof suite (tests/data/kzg; an error there is a false verification
here, as in kzg-rs), go-ethereum's pointEvaluation vector, and generated cases: valid openings of
f(X) = a + bX (C = aG1 + b[s]G1, proof = bG1, y = a + bz), the same with y, z or the proof wrong,
the point at infinity in either slot, and encodings that must be rejected: missing compression
flag, non-canonical infinity, x at or above p, x off the curve, curve points outside G1, z or y at
or above r. Needs py_ecc.

    test_kzg.py [--seed N] [--random N]
    test_kzg.py --sp1-vectors FILE   write tests/accelerators/guest.cs vectors (kind 3) to FILE and
                                     print the output the guest must commit
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
from model import BLS12_381 as C  # noqa: E402
from py_ecc import optimized_bls12_381 as bls  # noqa: E402

DATA = HERE.parent / "data"
# [s]G1 = g1_monomial[1] of the trusted setup (compressed ad3eb501...5a04c81).
S_G1 = (0x0D3EB50121139AA34DB1D545093AC9374AB7BCA2C0F3BF28E27C8DCD8FC7CB42D25926FC0C97B336E9F0FB35E5A04C81,
        0x17DE623F59A3043952D2F637A935FAE14B6DEE8B255E526304963D58AB6F1A827C7DE623D34D394F8A3D0F57D6E972B9)


def compress(pt):
    """ZCash compressed G1 encoding of an affine point (None = infinity)."""
    if pt is None:
        return bytes([0xC0]) + bytes(47)
    x, y = pt
    b = bytearray(x.to_bytes(48, "big"))
    b[0] |= 0x80 | (0x20 if y > (C.p - 1) // 2 else 0)
    return bytes(b)


def affine(p_):
    if bls.is_inf(p_):
        return None
    p_ = bls.normalize(p_)
    return (int(p_[0]), int(p_[1]))


def jac(pt):
    return (bls.FQ(pt[0]), bls.FQ(pt[1]), bls.FQ(1))


def b32(v):
    return v.to_bytes(32, "big")


def opening(rng, a=None, b=None, z=None):
    a = rng.randrange(C.r) if a is None else a
    b = rng.randrange(C.r) if b is None else b
    z = rng.randrange(C.r) if z is None else z
    commitment = affine(bls.add(bls.multiply(bls.G1, a), bls.multiply(jac(S_G1), b)))
    proof = affine(bls.multiply(bls.G1, b))
    return compress(commitment), b32(z), b32((a + b * z) % C.r), compress(proof)


def point_outside_g1(rng):
    while True:
        x = rng.randrange(C.p)
        rhs = (x ** 3 + 4) % C.p
        y = pow(rhs, (C.p + 1) // 4, C.p)
        if y * y % C.p == rhs and not C.in_g1((x, y)):
            return x, y


def x_off_curve(rng):
    while True:
        x = rng.randrange(C.p)
        rhs = (x ** 3 + 4) % C.p
        if pow(rhs, (C.p - 1) // 2, C.p) == C.p - 1:
            return x


def cases(rng, count):
    out = []
    suite = json.load(open(DATA / "kzg" / "verify_kzg_proof.json"))["cases"]
    for c in suite:
        h = lambda s: bytes.fromhex(s[2:])
        fields = (h(c["commitment"]), h(c["z"]), h(c["y"]), h(c["proof"]))
        # Wrong-length encodings never reach the accelerator: its operands are fixed-size and the
        # 0x0a precompile rejects any input that is not 192 bytes first.
        if tuple(map(len, fields)) != (48, 32, 32, 48):
            continue
        out.append((fields, 1 if c["output"] else 0))
    k = bytes.fromhex(json.load(open(DATA / "geth" / "pointEvaluation.json"))[0]["Input"])
    out.append(((k[96:144], k[32:64], k[64:96], k[144:192]), 1))
    for _ in range(count):
        c, z, y, p = opening(rng)
        out.append(((c, z, y, p), 1))
        out.append(((c, z, b32((int.from_bytes(y, "big") + 1) % C.r), p), 0))
        out.append(((c, b32((int.from_bytes(z, "big") + 1) % C.r), y, p), 0))
        out.append(((p, z, y, c), 0))
    # Openings with the point at infinity: b = 0 gives proof = infinity; a = b = 0 both.
    out.append((opening(rng, b=0), 1))
    out.append((opening(rng, a=0, b=0), 1))
    out.append((opening(rng, a=0, b=0, z=0), 1))
    # Rejected encodings and scalars.
    c, z, y, p = opening(rng)
    outside = compress(point_outside_g1(rng))
    xbad = bytearray(compress((x_off_curve(rng), 1)))
    big_x = bytearray((C.p).to_bytes(48, "big"))
    big_x[0] |= 0x80
    bad_points = [bytes([c[0] & 0x7F]) + c[1:], bytes([0xC0]) + bytes(46) + b"\x01", bytes([0xE0]) + bytes(47),
                  bytes([0x40]) + bytes(47), outside, bytes(xbad), bytes(big_x), bytes(48)]
    for bp in bad_points:
        out.append(((bp, z, y, p), 0))
        out.append(((c, z, y, bp), 0))
    out.append(((c, b32(C.r), y, p), 0))
    out.append(((c, z, b32(C.r), p), 0))
    out.append(((c, b32(2**256 - 1), y, p), 0))
    # z >= r must fail even when z - r would verify.
    a, b, zz = rng.randrange(C.r), rng.randrange(C.r), rng.randrange(2**256 - C.r)
    c2, _, y2, p2 = opening(rng, a, b, zz)
    out.append(((c2, b32(zz + C.r), y2, p2), 0))
    out.append(((c2, b32(zz), y2, p2), 1))
    return out


def build(workdir):
    cc = os.environ.get("CC", "cc")
    exe = Path(workdir) / "harness"
    subprocess.run([cc, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(exe), str(HERE / "harness.c")],
                   check=True)
    return exe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--random", type=int, default=8)
    parser.add_argument("--sp1-vectors", type=Path)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    vectors = cases(rng, args.random)
    if args.sp1_vectors:
        data, results = bytearray(b"\x03"), bytearray()
        for (c, z, y, p), want in vectors:
            data += c + z + y + p
            results += bytes([1, want])
        args.sp1_vectors.write_bytes(bytes(data))
        print(keccak256(bytes(results)).hex())
        return
    with tempfile.TemporaryDirectory() as workdir:
        exe = build(workdir)
        commands = "".join(f"kzg {c.hex()} {z.hex()} {y.hex()} {p.hex()}\n" for (c, z, y, p), _ in vectors)
        result = subprocess.run([str(exe)], input=commands, capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f"harness failed ({result.returncode}): {result.stderr.strip()}")
        failures, calls = 0, []
        for ((c, z, y, p), want), line in zip(vectors, result.stdout.splitlines()):
            f = line.split()
            got = int(f[1]) if f[0] == "ok" else None
            if got != want:
                failures += 1
                print(f"MISMATCH c={c.hex()} z={z.hex()} y={y.hex()} proof={p.hex()}: got {got} want {want}")
            if got == 1:
                calls.append(int(f[2]))
        if calls:
            print(f"verified openings: max {max(calls)} syscalls")
        print(f"{len(vectors)} vectors: {'FAILED' if failures else 'OK'} ({failures} failures)")
        sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
