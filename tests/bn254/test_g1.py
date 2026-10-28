#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Differential test of src/bn254/g1.c against plain Python BN254 G1 arithmetic (EIP-196).

Builds tests/bn254/harness.c for the host (CC, default cc) on emulated SP1 precompiles that fail
on any use the real ones reject (equal x on BN254_ADD, a point off the curve, infinity), and checks
that 0x06 and 0x07 agree with the reference on:
  - random points and scalars, the point at infinity, P + P and P + (-P);
  - coordinates at or above p and points off the curve, which must fail;
  - scalars of r and above (taken mod r), and scalars built from the GLV lambda that walk the
    accumulator into the table points, their negations and infinity.
It also checks the GLV split on its own: k = k1 + k2*lambda (mod r), |k1|, |k2| < 2^127.

    test_g1.py [--seed N] [--random N]
    test_g1.py --sp1-vectors FILE    write the vectors for tests/accelerators/guest.cs to FILE and
                                     print the output the guest must commit, then exit
"""

import argparse
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "common"))
from keccak import keccak256  # noqa: E402

P = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47
R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
G = (1, 2)
LAMBDA = 0xB3C4D79D41A917585BFC41088D8DAAA78B17EA66B99C90DD
ADD, MUL = 0, 1


def on_curve(pt):
    return pt is None or (pt[1] * pt[1] - pt[0] ** 3 - 3) % P == 0


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, P)
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, P)
    x = (m * m - a[0] - b[0]) % P
    return x, (m * (a[0] - x) - a[1]) % P


def point_mul(k, a):
    result = None
    for bit in bin(k % R)[2:]:
        result = point_add(result, result)
        if bit == "1":
            result = point_add(result, a)
    return result


def neg(pt):
    return None if pt is None else (pt[0], (P - pt[1]) % P)


def decode(b):
    """The point, None for infinity, or False when 0x06/0x07 must fail."""
    x, y = int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big")
    if x >= P or y >= P:
        return False
    if x == 0 and y == 0:
        return None
    return (x, y) if on_curve((x, y)) else False


def encode(pt):
    return bytes(64) if pt is None else pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def reference(op, a, b):
    """The 64-byte output, or None where the precompile must fail."""
    p = decode(a)
    if p is False:
        return None
    if op == ADD:
        q = decode(b)
        return None if q is False else encode(point_add(p, q))
    return encode(point_mul(int.from_bytes(b[:32], "big"), p))


def b32(v):
    return v.to_bytes(32, "big")


def raw(x, y):
    return b32(x) + b32(y)


def vectors(rng, count):
    inf = bytes(64)
    g = encode(G)
    points = [G, neg(G), point_mul(2, G), point_mul(LAMBDA, G)] + [point_mul(rng.randrange(1, R), G) for _ in range(6)]
    bad = [raw(P, 2), raw(1, P), raw(P + 1, 2), raw(1, 3), raw(0, 1), raw(5, 0), raw(2**256 - 1, 2**256 - 1)]
    for p in points:
        e = encode(p)
        yield ADD, e, e
        yield ADD, e, encode(neg(p))
        yield ADD, e, inf
        yield ADD, inf, e
        for q in points:
            yield ADD, e, encode(q)
    yield ADD, inf, inf
    for x in bad:
        yield ADD, x, g
        yield ADD, g, x
        yield MUL, x, b32(1)
        yield MUL, x, b32(0)

    small = list(range(0, 18)) + [127, 128, 255, 256]
    scalars = small + [R - v for v in small if v] + [R + v for v in small] + [
        2**256 - 1, 2**256 - R, LAMBDA, R - LAMBDA, LAMBDA * LAMBDA % R, LAMBDA + 1, LAMBDA - 1, R // 2,
        R // 2 + 1, 2**126, 2**127 - 1, 2**127, 2**127 + 1, 2**253]
    # k = i + j*lambda with small i, j: both halves tiny, so the accumulator meets table entries.
    for i in range(-17, 18, 4):
        for j in range(-17, 18, 4):
            scalars.append((i + j * LAMBDA) % R)
    for k in scalars:
        for p in points[:4] + [None]:
            yield MUL, encode(p), b32(k % 2**256)
    for _ in range(count):
        p = point_mul(rng.randrange(1, R), G)
        yield MUL, encode(p), b32(rng.randrange(2**256))
        yield ADD, encode(p), encode(point_mul(rng.randrange(1, R), G))


def build(workdir):
    cc = os.environ.get("CC", "cc")
    exe = Path(workdir) / "harness"
    subprocess.run([cc, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(exe), str(HERE / "harness.c")],
                   check=True)
    return exe


def run(exe, commands):
    result = subprocess.run([str(exe)], input="".join(commands), capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"harness failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.splitlines()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--random", type=int, default=300)
    parser.add_argument("--sp1-vectors", type=Path)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    cases = list(vectors(rng, args.random))
    if args.sp1_vectors:
        write_sp1_vectors(cases, args.sp1_vectors)
        return

    with tempfile.TemporaryDirectory() as workdir:
        exe = build(workdir)
        commands = [f"{'add' if op == ADD else 'mul'} {a.hex()} {(b if op == ADD else b[:32]).hex()}\n"
                    for op, a, b in cases]
        failures, mul_ops = 0, []
        first_random = len(cases) - 2 * args.random
        for index, ((op, a, b), line) in enumerate(zip(cases, run(exe, commands))):
            fields = line.split()
            got = None if fields[0] == "fail" else bytes.fromhex(fields[1])
            want = reference(op, a, b)
            if got != want:
                failures += 1
                print(f"MISMATCH {'add' if op == ADD else 'mul'} a={a.hex()} b={b.hex()}\n"
                      f"  got  {got.hex() if got else None}\n  want {want.hex() if want else None}")
            if op == MUL and index >= first_random:
                mul_ops.append((int(fields[-2]), int(fields[-1])))

        k_values = [rng.randrange(R) for _ in range(5000)] + [0, 1, R - 1, LAMBDA, R - LAMBDA, R // 2, R // 2 + 1]
        for k, line in zip(k_values, run(exe, [f"split {b32(k).hex()}\n" for k in k_values])):
            k1, neg1, k2, neg2 = line.split()
            k1 = -int(k1, 16) if neg1 == "1" else int(k1, 16)
            k2 = -int(k2, 16) if neg2 == "1" else int(k2, 16)
            if (k1 + k2 * LAMBDA - k) % R or abs(k1) >= 2**127 or abs(k2) >= 2**127:
                failures += 1
                print(f"SPLIT k={k:x}: k1={k1:x} k2={k2:x}")

        if mul_ops:
            print(f"{len(mul_ops)} random multiplications: mean {sum(d for d, _ in mul_ops) / len(mul_ops):.1f} "
                  f"doubles, {sum(a for _, a in mul_ops) / len(mul_ops):.1f} adds")
        print(f"{len(cases)} vectors, {len(k_values)} splits: {'FAILED' if failures else 'OK'} ({failures} failures)")
        sys.exit(1 if failures else 0)


def write_sp1_vectors(cases, path):
    """Records (op | a | b) of 129 bytes for the guest, a mul's scalar in the first 32 bytes of b. The
    guest commits keccak256 over (ok | output, or 64 zero bytes) per record."""
    data, results = bytearray(), bytearray()
    for op, a, b in cases:
        data += bytes([op]) + a + (b if op == ADD else b[:32] + bytes(32))
        want = reference(op, a, b)
        results += bytes(65) if want is None else b"\x01" + want
    path.write_bytes(b"\x01" + bytes(data))
    print(keccak256(bytes(results)).hex())


if __name__ == "__main__":
    main()
