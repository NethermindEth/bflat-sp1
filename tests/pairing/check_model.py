#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Checks tests/pairing/model.py against py_ecc: the final-exponentiation identities, the twisted
Frobenius, the projective formulas against affine arithmetic, and pairing checks (bilinearity,
non-degeneracy) on both curves. Needs py_ecc."""

import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "pairing"))
from model import BLS12_381, BN254  # noqa: E402
from py_ecc import optimized_bls12_381 as bls  # noqa: E402
from py_ecc import optimized_bn128 as bn  # noqa: E402

rng = random.Random(7)


def affine_g2(lib, q):
    q = lib.normalize(q)
    return (tuple(int(c) for c in q[0].coeffs), tuple(int(c) for c in q[1].coeffs))


def affine_g1(lib, p_):
    p_ = lib.normalize(p_)
    return (int(p_[0]), int(p_[1]))


def to_affine(c, t):
    zi = c.f2inv(t[2])
    return (c.f2mul(t[0], zi), c.f2mul(t[1], zi))


def twist_add(c, a, b):
    if a == b:
        lam = c.f2mul(c.f2scale(c.f2mul(a[0], a[0]), 3), c.f2inv(c.f2scale(a[1], 2)))
    else:
        lam = c.f2mul(c.f2sub(b[1], a[1]), c.f2inv(c.f2sub(b[0], a[0])))
    x = c.f2sub(c.f2sub(c.f2mul(lam, lam), a[0]), b[0])
    return (x, c.f2sub(c.f2mul(lam, c.f2sub(a[0], x)), a[1]))


def twist_mul(c, k, q):
    r = None
    for bit in bin(k)[2:]:
        if r is not None:
            r = twist_add(c, r, r)
        if bit == "1":
            r = q if r is None else twist_add(c, r, q)
    return r


def identities():
    for c in (BN254, BLS12_381):
        d = (c.p ** 4 - c.p ** 2 + 1) // c.r
        assert (c.p ** 4 - c.p ** 2 + 1) % c.r == 0
        x, p = c.x, c.p
        if c.name == "bn254":
            l = [-36 * x ** 3 - 30 * x ** 2 - 18 * x - 2, -36 * x ** 3 - 18 * x ** 2 - 12 * x + 1, 6 * x ** 2 + 1, 1]
            assert sum(li * p ** i for i, li in enumerate(l)) == d, "bn254 hard-part decomposition"
            m = 2 * x * (6 * x * x + 3 * x + 1)
            l = [12 * x ** 3 + 12 * x ** 2 + 6 * x + 1, 12 * x ** 3 + 6 * x ** 2 + 4 * x, 12 * x ** 3 + 6 * x ** 2 + 6 * x,
                 12 * x ** 3 + 6 * x ** 2 + 4 * x - 1]
            assert sum(li * p ** i for i, li in enumerate(l)) == m * d, "bn254 hard part as a multiple"
            assert math.gcd(m, c.r) == 1, "bn254 hard-part multiple coprime to r"
            assert (p - 6 * x * x) % c.r == 0, "p = 6x^2 mod r"
        else:
            assert (x - 1) ** 2 * (x + p) * (x * x + p * p - 1) + 3 == 3 * d, "bls hard part"
        print(c.name, "identities OK")


def formulas(c, lib):
    q = affine_g2(lib, lib.multiply(lib.G2, rng.randrange(1, c.r)))
    assert c.on_twist(q)
    # pi(Q) = [p]Q on G2.
    assert c.pi(q) == twist_mul(c, c.p % c.r, q), "twisted Frobenius"
    t = (q[0], q[1], (1, 0))
    for _ in range(5):
        t2, _ = c.dbl(t, 1, 1)
        assert to_affine(c, t2) == twist_add(c, to_affine(c, t), to_affine(c, t)), "doubling"
        t3, _ = c.add(t2, q, 1, 1)
        assert to_affine(c, t3) == twist_add(c, to_affine(c, t2), q), "addition"
        t = t3
    print(c.name, "formulas OK")


def pairings(c, lib, rounds):
    g1, g2 = lib.G1, lib.G2
    for _ in range(rounds):
        a, b = rng.randrange(1, c.r), rng.randrange(1, c.r)
        P, Q = lib.multiply(g1, a), lib.multiply(g2, b)
        P2 = lib.multiply(g1, a * b % c.r)
        ok = [(affine_g1(lib, P), affine_g2(lib, Q)), (affine_g1(lib, lib.neg(P2)), affine_g2(lib, g2))]
        assert c.pairing_check(ok), "e(aG1, bG2) e(-abG1, G2) = 1"
        bad = [(affine_g1(lib, P), affine_g2(lib, Q)), (affine_g1(lib, lib.neg(lib.add(P2, g1))), affine_g2(lib, g2))]
        assert not c.pairing_check(bad), "non-degenerate"
        assert not c.pairing_check([(affine_g1(lib, P), affine_g2(lib, Q))])
    print(c.name, f"pairing checks OK ({rounds} rounds)")


def random_twist_point(c):
    while True:
        x = (rng.randrange(c.p), rng.randrange(c.p))
        y = c.f2sqrt(c.f2add(c.f2mul(c.f2mul(x, x), x), c.b2))
        if y is not None and c.f2mul(y, y) == c.f2add(c.f2mul(c.f2mul(x, x), x), c.b2):
            return (x, y)


def random_g1_point(c):
    while True:
        x = rng.randrange(c.p)
        a = (x ** 3 + c.b) % c.p
        y = pow(a, (c.p + 1) // 4, c.p)
        if y * y % c.p == a:
            return (x, y)


def subgroups():
    for _ in range(3):
        q = affine_g2(bn, bn.multiply(bn.G2, rng.randrange(1, BN254.r)))
        assert BN254.in_g2(q)
        z = random_twist_point(BN254)
        assert BN254.twist_mul(BN254.r, z) is not None, "random twist point outside G2"
        assert not BN254.in_g2(z)
    print("bn254 G2 subgroup check OK")
    c = BLS12_381
    for _ in range(3):
        assert c.in_g1(c.g1_mul(rng.randrange(1, c.r), c.G1))
        z = random_g1_point(c)
        assert c.g1_mul(c.r, z) is not None, "random point outside G1"
        assert not c.in_g1(z)
    print("bls12_381 G1 subgroup check OK, beta =", hex(c.beta))


identities()
subgroups()
formulas(BN254, bn)
formulas(BLS12_381, bls)
pairings(BN254, bn, 3)
pairings(BLS12_381, bls, 2)
