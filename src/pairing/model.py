# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Plain-integer model of the pairing code in this directory: the same towers, Miller loop, final exponentiation and
subgroup checks, written for clarity rather than speed. gen_constants.py derives the C constants from it,
and tests/pairing compares it against py_ecc and against the C code.

Fp2 = Fp[u]/(u^2 + 1); Fp12 elements are six Fp2 coefficients of w, w^6 = xi, so the C layout
(c0 = (g0, g2, g4), c1 = (g1, g3, g5)) is the same element."""


class Curve:
    def __init__(self, name, p, r, x, b, xi, twist):
        self.name, self.p, self.r, self.x, self.b, self.xi, self.twist = name, p, r, x, b, xi, twist
        # Twist coefficient b' of E': D-type b/xi, M-type b*xi.
        self.b2 = self.f2mul((b, 0), self.f2inv(xi)) if twist == "D" else self.f2mul((b, 0), xi)
        self.gamma = [[self.f2pow(xi, k * (p ** n - 1) // 6) for k in range(6)] for n in range(4)]
        # Twisted Frobenius pi(x', y') = (conj(x') * cx, conj(y') * cy) on E'.
        if twist == "D":
            self.pi_x, self.pi_y = self.f2pow(xi, (p - 1) // 3), self.f2pow(xi, (p - 1) // 2)
        else:
            self.pi_x = self.f2inv(self.f2pow(xi, (p - 1) // 3))
            self.pi_y = self.f2inv(self.f2pow(xi, (p - 1) // 2))

    # ---- Fp2 ----
    def f2add(self, a, b):
        p = self.p
        return ((a[0] + b[0]) % p, (a[1] + b[1]) % p)

    def f2sub(self, a, b):
        p = self.p
        return ((a[0] - b[0]) % p, (a[1] - b[1]) % p)

    def f2mul(self, a, b):
        p = self.p
        return ((a[0] * b[0] - a[1] * b[1]) % p, (a[0] * b[1] + a[1] * b[0]) % p)

    def f2neg(self, a):
        return ((-a[0]) % self.p, (-a[1]) % self.p)

    def f2conj(self, a):
        return (a[0], (-a[1]) % self.p)

    def f2inv(self, a):
        p = self.p
        n = pow((a[0] * a[0] + a[1] * a[1]) % p, p - 2, p)
        return (a[0] * n % p, (-a[1]) * n % p)

    def f2pow(self, a, e):
        r = (1, 0)
        while e:
            if e & 1:
                r = self.f2mul(r, a)
            a = self.f2mul(a, a)
            e >>= 1
        return r

    def f2sqrt(self, a):
        """A square root in Fp2 for p = 3 mod 4 (Adj and Rodriguez-Henriquez, algorithm 9), or None."""
        p = self.p
        a1 = self.f2pow(a, (p - 3) // 4)
        alpha = self.f2mul(a1, self.f2mul(a1, a))
        if self.f2mul(self.f2conj(alpha), alpha) == (p - 1, 0):
            return None
        x0 = self.f2mul(a1, a)
        if alpha == (p - 1, 0):
            return self.f2mul((0, 1), x0)
        return self.f2mul(self.f2pow(self.f2add((1, 0), alpha), (p - 1) // 2), x0)

    def f2scale(self, a, s):
        return (a[0] * s % self.p, a[1] * s % self.p)

    # ---- Fp12 as [g0..g5] ----
    def one(self):
        return [(1, 0)] + [(0, 0)] * 5

    def mul12(self, a, b):
        c = [(0, 0)] * 11
        for i in range(6):
            for j in range(6):
                c[i + j] = self.f2add(c[i + j], self.f2mul(a[i], b[j]))
        for k in range(10, 5, -1):
            c[k - 6] = self.f2add(c[k - 6], self.f2mul(c[k], self.xi))
        return c[:6]

    def conj12(self, a):
        # f^(p^6): w^(p^6) = -w, so odd powers of w flip.
        return [a[k] if k % 2 == 0 else self.f2neg(a[k]) for k in range(6)]

    def frob12(self, a, n):
        return [self.f2mul(self.f2conj(a[k]) if n % 2 else a[k], self.gamma[n][k]) for k in range(6)]

    def inv12(self, a):
        # a^-1 = a^(p^6) * (a * a^(p^6))^-1, and a * a^(p^6) lies in Fp6 (even powers of w only).
        b = self.conj12(a)
        n = self.mul12(a, b)
        assert all(n[k] == (0, 0) for k in (1, 3, 5))
        # Invert n = g0 + g2 v + g4 v^2 in Fp6 = Fp2[v]/(v^3 - xi).
        a0, a1, a2 = n[0], n[2], n[4]
        t0 = self.f2sub(self.f2mul(a0, a0), self.f2mul(self.xi, self.f2mul(a1, a2)))
        t1 = self.f2sub(self.f2mul(self.xi, self.f2mul(a2, a2)), self.f2mul(a0, a1))
        t2 = self.f2sub(self.f2mul(a1, a1), self.f2mul(a0, a2))
        d = self.f2add(self.f2mul(a0, t0), self.f2mul(self.xi, self.f2add(self.f2mul(a2, t1), self.f2mul(a1, t2))))
        di = self.f2inv(d)
        ninv = [self.f2mul(t0, di), (0, 0), self.f2mul(t1, di), (0, 0), self.f2mul(t2, di), (0, 0)]
        return self.mul12(b, ninv)

    def pow12(self, a, e):
        r = self.one()
        for bit in bin(e)[2:]:
            r = self.mul12(r, r)
            if bit == "1":
                r = self.mul12(r, a)
        return r

    # ---- Twist points, homogeneous projective (X, Y, Z) ----
    def on_twist(self, q):
        x, y = q
        return self.f2sub(self.f2mul(y, y), self.f2add(self.f2mul(self.f2mul(x, x), x), self.b2)) == (0, 0)

    def line(self, a, b, c, xp, yp):
        """The line a*yP + b*xP + c in the Fp12 layout of this twist (a, b, c in Fp2)."""
        f = [(0, 0)] * 6
        if self.twist == "D":
            f[0], f[1], f[3] = self.f2scale(a, yp), self.f2scale(b, xp), c
        else:
            f[0], f[2], f[3] = c, self.f2scale(b, xp), self.f2scale(a, yp)
        return f

    def dbl(self, t, xp, yp):
        X, Y, Z = t
        m, s = self.f2mul, self.f2sub
        b3 = self.f2scale(self.b2, 3)
        YY, ZZ, XX = m(Y, Y), m(Z, Z), m(X, X)
        E = m(b3, ZZ)  # 3b'Z^2
        line = self.line(self.f2scale(m(Y, Z), 2), self.f2neg(self.f2scale(XX, 3)), s(YY, E), xp, yp)
        # 2T: X3 = XY/2 (Y^2 - 9b'Z^2), Y3 = ((Y^2 + 9b'Z^2)/2)^2 - 27 b'^2 Z^4, Z3 = 2 Y^3 Z
        inv2 = (self.p + 1) // 2
        F = self.f2scale(E, 3)
        X3 = self.f2scale(m(m(X, Y), s(YY, F)), inv2)
        G = self.f2scale(self.f2add(YY, F), inv2)
        Y3 = s(m(G, G), self.f2scale(m(E, E), 3))
        Z3 = self.f2scale(m(m(YY, Y), Z), 2)
        return (X3, Y3, Z3), line

    def add(self, t, q, xp, yp):
        X, Y, Z = t
        xq, yq = q
        m, s = self.f2mul, self.f2sub
        theta = s(Y, m(yq, Z))
        lam = s(X, m(xq, Z))
        # Line through Q with slope theta/lam, scaled by lam: lam*yP - theta*xP + (theta*xQ - lam*yQ).
        line = self.line(lam, self.f2neg(theta), s(m(theta, xq), m(lam, yq)), xp, yp)
        C, D = m(theta, theta), m(lam, lam)
        E, F, G = m(D, lam), m(Z, C), m(X, D)
        H = s(self.f2add(E, F), self.f2scale(G, 2))
        X3 = m(lam, H)
        Y3 = s(m(theta, s(G, H)), m(Y, E))
        Z3 = m(Z, E)
        return (X3, Y3, Z3), line

    def pi(self, q):
        return (self.f2mul(self.f2conj(q[0]), self.pi_x), self.f2mul(self.f2conj(q[1]), self.pi_y))

    def loop_bits(self):
        n = 6 * self.x + 2 if self.name == "bn254" else abs(self.x)
        return bin(n)[3:]

    def miller(self, pairs):
        """pairs: [((xP, yP), (xQ, yQ))], none at infinity."""
        f = self.one()
        ts = [(q[0], q[1], (1, 0)) for _, q in pairs]
        for bit in self.loop_bits():
            f = self.mul12(f, f)
            for i, (p_, q) in enumerate(pairs):
                ts[i], l = self.dbl(ts[i], *p_)
                f = self.mul12(f, l)
                if bit == "1":
                    ts[i], l = self.add(ts[i], q, *p_)
                    f = self.mul12(f, l)
        if self.name == "bn254":
            for i, (p_, q) in enumerate(pairs):
                q1 = self.pi(q)
                q2 = self.pi(q1)
                q2 = (q2[0], self.f2neg(q2[1]))
                ts[i], l = self.add(ts[i], q1, *p_)
                f = self.mul12(f, l)
                ts[i], l = self.add(ts[i], q2, *p_)
                f = self.mul12(f, l)
        return f

    def final_exp(self, f):
        f = self.mul12(self.conj12(f), self.inv12(f))
        f = self.mul12(self.frob12(f, 2), f)
        x = self.x
        # In the cyclotomic subgroup an inverse is a conjugate.
        def expx(a):
            r = self.pow12(a, abs(x))
            return self.conj12(r) if x < 0 else r
        if self.name == "bn254":
            # (p^4 - p^2 + 1)/r = l0 + l1 p + l2 p^2 + l3 p^3 with
            # l3 = 1, l2 = 6x^2 + 1, l1 = -36x^3 - 18x^2 - 12x + 1, l0 = -36x^3 - 30x^2 - 18x - 2.
            fx = expx(f)
            fx2 = expx(fx)
            fx3 = expx(fx2)
            def small(a, k):
                return self.pow12(a, k)
            l2 = self.mul12(small(fx2, 6), f)
            l1 = self.mul12(self.conj12(self.mul12(self.mul12(small(fx3, 36), small(fx2, 18)), small(fx, 12))), f)
            l0 = self.conj12(self.mul12(self.mul12(self.mul12(small(fx3, 36), small(fx2, 30)), small(fx, 18)), small(f, 2)))
            return self.mul12(self.mul12(l0, self.frob12(l1, 1)), self.mul12(self.frob12(l2, 2), self.frob12(f, 3)))
        # BLS12: 3(p^4 - p^2 + 1)/r = (x - 1)^2 (x + p) (x^2 + p^2 - 1) + 3.
        t0 = self.mul12(expx(f), self.conj12(f))
        t0 = self.mul12(expx(t0), self.conj12(t0))
        t1 = self.mul12(expx(t0), self.frob12(t0, 1))
        t2 = self.mul12(self.mul12(expx(expx(t1)), self.frob12(t1, 2)), self.conj12(t1))
        return self.mul12(t2, self.mul12(self.mul12(f, f), f))

    # ---- Subgroup checks ----
    def twist_add(self, a, b):
        """Affine addition on E' (None = infinity)."""
        if a is None:
            return b
        if b is None:
            return a
        if a[0] == b[0]:
            if self.f2add(a[1], b[1]) == (0, 0):
                return None
            lam = self.f2mul(self.f2scale(self.f2mul(a[0], a[0]), 3), self.f2inv(self.f2scale(a[1], 2)))
        else:
            lam = self.f2mul(self.f2sub(b[1], a[1]), self.f2inv(self.f2sub(b[0], a[0])))
        x = self.f2sub(self.f2sub(self.f2mul(lam, lam), a[0]), b[0])
        return (x, self.f2sub(self.f2mul(lam, self.f2sub(a[0], x)), a[1]))

    def twist_mul(self, k, q):
        r = None
        for bit in bin(k)[2:]:
            r = self.twist_add(r, r)
            if bit == "1":
                r = self.twist_add(r, q)
        return r

    def in_g2(self, q):
        """BN254: Q in G2 iff pi(Q) = [6x^2]Q (p = 6x^2 mod r)."""
        return self.pi(q) == self.twist_mul(6 * self.x * self.x, q)

    def g1_add(self, a, b):
        p = self.p
        if a is None:
            return b
        if b is None:
            return a
        if a[0] == b[0]:
            if (a[1] + b[1]) % p == 0:
                return None
            lam = 3 * a[0] * a[0] * pow(2 * a[1], p - 2, p) % p
        else:
            lam = (b[1] - a[1]) * pow(b[0] - a[0], p - 2, p) % p
        x = (lam * lam - a[0] - b[0]) % p
        return (x, (lam * (a[0] - x) - a[1]) % p)

    def g1_mul(self, k, a):
        r = None
        for bit in bin(k)[2:]:
            r = self.g1_add(r, r)
            if bit == "1":
                r = self.g1_add(r, a)
        return r

    def in_g1(self, a):
        """BLS12-381: P in G1 iff phi(P) = -[x^2]P, phi(x, y) = (beta x, y) with eigenvalue -x^2."""
        x2 = self.g1_mul(self.x * self.x, a)
        phi = (self.beta * a[0] % self.p, a[1])
        return x2 is not None and phi == (x2[0], (-x2[1]) % self.p)

    def pairing_check(self, pairs):
        live = [(p_, q) for p_, q in pairs if p_ is not None and q is not None]
        if not live:
            return True
        return self.final_exp(self.miller(live)) == self.one()


BN254 = Curve("bn254",
              0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47,
              0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001,
              4965661367192848881, 3, (9, 1), "D")
BLS12_381 = Curve("bls12_381",
                  0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB,
                  0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
                  -0xD201000000010000, 4, (1, 1), "M")


def _bls_beta():
    """The cube root of unity mod p whose map (x, y) -> (beta x, y) is [-x^2] on G1."""
    c = BLS12_381
    g = (0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB,
         0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1)
    for g0 in range(2, 50):
        b = pow(g0, (c.p - 1) // 3, c.p)
        if b == 1:
            continue
        for beta in (b, b * b % c.p):
            lam = c.g1_mul(c.x * c.x, g)
            if (beta * g[0] % c.p, g[1]) == (lam[0], (-lam[1]) % c.p):
                return beta
    raise AssertionError("no beta")


BLS12_381.beta = _bls_beta()
BLS12_381.G1 = (0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB,
                0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1)
