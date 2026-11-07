/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Fp2/Fp6/Fp12 on the SP1 field precompiles, the projective Miller-loop steps and the final
 * exponentiation, shared by the BN254 and BLS12-381 pairings. model.py is the reference: every
 * formula here is its counterpart there, checked against py_ecc by tests/pairing.
 *
 * Include after fields.h and the curve's constants header, with:
 *   SYS_FP_ADD, SYS_FP_SUB, SYS_FP_MUL, SYS_FP2_ADD, SYS_FP2_SUB, SYS_FP2_MUL   precompile ids
 *   FP_BYTES                     big-endian encoding width of an Fp element
 *   TWIST_D                      1 for a D-type twist (BN254), 0 for an M-type one (BLS12-381)
 *   BN_CURVE                     1 for BN254's optimal-ate loop and final exponentiation
 *   XI_ONE_PLUS_U                1 when xi = 1 + u, multiplied by with one addition and one subtraction
 *
 * The field precompiles compute x op= y on canonical operands. Each reads y, then reads and writes
 * x one memory clock later, so y may be x itself: a helper copies only when its result is a third
 * value, or is the second operand of a subtraction. All values stay canonical (below p). */

#ifndef PAIRING_TOWER_H
#define PAIRING_TOWER_H

/* ---- Fp ---------------------------------------------------------------- */

static inline void fp_set_small(fp *r, uint64_t v)
{
    r->v[0] = v;
    for (int i = 1; i < NL; i++)
        r->v[i] = 0;
}

static inline int fp_is_zero(const fp *a)
{
    uint64_t t = 0;
    for (int i = 0; i < NL; i++)
        t |= a->v[i];
    return t == 0;
}

static inline int fp_eq(const fp *a, const fp *b)
{
    uint64_t t = 0;
    for (int i = 0; i < NL; i++)
        t |= a->v[i] ^ b->v[i];
    return t == 0;
}

static inline int fp_lt(const fp *a, const fp *b)
{
    for (int i = NL - 1; i >= 0; i--)
    {
        if (a->v[i] != b->v[i])
            return a->v[i] < b->v[i];
    }
    return 0;
}

static inline void fp_load(fp *r, const uint8_t *b)
{
    for (int i = 0; i < NL; i++)
    {
        const uint8_t *w = b + 8 * (NL - 1 - i);
        uint64_t v = 0;
        for (int j = 0; j < 8; j++)
            v = (v << 8) | w[j];
        r->v[i] = v;
    }
}

static inline void fp_store(uint8_t *b, const fp *a)
{
    for (int i = 0; i < NL; i++)
    {
        uint8_t *w = b + 8 * (NL - 1 - i);
        for (int j = 0; j < 8; j++)
            w[j] = (uint8_t)(a->v[i] >> (56 - 8 * j));
    }
}

static inline void fp_op(uint64_t id, int commutes, fp *r, const fp *a, const fp *b)
{
    if (r == b && r != a)
    {
        if (commutes)
        {
            sp1_syscall(id, r, a);
            return;
        }
        fp t = *a;
        sp1_syscall(id, &t, b);
        *r = t;
        return;
    }
    if (r != a)
        *r = *a;
    sp1_syscall(id, r, b);
}

static inline void fp_add(fp *r, const fp *a, const fp *b)
{
    fp_op(SYS_FP_ADD, 1, r, a, b);
}

static inline void fp_sub(fp *r, const fp *a, const fp *b)
{
    fp_op(SYS_FP_SUB, 0, r, a, b);
}

static inline void fp_mul(fp *r, const fp *a, const fp *b)
{
    fp_op(SYS_FP_MUL, 1, r, a, b);
}

static inline void fp_neg(fp *r, const fp *a)
{
    fp t;
    if (r == a)
    {
        t = *a;
        a = &t;
    }
    fp_set_small(r, 0);
    fp_sub(r, r, a);
}

/* r = a^e, e given as NL limbs. */
static void fp_pow(fp *r, const fp *a, const fp *e)
{
    fp acc, base = *a;
    fp_set_small(&acc, 1);
    for (int i = 64 * NL - 1; i >= 0; i--)
    {
        fp_mul(&acc, &acc, &acc);
        if ((e->v[i >> 6] >> (i & 63)) & 1)
            fp_mul(&acc, &acc, &base);
    }
    *r = acc;
}

/* r = a^-1 for a != 0, by Fermat: once per pairing, so the exponentiation is cheap enough. */
static void fp_inv(fp *r, const fp *a)
{
    fp_pow(r, a, &P_MINUS_2);
}

/* ---- Fp2 = Fp[u]/(u^2 + 1) --------------------------------------------- */

static inline void fp2_set_small(fp2 *r, uint64_t v)
{
    fp_set_small(&r->c0, v);
    fp_set_small(&r->c1, 0);
}

static inline int fp2_is_zero(const fp2 *a)
{
    return fp_is_zero(&a->c0) && fp_is_zero(&a->c1);
}

static inline int fp2_eq(const fp2 *a, const fp2 *b)
{
    return fp_eq(&a->c0, &b->c0) && fp_eq(&a->c1, &b->c1);
}

static inline void fp2_op(uint64_t id, int commutes, fp2 *r, const fp2 *a, const fp2 *b)
{
    if (r == b && r != a)
    {
        if (commutes)
        {
            sp1_syscall(id, r, a);
            return;
        }
        fp2 t = *a;
        sp1_syscall(id, &t, b);
        *r = t;
        return;
    }
    if (r != a)
        *r = *a;
    sp1_syscall(id, r, b);
}

static inline void fp2_add(fp2 *r, const fp2 *a, const fp2 *b)
{
    fp2_op(SYS_FP2_ADD, 1, r, a, b);
}

static inline void fp2_sub(fp2 *r, const fp2 *a, const fp2 *b)
{
    fp2_op(SYS_FP2_SUB, 0, r, a, b);
}

static inline void fp2_mul(fp2 *r, const fp2 *a, const fp2 *b)
{
    fp2_op(SYS_FP2_MUL, 1, r, a, b);
}

static inline void fp2_sqr(fp2 *r, const fp2 *a)
{
    fp2_mul(r, a, a);
}

static inline void fp2_dbl(fp2 *r, const fp2 *a)
{
    fp2_add(r, a, a);
}

static inline void fp2_neg(fp2 *r, const fp2 *a)
{
    fp2 t;
    if (r == a)
    {
        t = *a;
        a = &t;
    }
    fp2_set_small(r, 0);
    fp2_sub(r, r, a);
}

static inline void fp2_conj(fp2 *r, const fp2 *a)
{
    r->c0 = a->c0;
    fp_neg(&r->c1, &a->c1);
}

/* r = a * s for s in Fp: two Fp products cost less than one Fp2 product with (s, 0). */
static inline void fp2_scale(fp2 *r, const fp2 *a, const fp *s)
{
    fp_mul(&r->c0, &a->c0, s);
    fp_mul(&r->c1, &a->c1, s);
}

static inline void fp2_mul_xi(fp2 *r, const fp2 *a)
{
#if XI_ONE_PLUS_U
    /* (a0 + a1 u)(1 + u) = (a0 - a1) + (a0 + a1) u */
    if (r == a)
    {
        fp t = a->c1;
        fp_add(&r->c1, &r->c1, &r->c0);
        fp_sub(&r->c0, &r->c0, &t);
        return;
    }
    fp_add(&r->c1, &a->c0, &a->c1);
    fp_sub(&r->c0, &a->c0, &a->c1);
#else
    fp2_mul(r, a, &XI);
#endif
}

/* r = a^-1 = conj(a) / (a0^2 + a1^2), for a != 0. */
static void fp2_inv(fp2 *r, const fp2 *a)
{
    fp n, t;
    fp_mul(&n, &a->c0, &a->c0);
    fp_mul(&t, &a->c1, &a->c1);
    fp_add(&n, &n, &t);
    fp_inv(&n, &n);
    fp2 c;
    fp2_conj(&c, a);
    fp2_scale(r, &c, &n);
}

/* ---- Fp6 = Fp2[v]/(v^3 - xi) ------------------------------------------- */

static inline void fp6_add(fp6 *r, const fp6 *a, const fp6 *b)
{
    fp2_add(&r->c0, &a->c0, &b->c0);
    fp2_add(&r->c1, &a->c1, &b->c1);
    fp2_add(&r->c2, &a->c2, &b->c2);
}

static inline void fp6_sub(fp6 *r, const fp6 *a, const fp6 *b)
{
    fp2_sub(&r->c0, &a->c0, &b->c0);
    fp2_sub(&r->c1, &a->c1, &b->c1);
    fp2_sub(&r->c2, &a->c2, &b->c2);
}

static inline void fp6_neg(fp6 *r, const fp6 *a)
{
    fp2_neg(&r->c0, &a->c0);
    fp2_neg(&r->c1, &a->c1);
    fp2_neg(&r->c2, &a->c2);
}

/* Karatsuba: six Fp2 products, written straight into r, which must not overlap a or b. */
static void fp6_mul(fp6 *r, const fp6 *a, const fp6 *b)
{
    fp2 t0, t1, t2, u;
    fp2_mul(&t0, &a->c0, &b->c0);
    fp2_mul(&t1, &a->c1, &b->c1);
    fp2_mul(&t2, &a->c2, &b->c2);

    fp2_add(&r->c0, &a->c1, &a->c2);
    fp2_add(&u, &b->c1, &b->c2);
    fp2_mul(&r->c0, &r->c0, &u);
    fp2_sub(&r->c0, &r->c0, &t1);
    fp2_sub(&r->c0, &r->c0, &t2);
    fp2_mul_xi(&r->c0, &r->c0);
    fp2_add(&r->c0, &r->c0, &t0);

    fp2_add(&r->c2, &a->c0, &a->c2);
    fp2_add(&u, &b->c0, &b->c2);
    fp2_mul(&r->c2, &r->c2, &u);
    fp2_sub(&r->c2, &r->c2, &t0);
    fp2_sub(&r->c2, &r->c2, &t2);
    fp2_add(&r->c2, &r->c2, &t1);

    fp2_add(&r->c1, &a->c0, &a->c1);
    fp2_add(&u, &b->c0, &b->c1);
    fp2_mul(&r->c1, &r->c1, &u);
    fp2_sub(&r->c1, &r->c1, &t0);
    fp2_sub(&r->c1, &r->c1, &t1);
    fp2_mul_xi(&t2, &t2);
    fp2_add(&r->c1, &r->c1, &t2);
}

/* r = a + b v = (a0 + xi b2, a1 + b0, a2 + b1). r may be a; b must not overlap r. */
static inline void fp6_add_mul_v(fp6 *r, const fp6 *a, const fp6 *b)
{
    fp2 x;
    fp2_mul_xi(&x, &b->c2);
    fp2_add(&r->c0, &a->c0, &x);
    fp2_add(&r->c1, &a->c1, &b->c0);
    fp2_add(&r->c2, &a->c2, &b->c1);
}

/* r = a - b v. r may be a; b must not overlap r. */
static inline void fp6_sub_mul_v(fp6 *r, const fp6 *a, const fp6 *b)
{
    fp2 x;
    fp2_mul_xi(&x, &b->c2);
    fp2_sub(&r->c0, &a->c0, &x);
    fp2_sub(&r->c1, &a->c1, &b->c0);
    fp2_sub(&r->c2, &a->c2, &b->c1);
}

/* r = a * (b0, b1, 0). r may alias a; b0 and b1 must not overlap r. */
static void fp6_mul_by_01(fp6 *r, const fp6 *a, const fp2 *b0, const fp2 *b1)
{
    fp2 t0, t1, u;
    fp2_mul(&t0, &a->c0, b0);
    fp2_mul(&t1, &a->c1, b1);
    /* a0 and a1 are spent from here on, and a2 after the last product with it. */
    fp2_add(&r->c1, &a->c0, &a->c1);
    fp2_mul(&r->c0, &a->c2, b1);
    fp2_mul_xi(&r->c0, &r->c0);
    fp2_add(&r->c0, &r->c0, &t0);
    fp2_mul(&r->c2, &a->c2, b0);
    fp2_add(&r->c2, &r->c2, &t1);
    fp2_add(&u, b0, b1);
    fp2_mul(&r->c1, &r->c1, &u);
    fp2_sub(&r->c1, &r->c1, &t0);
    fp2_sub(&r->c1, &r->c1, &t1);
}

#if !TWIST_D
/* r = a * (0, b1, 0) = (xi a2 b1, a0 b1, a1 b1). r may alias a. */
static void fp6_mul_by_1(fp6 *r, const fp6 *a, const fp2 *b1)
{
    fp2 c0;
    fp2_mul(&c0, &a->c2, b1);
    fp2_mul_xi(&c0, &c0);
    fp2_mul(&r->c2, &a->c1, b1);
    fp2_mul(&r->c1, &a->c0, b1);
    r->c0 = c0;
}
#else
/* r = a * (b0, 0, 0). */
static void fp6_mul_by_0(fp6 *r, const fp6 *a, const fp2 *b0)
{
    fp2_mul(&r->c0, &a->c0, b0);
    fp2_mul(&r->c1, &a->c1, b0);
    fp2_mul(&r->c2, &a->c2, b0);
}
#endif

static void fp6_inv(fp6 *r, const fp6 *a)
{
    fp2 t0, t1, t2, s, d;
    fp2_sqr(&t0, &a->c0);
    fp2_mul(&s, &a->c1, &a->c2);
    fp2_mul_xi(&s, &s);
    fp2_sub(&t0, &t0, &s);

    fp2_sqr(&t1, &a->c2);
    fp2_mul_xi(&t1, &t1);
    fp2_mul(&s, &a->c0, &a->c1);
    fp2_sub(&t1, &t1, &s);

    fp2_sqr(&t2, &a->c1);
    fp2_mul(&s, &a->c0, &a->c2);
    fp2_sub(&t2, &t2, &s);

    fp2_mul(&d, &a->c2, &t1);
    fp2_mul(&s, &a->c1, &t2);
    fp2_add(&d, &d, &s);
    fp2_mul_xi(&d, &d);
    fp2_mul(&s, &a->c0, &t0);
    fp2_add(&d, &d, &s);
    fp2_inv(&d, &d);

    fp2_mul(&r->c0, &t0, &d);
    fp2_mul(&r->c1, &t1, &d);
    fp2_mul(&r->c2, &t2, &d);
}

/* ---- Fp12 = Fp6[w]/(w^2 - v) ------------------------------------------- */

static inline void fp12_set_one(fp12 *r)
{
    fp2_set_small(&r->c0.c0, 1);
    fp2_set_small(&r->c0.c1, 0);
    fp2_set_small(&r->c0.c2, 0);
    r->c1.c0 = r->c1.c1 = r->c1.c2 = r->c0.c1;
}

static int fp12_is_one(const fp12 *a)
{
    fp2 one, zero;
    fp2_set_small(&one, 1);
    fp2_set_small(&zero, 0);
    return fp2_eq(&a->c0.c0, &one) && fp2_eq(&a->c0.c1, &zero) && fp2_eq(&a->c0.c2, &zero) &&
           fp2_eq(&a->c1.c0, &zero) && fp2_eq(&a->c1.c1, &zero) && fp2_eq(&a->c1.c2, &zero);
}

/* r may alias a or b: neither is read once the products start writing r. */
static void fp12_mul(fp12 *r, const fp12 *a, const fp12 *b)
{
    fp6 t0, t1, s, u;
    fp6_mul(&t0, &a->c0, &b->c0);
    fp6_mul(&t1, &a->c1, &b->c1);
    fp6_add(&s, &a->c0, &a->c1);
    fp6_add(&u, &b->c0, &b->c1);
    fp6_mul(&r->c1, &s, &u);
    fp6_sub(&r->c1, &r->c1, &t0);
    fp6_sub(&r->c1, &r->c1, &t1);
    fp6_add_mul_v(&r->c0, &t0, &t1);
}

/* (a0 + a1 w)^2 = (a0 + a1)(a0 + v a1) - t - v t + 2t w, t = a0 a1. r may alias a. */
static void fp12_sqr(fp12 *r, const fp12 *a)
{
    fp6 t, s, u;
    fp6_mul(&t, &a->c0, &a->c1);
    fp6_add(&s, &a->c0, &a->c1);
    fp6_add_mul_v(&u, &a->c0, &a->c1);
    fp6_mul(&r->c0, &s, &u);
    fp6_sub(&r->c0, &r->c0, &t);
    fp6_sub_mul_v(&r->c0, &r->c0, &t);
    fp6_add(&r->c1, &t, &t);
}

/* a^(p^6): odd powers of w flip sign. In the cyclotomic subgroup this is the inverse. */
static inline void fp12_conj(fp12 *r, const fp12 *a)
{
    r->c0 = a->c0;
    fp6_neg(&r->c1, &a->c1);
}

/* a^-1 = (a0 - a1 w) / (a0^2 - v a1^2). */
static void fp12_inv(fp12 *r, const fp12 *a)
{
    fp6 t0, t1;
    fp6_mul(&t0, &a->c0, &a->c0);
    fp6_mul(&t1, &a->c1, &a->c1);
    fp6_sub_mul_v(&t0, &t0, &t1);
    fp6_inv(&t0, &t0);
    fp6_mul(&r->c0, &a->c0, &t0);
    fp6_mul(&r->c1, &a->c1, &t0);
    fp6_neg(&r->c1, &r->c1);
}

/* a^(p^n), n = 1..3: coefficient k of w (g0 = c0.c0, g1 = c1.c0, g2 = c0.c1, ...) becomes
 * conj^n(g_k) * GAMMA[n - 1][k]. */
static void fp12_frob(fp12 *r, const fp12 *a, int n)
{
    fp2 *out[6] = {&r->c0.c0, &r->c1.c0, &r->c0.c1, &r->c1.c1, &r->c0.c2, &r->c1.c2};
    const fp2 *in[6] = {&a->c0.c0, &a->c1.c0, &a->c0.c1, &a->c1.c1, &a->c0.c2, &a->c1.c2};
    for (int k = 0; k < 6; k++)
    {
        fp2 g;
        if (n & 1)
            fp2_conj(&g, in[k]);
        else
            g = *in[k];
        if (k == 0)
            *out[k] = g;
        else
            fp2_mul(out[k], &g, &GAMMA[n - 1][k]);
    }
}

/* (x + y t)^2 = (x^2 + xi y^2) + 2xy t over Fp4 = Fp2[t]/(t^2 - xi). r0 and r1 must not overlap
 * x or y. */
static void fp4_sqr(fp2 *r0, fp2 *r1, const fp2 *x, const fp2 *y)
{
    fp2 u;
    fp2_mul(r1, x, y);
    fp2_mul_xi(&u, y);
    fp2_add(&u, &u, x);
    fp2_add(r0, x, y);
    fp2_mul(r0, r0, &u);
    fp2_sub(r0, r0, r1);
    fp2_mul_xi(&u, r1);
    fp2_sub(r0, r0, &u);
    fp2_dbl(r1, r1);
}

/* z = 3t + 2z when plus, else 3t - 2z. */
static void cyclotomic_combine(fp2 *z, const fp2 *t, int plus)
{
    if (plus)
    {
        fp2_add(z, z, t);
        fp2_dbl(z, z);
        fp2_add(z, z, t);
        return;
    }
    fp2 s;
    fp2_sub(&s, t, z);
    fp2_dbl(&s, &s);
    fp2_add(z, &s, t);
}

/* r = a^2 for a in the cyclotomic subgroup (Granger-Scott): three Fp4 squarings, combined in
 * place. */
static void fp12_cyclotomic_sqr(fp12 *r, const fp12 *a)
{
    if (r != a)
        *r = *a;
    fp2 *z0 = &r->c0.c0, *z4 = &r->c0.c1, *z3 = &r->c0.c2, *z2 = &r->c1.c0, *z1 = &r->c1.c1, *z5 = &r->c1.c2;
    fp2 t0, t1, t2, t3, t4, t5;
    fp4_sqr(&t0, &t1, z0, z1);
    fp4_sqr(&t2, &t3, z2, z3);
    fp4_sqr(&t4, &t5, z4, z5);
    cyclotomic_combine(z0, &t0, 0);
    cyclotomic_combine(z1, &t1, 1);
    fp2_mul_xi(&t5, &t5);
    cyclotomic_combine(z2, &t5, 1);
    cyclotomic_combine(z3, &t4, 0);
    cyclotomic_combine(z4, &t2, 0);
    cyclotomic_combine(z5, &t3, 1);
}

/* a^x for the curve parameter x, a in the cyclotomic subgroup, over the signed digits of |x|:
 * there a^-1 is a conjugate, so a negative digit costs no more than a positive one. */
static void fp12_exp_x(fp12 *r, const fp12 *a)
{
    fp12 acc = *a, inv;
    fp12_conj(&inv, a);
    for (int i = 1; i < X_NAF_LEN; i++)
    {
        fp12_cyclotomic_sqr(&acc, &acc);
        if (X_NAF[i] > 0)
            fp12_mul(&acc, &acc, a);
        else if (X_NAF[i] < 0)
            fp12_mul(&acc, &acc, &inv);
    }
    if (X_NEGATIVE)
        fp12_conj(&acc, &acc);
    *r = acc;
}

/* ---- Lines and the twist ----------------------------------------------- */

/* f *= the line a*yP + b*xP + c, placed at w^0, w^1, w^3 (D-type: l0 = (a yP, 0, 0),
 * l1 = (b xP, c, 0)) or w^3, w^2, w^0 (M-type: l0 = (c, b xP, 0), l1 = (0, a yP, 0)), by Karatsuba
 * over Fp6 with the sparse factors multiplied directly. */
static void fp12_mul_line(fp12 *f, const fp2 *a, const fp2 *b, const fp2 *c, const fp *xp, const fp *yp)
{
    fp2 ay, bx, s0, s1;
    fp6 t0, t1;
    fp2_scale(&ay, a, yp);
    fp2_scale(&bx, b, xp);
#if TWIST_D
    fp6_mul_by_0(&t0, &f->c0, &ay);
    fp6_mul_by_01(&t1, &f->c1, &bx, c);
    fp2_add(&s0, &ay, &bx);
    s1 = *c;
#else
    fp6_mul_by_01(&t0, &f->c0, c, &bx);
    fp6_mul_by_1(&t1, &f->c1, &ay);
    s0 = *c;
    fp2_add(&s1, &bx, &ay);
#endif
    fp6_add(&f->c1, &f->c0, &f->c1);
    fp6_mul_by_01(&f->c1, &f->c1, &s0, &s1);
    fp6_sub(&f->c1, &f->c1, &t0);
    fp6_sub(&f->c1, &f->c1, &t1);
    fp6_add_mul_v(&f->c0, &t0, &t1);
}

/* T = 2T and, unless f is NULL, f *= the tangent at T evaluated at P. */
static void g2_dbl_line(g2_proj *t, fp12 *f, const fp *xp, const fp *yp)
{
    fp2 yy, e, a, b, c, s;
    fp2_sqr(&yy, &t->y);
    fp2_sqr(&e, &t->z);
    fp2_mul(&e, &e, &TWIST_B3);
    fp2_mul(&a, &t->y, &t->z);
    fp2_dbl(&a, &a);
    fp2_sqr(&s, &t->x);
    fp2_set_small(&b, 0);
    fp2_sub(&b, &b, &s);
    fp2_sub(&b, &b, &s);
    fp2_sub(&b, &b, &s);
    fp2_sub(&c, &yy, &e);
    if (f)
        fp12_mul_line(f, &a, &b, &c, xp, yp);

    /* X3 = XY (Y^2 - 9bZ^2) / 2, Y3 = ((Y^2 + 9bZ^2) / 2)^2 - 27b^2 Z^4, Z3 = 2Y^3 Z, each
     * computed where it is stored once the old coordinate is spent. */
    fp2 f3;
    fp2_dbl(&f3, &e);
    fp2_add(&f3, &f3, &e);
    fp2_mul(&t->z, &t->z, &t->y);
    fp2_mul(&t->z, &t->z, &yy);
    fp2_dbl(&t->z, &t->z);
    fp2_mul(&t->x, &t->x, &t->y);
    fp2_sub(&s, &yy, &f3);
    fp2_mul(&t->x, &t->x, &s);
    fp2_scale(&t->x, &t->x, &INV2);
    fp2_add(&f3, &f3, &yy);
    fp2_scale(&f3, &f3, &INV2);
    fp2_sqr(&t->y, &f3);
    fp2_sqr(&e, &e);
    fp2_sub(&t->y, &t->y, &e);
    fp2_sub(&t->y, &t->y, &e);
    fp2_sub(&t->y, &t->y, &e);
}

/* T = T + Q and, unless f is NULL, f *= the line through T and Q evaluated at P. T != +-Q. */
static void g2_add_line(g2_proj *t, const g2_affine *q, fp12 *f, const fp *xp, const fp *yp)
{
    fp2 theta, lam, s, c, nt;
    fp2_mul(&s, &q->y, &t->z);
    fp2_sub(&theta, &t->y, &s);
    fp2_mul(&s, &q->x, &t->z);
    fp2_sub(&lam, &t->x, &s);
    fp2_mul(&c, &theta, &q->x);
    fp2_mul(&s, &lam, &q->y);
    fp2_sub(&c, &c, &s);
    fp2_neg(&nt, &theta);
    if (f)
        fp12_mul_line(f, &lam, &nt, &c, xp, yp);

    /* With g = X lam^2 and h = lam^3 + Z theta^2 - 2g: X3 = lam h, Y3 = theta (g - h) - Y lam^3,
     * Z3 = Z lam^3. g takes X's place and h theta^2's. */
    fp2 h, d, e;
    fp2_sqr(&h, &theta);
    fp2_mul(&h, &h, &t->z);
    fp2_sqr(&d, &lam);
    fp2_mul(&e, &d, &lam);
    fp2_mul(&t->x, &t->x, &d);
    fp2_add(&h, &h, &e);
    fp2_sub(&h, &h, &t->x);
    fp2_sub(&h, &h, &t->x);
    fp2_sub(&t->x, &t->x, &h);
    fp2_mul(&theta, &theta, &t->x);
    fp2_mul(&t->y, &t->y, &e);
    fp2_sub(&t->y, &theta, &t->y);
    fp2_mul(&t->z, &t->z, &e);
    fp2_mul(&t->x, &lam, &h);
}

#if BN_CURVE
/* The twisted Frobenius pi(Q) = (conj(x) PI_X, conj(y) PI_Y). */
static void g2_frob(g2_affine *r, const g2_affine *q)
{
    fp2 t;
    fp2_conj(&t, &q->x);
    fp2_mul(&r->x, &t, &PI_X);
    fp2_conj(&t, &q->y);
    fp2_mul(&r->y, &t, &PI_Y);
}
#endif

#define MILLER_BATCH 8

/* f *= the Miller function of each pair (P, Q), none at infinity, n <= MILLER_BATCH. One shared
 * squaring per step. For BLS12-381 x < 0 is ignored: the function of -x is the inverse of that of
 * x up to vertical lines, which only changes the pairing check's result to its inverse. */
static void miller_loop(fp12 *f, const fp *xp, const fp *yp, const g2_affine *q, int n)
{
    g2_proj t[MILLER_BATCH];
    g2_affine neg[MILLER_BATCH];
    fp12 m;
    fp12_set_one(&m);
    for (int k = 0; k < n; k++)
    {
        t[k].x = q[k].x;
        t[k].y = q[k].y;
        fp2_set_small(&t[k].z, 1);
        neg[k].x = q[k].x;
        fp2_neg(&neg[k].y, &q[k].y);
    }
    /* Signed digits: a -1 adds -Q, whose line differs from the binary loop's by vertical lines,
     * which the final exponentiation removes. */
    for (int i = 1; i < LOOP_NAF_LEN; i++)
    {
        if (i != 1)
            fp12_sqr(&m, &m);
        int digit = LOOP_NAF[i];
        for (int k = 0; k < n; k++)
        {
            g2_dbl_line(&t[k], &m, &xp[k], &yp[k]);
            if (digit)
                g2_add_line(&t[k], digit > 0 ? &q[k] : &neg[k], &m, &xp[k], &yp[k]);
        }
    }
#if BN_CURVE
    for (int k = 0; k < n; k++)
    {
        g2_affine q1, q2;
        g2_frob(&q1, &q[k]);
        g2_frob(&q2, &q1);
        fp2_neg(&q2.y, &q2.y);
        g2_add_line(&t[k], &q1, &m, &xp[k], &yp[k]);
        g2_add_line(&t[k], &q2, &m, &xp[k], &yp[k]);
    }
#endif
    fp12_mul(f, f, &m);
}

/* f^(m (p^12 - 1)/r) for BN254, m = 2x(6x^2 + 3x + 1); f^(3 (p^12 - 1)/r) for BLS12-381. Either is
 * 1 exactly when f^((p^12 - 1)/r) is, as m and 3 are coprime to r. */
static void final_exp(fp12 *r, const fp12 *f)
{
    fp12 a, b;
    /* Easy part: f^((p^6 - 1)(p^2 + 1)). */
    fp12_inv(&b, f);
    fp12_conj(&a, f);
    fp12_mul(&a, &a, &b);
    fp12_frob(&b, &a, 2);
    fp12_mul(&a, &b, &a);
#if BN_CURVE
    /* Hard part, as Fuentes-Castaneda, Knapp and Rodriguez-Henriquez: m (p^4 - p^2 + 1)/r =
     * (12x^3 + 12x^2 + 6x + 1) + (12x^3 + 6x^2 + 4x) p + (12x^3 + 6x^2 + 6x) p^2
     * + (12x^3 + 6x^2 + 4x - 1) p^3. Three exponentiations by x, three squarings and ten
     * products, where the plain exponent costs some 25 squarings and 8 products more. */
    fp12 a2x, a6x, a6x2, k, t;
    fp12_exp_x(&t, &a);
    fp12_cyclotomic_sqr(&a2x, &t);
    fp12_cyclotomic_sqr(&a6x, &a2x);
    fp12_mul(&a6x, &a6x, &a2x);
    fp12_exp_x(&a6x2, &a6x);
    fp12_cyclotomic_sqr(&t, &a6x2);
    fp12_exp_x(&k, &t);
    fp12_mul(&k, &k, &a6x2);
    fp12_mul(&k, &k, &a6x);

    fp12 l, n;
    fp12_conj(&t, &a2x);
    fp12_mul(&l, &k, &t);
    fp12_mul(&n, &k, &a6x2);
    fp12_mul(&n, &n, &a);
    fp12_frob(&t, &l, 1);
    fp12_mul(&n, &n, &t);
    fp12_frob(&t, &k, 2);
    fp12_mul(&n, &n, &t);
    fp12_conj(&t, &a);
    fp12_mul(&l, &l, &t);
    fp12_frob(&t, &l, 3);
    fp12_mul(r, &n, &t);
#else
    /* 3 (p^4 - p^2 + 1)/r = (x - 1)^2 (x + p) (x^2 + p^2 - 1) + 3. */
    fp12 t0, t1, t2, s;
    fp12_exp_x(&t0, &a);
    fp12_conj(&s, &a);
    fp12_mul(&t0, &t0, &s);
    fp12_exp_x(&t1, &t0);
    fp12_conj(&s, &t0);
    fp12_mul(&t0, &t1, &s);
    fp12_exp_x(&t1, &t0);
    fp12_frob(&s, &t0, 1);
    fp12_mul(&t1, &t1, &s);
    fp12_exp_x(&t2, &t1);
    fp12_exp_x(&t2, &t2);
    fp12_frob(&s, &t1, 2);
    fp12_mul(&t2, &t2, &s);
    fp12_conj(&s, &t1);
    fp12_mul(&t2, &t2, &s);
    fp12_cyclotomic_sqr(&s, &a);
    fp12_mul(&s, &s, &a);
    fp12_mul(r, &t2, &s);
#endif
}

#endif
