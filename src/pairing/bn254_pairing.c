/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * zkvm_bn254_pairing for SP1 (EIP-197, precompile 0x08), replacing the zkEVM SDK's.
 *
 * The SDK pairs through substrate-bn, whose tower arithmetic reaches the BN254 field precompiles
 * one element at a time and copies every operand in and out (~2.3M instructions for two pairs).
 * Here Fp2 products, sums and differences are single BN254_FP2 precompile calls on operands laid
 * out the way the precompile takes them; see tower.h for the Miller loop and the final
 * exponentiation, and model.py for the reference they follow.
 *
 * EIP-197 requires both points on their curves and the G2 point in the order-r subgroup. G2 has a
 * large cofactor, so that check is real work: Q is in G2 exactly when pi(Q) = [6x^2]Q (p = 6x^2
 * mod r for BN curves), a 127-bit multiplication instead of a 254-bit one. */

#include <stdbool.h>

#include "../common/u256.h"

#define NL 4
#define FP_BYTES 32
#define SYS_FP_ADD 0x00010126ULL
#define SYS_FP_SUB 0x00010127ULL
#define SYS_FP_MUL 0x00010128ULL
#define SYS_FP2_ADD 0x00010129ULL
#define SYS_FP2_SUB 0x0001012aULL
#define SYS_FP2_MUL 0x0001012bULL
#define TWIST_D 1
#define BN_CURVE 1
#define XI_ONE_PLUS_U 0

#include "fields.h"
#include "bn254_constants.h"
#include "tower.h"

#define ZKVM_EOK 0
#define ZKVM_EFAIL (-1)

/* 1 for a point, 0 for the encoding of infinity (all zero), -1 for anything else. */
static int decode_g1(fp *x, fp *y, const uint8_t *b)
{
    fp_load(x, b);
    fp_load(y, b + FP_BYTES);
    if (!fp_lt(x, &FIELD_P) || !fp_lt(y, &FIELD_P))
        return -1;
    if (fp_is_zero(x) && fp_is_zero(y))
        return 0;
    fp lhs, rhs;
    fp_mul(&lhs, y, y);
    fp_mul(&rhs, x, x);
    fp_mul(&rhs, &rhs, x);
    fp_add(&rhs, &rhs, &CURVE_B);
    return fp_eq(&lhs, &rhs) ? 1 : -1;
}

static int on_twist(const g2_affine *q)
{
    fp2 lhs, rhs;
    fp2_sqr(&lhs, &q->y);
    fp2_sqr(&rhs, &q->x);
    fp2_mul(&rhs, &rhs, &q->x);
    fp2_add(&rhs, &rhs, &TWIST_B);
    return fp2_eq(&lhs, &rhs);
}

/* [6x^2]Q == pi(Q) for Q on E', over the signed digits of 6x^2. The double-and-add tracks
 * infinity and the degenerate additions a point outside G2 can reach (T = +-D for the point D
 * being added, or a doubling to a point of order 2). */
static int in_g2(const g2_affine *q)
{
    g2_affine neg = {q->x, q->y};
    fp2_neg(&neg.y, &q->y);
    g2_proj t;
    int infinity = 1;
    for (int i = 0; i < SIX_X2_NAF_LEN; i++)
    {
        if (!infinity)
        {
            g2_dbl_line(&t, NULL, NULL, NULL);
            if (fp2_is_zero(&t.z))
                infinity = 1;
        }
        int digit = SIX_X2_NAF[i];
        if (!digit)
            continue;
        const g2_affine *d = digit > 0 ? q : &neg;
        if (infinity)
        {
            t.x = d->x;
            t.y = d->y;
            fp2_set_small(&t.z, 1);
            infinity = 0;
            continue;
        }
        fp2 xz, yz;
        fp2_mul(&xz, &d->x, &t.z);
        fp2_mul(&yz, &d->y, &t.z);
        if (fp2_eq(&xz, &t.x))
        {
            if (fp2_eq(&yz, &t.y))
            {
                g2_dbl_line(&t, NULL, NULL, NULL);
                if (fp2_is_zero(&t.z))
                    infinity = 1;
            }
            else
            {
                infinity = 1;
            }
            continue;
        }
        g2_add_line(&t, d, NULL, NULL, NULL);
    }
    if (infinity)
        return 0;
    g2_affine pq;
    g2_frob(&pq, q);
    fp2 xz, yz;
    fp2_mul(&xz, &pq.x, &t.z);
    fp2_mul(&yz, &pq.y, &t.z);
    return fp2_eq(&xz, &t.x) && fp2_eq(&yz, &t.y);
}

/* EIP-197 encodes an Fp2 element imaginary part first: x.c1 | x.c0 | y.c1 | y.c0. */
static int decode_g2(g2_affine *q, const uint8_t *b)
{
    fp_load(&q->x.c1, b);
    fp_load(&q->x.c0, b + FP_BYTES);
    fp_load(&q->y.c1, b + 2 * FP_BYTES);
    fp_load(&q->y.c0, b + 3 * FP_BYTES);
    if (!fp_lt(&q->x.c0, &FIELD_P) || !fp_lt(&q->x.c1, &FIELD_P) || !fp_lt(&q->y.c0, &FIELD_P) ||
        !fp_lt(&q->y.c1, &FIELD_P))
        return -1;
    if (fp2_is_zero(&q->x) && fp2_is_zero(&q->y))
        return 0;
    return on_twist(q) && in_g2(q) ? 1 : -1;
}

int zkvm_bn254_pairing(const uint8_t *pairs, size_t num_pairs, bool *verified)
{
    if ((pairs == NULL && num_pairs != 0) || verified == NULL)
        return ZKVM_EFAIL;

    fp xp[MILLER_BATCH], yp[MILLER_BATCH];
    g2_affine q[MILLER_BATCH];
    fp12 f;
    fp12_set_one(&f);
    int batch = 0, any = 0;
    for (size_t i = 0; i < num_pairs; i++)
    {
        const uint8_t *pair = pairs + i * (2 * FP_BYTES + 4 * FP_BYTES);
        int g1 = decode_g1(&xp[batch], &yp[batch], pair);
        int g2 = decode_g2(&q[batch], pair + 2 * FP_BYTES);
        if (g1 < 0 || g2 < 0)
            return ZKVM_EFAIL;
        /* A pair with a point at infinity contributes 1. */
        if (!g1 || !g2)
            continue;
        if (++batch == MILLER_BATCH)
        {
            miller_loop(&f, xp, yp, q, batch);
            batch = 0;
            any = 1;
        }
    }
    if (batch)
    {
        miller_loop(&f, xp, yp, q, batch);
        any = 1;
    }
    if (!any)
    {
        *verified = true;
        return ZKVM_EOK;
    }
    fp12 r;
    final_exp(&r, &f);
    *verified = fp12_is_one(&r);
    return ZKVM_EOK;
}
