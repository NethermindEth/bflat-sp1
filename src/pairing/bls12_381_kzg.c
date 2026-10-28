/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * zkvm_kzg_point_eval for SP1 (EIP-4844, precompile 0x0a), replacing the zkEVM SDK's.
 *
 * The SDK verifies through kzg-rs on the patched bls12_381 crate, which reaches the BLS12-381
 * field precompiles one element at a time and copies every operand in and out (~4.2M
 * instructions per verification). Here the pairing runs on the BLS12_381_FP2 precompiles through
 * tower.h, and the G1 work on the BLS12_381 point precompiles.
 *
 * verify_kzg_proof checks e(C - [y]G1, G2) = e(proof, [s]G2 - [z]G2). Moving the G2 scalar
 * multiplication to G1 gives the equivalent e(C - [y]G1 + [z]proof, G2) e(-proof, [s]G2) = 1, so
 * both G2 points are constants.
 *
 * C and proof arrive compressed (48 bytes, ZCash flags) and must decode to points of G1, the
 * order-r subgroup of a curve with a large cofactor: P is in G1 exactly when
 * phi(P) = -[x^2]P for phi(x, y) = (beta x, y), two sparse 64-bit multiplications. z and y must
 * be below r. Any input that fails a check verifies as false, as in kzg-rs. */

#include <stdbool.h>

#include "../common/u256.h"

#define NL 6
#define FP_BYTES 48
#define SYS_FP_ADD 0x00010120ULL
#define SYS_FP_SUB 0x00010121ULL
#define SYS_FP_MUL 0x00010122ULL
#define SYS_FP2_ADD 0x00010123ULL
#define SYS_FP2_SUB 0x00010124ULL
#define SYS_FP2_MUL 0x00010125ULL
#define TWIST_D 0
#define BN_CURVE 0
#define XI_ONE_PLUS_U 1

#include "fields.h"
#include "bls12_381_constants.h"
#include "tower.h"

#define SYS_G1_ADD 0x0001011eULL
#define SYS_G1_DOUBLE 0x0000011fULL

#define ZKVM_EOK 0
#define ZKVM_EFAIL (-1)

#define WINDOW 5
#define TABLE_ENTRIES (1 << (WINDOW - 2))
#define MAX_DIGITS 257

typedef struct
{
    fp x, y;
} g1_affine;

/* p += q for distinct p, q with distinct x; p = 2p for p other than infinity (no point of
 * BLS12-381's E(Fp) has order 2, the group order being odd). */
static inline void g1_add_raw(g1_affine *p, const g1_affine *q)
{
    sp1_syscall(SYS_G1_ADD, p, q);
}

static inline void g1_double_raw(g1_affine *p)
{
    sp1_syscall(SYS_G1_DOUBLE, p, NULL);
}

/* acc += q, with acc's infinity in *infinity. */
static void g1_add(g1_affine *acc, int *infinity, const g1_affine *q)
{
    if (*infinity)
    {
        *acc = *q;
        *infinity = 0;
    }
    else if (fp_eq(&acc->x, &q->x))
    {
        if (fp_eq(&acc->y, &q->y))
            g1_double_raw(acc);
        else
            *infinity = 1;
    }
    else
    {
        g1_add_raw(acc, q);
    }
}

static void g1_neg(g1_affine *r, const g1_affine *p)
{
    r->x = p->x;
    fp_neg(&r->y, &p->y);
}

/* r = [k]p for a public 64-bit k, by double-and-add; *infinity says whether r is infinity. */
static void g1_mul_u64(g1_affine *r, int *infinity, const g1_affine *p, uint64_t k)
{
    *infinity = 1;
    for (int i = 63; i >= 0; i--)
    {
        if (!*infinity)
            g1_double_raw(r);
        if ((k >> i) & 1)
            g1_add(r, infinity, p);
    }
}

/* phi(P) = -[x^2]P, x^2 = |x|^2. */
static int in_g1(const g1_affine *p)
{
    g1_affine t, u;
    int inf_t, inf_u;
    g1_mul_u64(&t, &inf_t, p, X_ABS);
    if (inf_t)
        return 0;
    g1_mul_u64(&u, &inf_u, &t, X_ABS);
    if (inf_u)
        return 0;
    fp bx, s;
    fp_mul(&bx, &p->x, &BETA);
    fp_add(&s, &u.y, &p->y);
    return fp_eq(&bx, &u.x) && fp_is_zero(&s);
}

/* 1 for a point of G1, 0 for the point at infinity, -1 for anything else (ZCash encoding: bit 7
 * compressed, bit 6 infinity, bit 5 the larger y). */
static int decompress(g1_affine *p, const uint8_t *in)
{
    uint8_t b0 = in[0];
    if (!(b0 & 0x80))
        return -1;
    if (b0 & 0x40)
    {
        uint8_t rest = b0 & 0x3f;
        for (int i = 1; i < FP_BYTES; i++)
            rest |= in[i];
        return rest ? -1 : 0;
    }
    uint8_t buf[FP_BYTES];
    for (int i = 0; i < FP_BYTES; i++)
        buf[i] = in[i];
    buf[0] &= 0x1f;
    fp_load(&p->x, buf);
    if (!fp_lt(&p->x, &FIELD_P))
        return -1;
    fp rhs, check;
    fp_mul(&rhs, &p->x, &p->x);
    fp_mul(&rhs, &rhs, &p->x);
    fp_add(&rhs, &rhs, &CURVE_B);
    fp_pow(&p->y, &rhs, &SQRT_EXPONENT);
    fp_mul(&check, &p->y, &p->y);
    if (!fp_eq(&check, &rhs))
        return -1;
    if (fp_lt(&HALF_P, &p->y) != !!(b0 & 0x20))
        fp_neg(&p->y, &p->y);
    return in_g1(p) ? 1 : -1;
}

/* A 32-byte big-endian scalar below r, as five little-endian limbs for wnaf(). */
static int load_scalar(uint64_t s[5], const uint8_t *b)
{
    load_be(s, b);
    s[4] = 0;
    return less_than(s, ORDER_R);
}

static void odd_multiples(g1_affine table[TABLE_ENTRIES], const g1_affine *p)
{
    /* jP = +-2P would need (j -+ 2)P = 0, and P has prime order r. */
    g1_affine twice = *p;
    g1_double_raw(&twice);
    table[0] = *p;
    for (int i = 1; i < TABLE_ENTRIES; i++)
    {
        table[i] = table[i - 1];
        g1_add_raw(&table[i], &twice);
    }
}

static void add_digit(g1_affine *acc, int *infinity, const g1_affine *table, int digit)
{
    g1_affine q;
    if (digit < 0)
        g1_neg(&q, &table[(-digit) >> 1]);
    else
        q = table[digit >> 1];
    g1_add(acc, infinity, &q);
}

int zkvm_kzg_point_eval(const uint8_t *commitment, const uint8_t *z, const uint8_t *y, const uint8_t *proof,
                        bool *verified)
{
    if (commitment == NULL || z == NULL || y == NULL || proof == NULL || verified == NULL)
        return ZKVM_EFAIL;
    *verified = false;

    uint64_t zs[5], ys[5];
    g1_affine c, pi;
    if (!load_scalar(zs, z) || !load_scalar(ys, y))
        return ZKVM_EOK;
    int has_c = decompress(&c, commitment);
    int has_pi = decompress(&pi, proof);
    if (has_c < 0 || has_pi < 0)
        return ZKVM_EOK;

    /* A = C - [y]G1 + [z]proof, one shared doubling chain over both scalars. */
    g1_affine g_table[TABLE_ENTRIES], pi_table[TABLE_ENTRIES];
    g1_affine g1 = {G1_X, G1_Y};
    odd_multiples(g_table, &g1);
    if (has_pi)
        odd_multiples(pi_table, &pi);
    int length = bit_length(ys);
    int bits = has_pi ? bit_length(zs) : 0;
    if (bits > length)
        length = bits;
    length++;
    int8_t digits[2 * MAX_DIGITS];
    for (int i = 0; i < 2 * length; i++)
        digits[i] = 0;
    wnaf(digits, 2, ys, WINDOW, length);
    if (has_pi)
        wnaf(digits + 1, 2, zs, WINDOW, length);

    g1_affine a = g1;
    int a_inf = 1;
    for (int i = length - 1; i >= 0; i--)
    {
        if (!a_inf)
            g1_double_raw(&a);
        if (digits[2 * i])
            add_digit(&a, &a_inf, g_table, -digits[2 * i]);
        if (digits[2 * i + 1])
            add_digit(&a, &a_inf, pi_table, digits[2 * i + 1]);
    }
    if (has_c)
        g1_add(&a, &a_inf, &c);

    fp xp[2], yp[2];
    g2_affine q[2];
    int n = 0;
    if (!a_inf)
    {
        xp[n] = a.x;
        yp[n] = a.y;
        q[n].x = G2_X;
        q[n].y = G2_Y;
        n++;
    }
    if (has_pi)
    {
        xp[n] = pi.x;
        fp_neg(&yp[n], &pi.y);
        q[n].x = S_G2_X;
        q[n].y = S_G2_Y;
        n++;
    }
    if (n == 0)
    {
        *verified = true;
        return ZKVM_EOK;
    }
    fp12 f, r;
    fp12_set_one(&f);
    miller_loop(&f, xp, yp, q, n);
    final_exp(&r, &f);
    *verified = fp12_is_one(&r);
    return ZKVM_EOK;
}
