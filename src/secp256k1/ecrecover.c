/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * zkvm_secp256k1_ecrecover for SP1, replacing the zkEVM SDK's.
 *
 * The SDK recovers through the patched k256 crate, whose linear combination
 * u1*G + u2*R walks the two scalars bit by bit and doubles BOTH running
 * points every step: 512 SECP256K1_DOUBLE and ~256 SECP256K1_ADD calls per
 * recovery. This computes the same point with one shared doubling chain over
 * four half-length scalars:
 *
 *   - GLV: u = a + b*lambda (mod n) with |a|, |b| < 2^128, and
 *     lambda*(x, y) = (beta*x, y), so u1*G + u2*R becomes a four-term sum
 *     whose doubling chain is ~129 steps instead of 256;
 *   - wNAF digits, window 8 against constant tables of odd multiples of G
 *     and lambda*G, window 5 against odd multiples of R and lambda*R built
 *     per call (~80 additions instead of ~256).
 *
 * The SP1 point precompiles are incomplete - SECP256K1_ADD requires distinct
 * x coordinates and neither accepts the point at infinity - while every
 * input here is attacker-chosen (the 0x01 precompile takes any hash, r and
 * s), so each accumulator addition checks for equal x and for infinity
 * before it reaches the precompile.
 *
 * Modular inverses and square roots come from SP1's FD_FP_INV/FD_FP_SQRT
 * hooks like the k256 crate's, and are checked with one multiplication. A
 * hint that fails its check is not trusted and the value is recomputed by
 * exponentiation, so the result never depends on the host. */

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint64_t x[4];
    uint64_t y[4];
} secp256k1_point;

/* The UINT256_MUL precompile's second operand: a multiplier and a modulus,
 * contiguous. */
typedef struct
{
    uint64_t y[4];
    uint64_t m[4];
} mulmod_operand;

#include "secp256k1_ops.h"
#include "secp256k1_tables.h"

#define ZKVM_EOK 0
#define ZKVM_EFAIL (-1)

#define WINDOW_R 5
#define R_ENTRIES (1 << (WINDOW_R - 2))
/* Scalars are at most 256 bits; one more position absorbs the final wNAF
 * carry. */
#define MAX_DIGITS 257

static const uint64_t FIELD_P[4] = {
    0xfffffffefffffc2fULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL};
static const uint64_t ORDER_N[4] = {
    0xbfd25e8cd0364141ULL, 0xbaaedce6af48a03bULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL};
static const uint64_t HALF_N[4] = {
    0xdfe92f46681b20a0ULL, 0x5d576e7357a4501dULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL};

/* (p + 1) / 4 and n - 2: the exponents of the hint-free fallbacks. */
static const uint64_t SQRT_EXPONENT[4] = {
    0xffffffffbfffff0cULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x3fffffffffffffffULL};
static const uint64_t INVERSE_EXPONENT[4] = {
    0xbfd25e8cd036413fULL, 0xbaaedce6af48a03bULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL};

/* GLV decomposition constants (as in libsecp256k1's secp256k1_scalar_split_lambda). */
static const uint64_t GLV_G1[4] = {
    0xe893209a45dbb031ULL, 0x3daa8a1471e8ca7fULL, 0xe86c90e49284eb15ULL, 0x3086d221a7d46bcdULL};
static const uint64_t GLV_G2[4] = {
    0x1571b4ae8ac47f71ULL, 0x221208ac9df506c6ULL, 0x6f547fa90abfe4c4ULL, 0xe4437ed6010e8828ULL};

static const mulmod_operand MINUS_B1_MOD_N = {
    {0x6f547fa90abfe4c3ULL, 0xe4437ed6010e8828ULL, 0, 0},
    {0xbfd25e8cd0364141ULL, 0xbaaedce6af48a03bULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL}};
static const mulmod_operand MINUS_B2_MOD_N = {
    {0xd765cda83db1562cULL, 0x8a280ac50774346dULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL},
    {0xbfd25e8cd0364141ULL, 0xbaaedce6af48a03bULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL}};
static const mulmod_operand MINUS_LAMBDA_MOD_N = {
    {0xe0cfc810b51283cfULL, 0xa880b9fc8ec739c2ULL, 0x5ad9e3fd77ed9ba4ULL, 0xac9c52b33fa3cf1fULL},
    {0xbfd25e8cd0364141ULL, 0xbaaedce6af48a03bULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL}};
static const mulmod_operand BETA_MOD_P = {
    {0xc1396c28719501eeULL, 0x9cf0497512f58995ULL, 0x6e64479eac3434e9ULL, 0x7ae96a2b657c0710ULL},
    {0xfffffffefffffc2fULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL}};

static inline void copy4(uint64_t r[4], const uint64_t a[4])
{
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
}

static inline int is_zero(const uint64_t a[4])
{
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

static inline int equal(const uint64_t a[4], const uint64_t b[4])
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
}

static int less_than(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; i--)
    {
        if (a[i] != b[i])
            return a[i] < b[i];
    }
    return 0;
}

/* r = a + b, returning the carry out. */
static uint64_t add_carry(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++)
    {
        uint64_t s = a[i] + carry;
        carry = s < carry;
        r[i] = s + b[i];
        carry += r[i] < s;
    }
    return carry;
}

/* r = a - b, returning the borrow out. */
static uint64_t sub_borrow(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++)
    {
        uint64_t d = a[i] - b[i];
        uint64_t next = a[i] < b[i];
        r[i] = d - borrow;
        borrow = next | (d < borrow);
    }
    return borrow;
}

/* r = a + b mod m, for a, b < m. */
static void add_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4])
{
    if (add_carry(r, a, b) || !less_than(r, m))
        sub_borrow(r, r, m);
}

static void load_be(uint64_t r[4], const uint8_t *b)
{
    for (int i = 0; i < 4; i++)
    {
        const uint8_t *w = b + 8 * (3 - i);
        r[i] = ((uint64_t)w[0] << 56) | ((uint64_t)w[1] << 48) | ((uint64_t)w[2] << 40) |
               ((uint64_t)w[3] << 32) | ((uint64_t)w[4] << 24) | ((uint64_t)w[5] << 16) |
               ((uint64_t)w[6] << 8) | (uint64_t)w[7];
    }
}

static void store_be(uint8_t *b, const uint64_t a[4])
{
    for (int i = 0; i < 4; i++)
    {
        uint8_t *w = b + 8 * (3 - i);
        for (int j = 0; j < 8; j++)
            w[j] = (uint8_t)(a[i] >> (56 - 8 * j));
    }
}

/* r = a * b mod m, through the UINT256_MUL precompile. */
static void mul_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4])
{
    mulmod_operand operand;
    copy4(operand.y, b);
    copy4(operand.m, m);
    copy4(r, a);
    sp1_uint256_mulmod(r, &operand);
}

/* r = a^e mod m by square-and-multiply; only reached when a hint fails its check. */
static void pow_mod(uint64_t r[4], const uint64_t a[4], const uint64_t e[4], const uint64_t m[4])
{
    mulmod_operand base;
    copy4(base.y, a);
    copy4(base.m, m);
    mulmod_operand square;
    copy4(square.m, m);
    uint64_t acc[4] = {1, 0, 0, 0};
    for (int i = 255; i >= 0; i--)
    {
        copy4(square.y, acc);
        sp1_uint256_mulmod(acc, &square);
        if ((e[i >> 6] >> (i & 63)) & 1)
            sp1_uint256_mulmod(acc, &base);
    }
    copy4(r, acc);
}

/* r = a^-1 mod n for 0 < a < n. */
static void invert_mod_n(uint64_t r[4], const uint64_t a[4])
{
    uint64_t check[4];
    if (secp256k1_hint_inverse(r, a, ORDER_N) && less_than(r, ORDER_N))
    {
        mul_mod(check, r, a, ORDER_N);
        if (check[0] == 1 && (check[1] | check[2] | check[3]) == 0)
            return;
    }
    pow_mod(r, a, INVERSE_EXPONENT, ORDER_N);
}

/* Sets y to a square root of a (mod p), returning 0 when a is not a square.
 * p = 3 (mod 4) makes -1 a non-residue, so a root of -a proves a is not a
 * square. */
static int sqrt_mod_p(uint64_t y[4], const uint64_t a[4])
{
    uint64_t check[4], target[4];
    int is_square;
    if (secp256k1_hint_sqrt(y, &is_square, a, FIELD_P) && less_than(y, FIELD_P))
    {
        if (is_square)
            copy4(target, a);
        else
            sub_borrow(target, FIELD_P, a);
        mul_mod(check, y, y, FIELD_P);
        if (equal(check, target))
            return is_square;
    }
    pow_mod(y, a, SQRT_EXPONENT, FIELD_P);
    mul_mod(check, y, y, FIELD_P);
    return equal(check, a);
}

/* Completes R from its x coordinate (< p) and the parity of y. Fails when x
 * is not on the curve. */
static int decompress(secp256k1_point *r, int odd)
{
    static const uint64_t seven[4] = {7, 0, 0, 0};
    uint64_t a[4];
    mul_mod(a, r->x, r->x, FIELD_P);
    mul_mod(a, a, r->x, FIELD_P);
    add_mod(a, a, seven, FIELD_P);
    /* x^3 + 7 is never 0: a point with y = 0 would have order 2, and the
     * group order is an odd prime. */
    if (!sqrt_mod_p(r->y, a))
        return 0;
    if ((int)(r->y[0] & 1) != odd)
        sub_borrow(r->y, FIELD_P, r->y);
    return 1;
}

/* r = round(a * b / 2^384), the GLV rounding step. */
static void mul_shift_384(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t product[8] = {0};
    for (int i = 0; i < 4; i++)
    {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++)
        {
            unsigned __int128 t = (unsigned __int128)a[i] * b[j] + product[i + j] + carry;
            product[i + j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        product[i + 4] = carry;
    }
    uint64_t round = product[5] >> 63;
    r[0] = product[6] + round;
    r[1] = product[7] + (r[0] < round);
    r[2] = r[1] < (r[0] < round);
    r[3] = 0;
}

/* Splits k into k1 + k2*lambda (mod n), returning each part as a magnitude
 * and a sign. The parts are below 2^129 for every k (libsecp256k1 proves
 * 2^128); nothing below relies on the bound beyond the cost. */
static void split_lambda(uint64_t k1[5], int *neg1, uint64_t k2[5], int *neg2, const uint64_t k[4])
{
    uint64_t c1[4], c2[4];
    mul_shift_384(c1, k, GLV_G1);
    mul_shift_384(c2, k, GLV_G2);
    sp1_uint256_mulmod(c1, &MINUS_B1_MOD_N);
    sp1_uint256_mulmod(c2, &MINUS_B2_MOD_N);
    add_mod(k2, c1, c2, ORDER_N);
    copy4(k1, k2);
    sp1_uint256_mulmod(k1, &MINUS_LAMBDA_MOD_N);
    add_mod(k1, k1, k, ORDER_N);

    *neg1 = less_than(HALF_N, k1);
    if (*neg1)
        sub_borrow(k1, ORDER_N, k1);
    *neg2 = less_than(HALF_N, k2);
    if (*neg2)
        sub_borrow(k2, ORDER_N, k2);
    k1[4] = 0;
    k2[4] = 0;
}

/* RV64IM has no count-leading-zeros instruction, and the freestanding
 * archive has no libgcc to supply __clzdi2. */
static int bit_length(const uint64_t a[4])
{
    for (int i = 3; i >= 0; i--)
    {
        uint64_t v = a[i];
        if (v == 0)
            continue;
        int bits = 64 * i + 1;
        for (int shift = 32; shift > 0; shift >>= 1)
        {
            if (v >> shift)
            {
                v >>= shift;
                bits += shift;
            }
        }
        return bits;
    }
    return 0;
}

/* Writes the width-w NAF of s into digits[4 * i] for i < len: odd digits in
 * (-2^(w-1), 2^(w-1)), at least w - 1 zeros between two of them. len must
 * exceed the bit length of s for the last carry to land inside it. */
static void wnaf(int8_t *digits, const uint64_t s[5], int w, int len)
{
    int bit = 0;
    uint32_t carry = 0;
    while (bit < len)
    {
        if (((s[bit >> 6] >> (bit & 63)) & 1) == carry)
        {
            bit++;
            continue;
        }
        int now = len - bit < w ? len - bit : w;
        int limb = bit >> 6;
        int offset = bit & 63;
        uint64_t bits = s[limb] >> offset;
        if (offset + now > 64)
            bits |= s[limb + 1] << (64 - offset);
        int32_t word = (int32_t)(bits & ((1u << now) - 1)) + (int32_t)carry;
        carry = ((uint32_t)word >> (w - 1)) & 1;
        word -= (int32_t)(carry << w);
        digits[4 * bit] = (int8_t)word;
        bit += now;
    }
}

/* acc += table entry |digit| (negated when the signs disagree), with acc's
 * infinity tracked in *infinity. */
static void add_term(secp256k1_point *acc, int *infinity, const secp256k1_point *table, int digit, int negate)
{
    const secp256k1_point *q;
    secp256k1_point negated;
    if (digit < 0)
    {
        digit = -digit;
        negate = !negate;
    }
    q = &table[digit >> 1];
    if (negate)
    {
        copy4(negated.x, q->x);
        sub_borrow(negated.y, FIELD_P, q->y);
        q = &negated;
    }

    if (*infinity)
    {
        *acc = *q;
        *infinity = 0;
    }
    else if (acc->x[0] == q->x[0] && equal(acc->x, q->x))
    {
        if (equal(acc->y, q->y))
            sp1_secp256k1_double(acc);
        else
            *infinity = 1;
    }
    else
    {
        sp1_secp256k1_add(acc, q);
    }
}

int zkvm_secp256k1_ecrecover(const uint8_t *msg, const uint8_t *sig, uint8_t recid, uint8_t *output)
{
    if (msg == NULL || sig == NULL || output == NULL || recid > 3)
        return ZKVM_EFAIL;

    uint64_t r[4], s[4], z[4];
    load_be(r, sig);
    load_be(s, sig + 32);
    load_be(z, msg);
    if (is_zero(r) || !less_than(r, ORDER_N) || is_zero(s) || !less_than(s, ORDER_N))
        return ZKVM_EFAIL;

    /* Recovery ids 2 and 3 name the point whose x coordinate is r + n. */
    secp256k1_point point_r;
    if (recid & 2)
    {
        if (add_carry(point_r.x, r, ORDER_N) || !less_than(point_r.x, FIELD_P))
            return ZKVM_EFAIL;
    }
    else
    {
        copy4(point_r.x, r);
    }
    if (!decompress(&point_r, recid & 1))
        return ZKVM_EFAIL;

    /* Q = u1*G + u2*R with u1 = -z/r and u2 = s/r. */
    uint64_t r_inverse[4], u1[4], u2[4];
    invert_mod_n(r_inverse, r);
    if (!less_than(z, ORDER_N))
        sub_borrow(z, z, ORDER_N);
    if (is_zero(z))
        u1[0] = u1[1] = u1[2] = u1[3] = 0;
    else
    {
        sub_borrow(u1, ORDER_N, z);
        mul_mod(u1, u1, r_inverse, ORDER_N);
    }
    mul_mod(u2, s, r_inverse, ORDER_N);

    uint64_t scalars[4][5];
    int negative[4];
    split_lambda(scalars[0], &negative[0], scalars[1], &negative[1], u1);
    split_lambda(scalars[2], &negative[2], scalars[3], &negative[3], u2);

    /* Odd multiples R, 3R, ..., 15R and their lambda images. No addition
     * here can meet equal x: jR = +-2R would need (j -+ 2)R = 0, and R has
     * prime order n. */
    secp256k1_point r_table[R_ENTRIES], lambda_r_table[R_ENTRIES];
    secp256k1_point twice_r = point_r;
    sp1_secp256k1_double(&twice_r);
    r_table[0] = point_r;
    for (int i = 1; i < R_ENTRIES; i++)
    {
        r_table[i] = r_table[i - 1];
        sp1_secp256k1_add(&r_table[i], &twice_r);
    }
    for (int i = 0; i < R_ENTRIES; i++)
    {
        lambda_r_table[i] = r_table[i];
        sp1_uint256_mulmod(lambda_r_table[i].x, &BETA_MOD_P);
    }

    int length = 0;
    for (int i = 0; i < 4; i++)
    {
        int bits = bit_length(scalars[i]);
        if (bits > length)
            length = bits;
    }
    length++;

    /* Digit j of position i is byte j of digits[i], so a position where all
     * four digits are zero costs one load. */
    uint32_t digits[MAX_DIGITS];
    for (int i = 0; i < length; i++)
        digits[i] = 0;
    wnaf((int8_t *)digits + 0, scalars[0], SECP256K1_WINDOW_G, length);
    wnaf((int8_t *)digits + 1, scalars[1], SECP256K1_WINDOW_G, length);
    wnaf((int8_t *)digits + 2, scalars[2], WINDOW_R, length);
    wnaf((int8_t *)digits + 3, scalars[3], WINDOW_R, length);

    secp256k1_point acc;
    int infinity = 1;
    for (int i = length - 1; i >= 0; i--)
    {
        if (!infinity)
            sp1_secp256k1_double(&acc);
        uint32_t d = digits[i];
        if (d == 0)
            continue;
        if ((int8_t)d)
            add_term(&acc, &infinity, SECP256K1_G_TABLE, (int8_t)d, negative[0]);
        if ((int8_t)(d >> 8))
            add_term(&acc, &infinity, SECP256K1_LAMBDA_G_TABLE, (int8_t)(d >> 8), negative[1]);
        if ((int8_t)(d >> 16))
            add_term(&acc, &infinity, r_table, (int8_t)(d >> 16), negative[2]);
        if ((int8_t)(d >> 24))
            add_term(&acc, &infinity, lambda_r_table, (int8_t)(d >> 24), negative[3]);
    }

    if (infinity)
        return ZKVM_EFAIL;

    store_be(output, acc.x);
    store_be(output + 32, acc.y);
    return ZKVM_EOK;
}
