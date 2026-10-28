/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * zkvm_bn254_g1_add and zkvm_bn254_g1_mul for SP1 (EIP-196, precompiles 0x06
 * and 0x07), replacing the zkEVM SDK's.
 *
 * The SDK goes through the patched substrate-bn crate, which reaches only the
 * BN254 field precompiles: every point operation is a Jacobian formula of
 * ~10 BN254_FP* calls plus the glue around them, and the scalar multiplication
 * is plain double-and-add over 254 bits. Here both run on the BN254_ADD and
 * BN254_DOUBLE point precompiles, and the multiplication uses GLV and wNAF:
 *
 *   - GLV: k = k1 + k2*lambda (mod r) with |k1|, |k2| < 2^127, and
 *     lambda*(x, y) = (beta*x, y), so the doubling chain is ~125 steps;
 *   - wNAF digits, window 5, against odd multiples of P and lambda*P built per
 *     call (~49 additions, 7 of them building the table).
 *
 * The point precompiles are incomplete - BN254_ADD requires distinct x
 * coordinates and neither accepts the point at infinity - while both inputs
 * are caller-chosen, so every accumulator addition checks for equal x and for
 * infinity before it reaches the precompile. G1 has prime order r (cofactor 1),
 * which keeps the table additions clear of equal x. */

#include "../common/u256.h"

#ifdef SP1_HOST_TEST

void sp1_bn254_add(sp1_point *p, const sp1_point *q);
void sp1_bn254_double(sp1_point *p);

#else

#define SP1_BN254_ADD 0x0001010eULL
#define SP1_BN254_DOUBLE 0x0000010fULL

/* p += q. p and q must be distinct points with distinct x coordinates. */
static inline void sp1_bn254_add(sp1_point *p, const sp1_point *q)
{
    sp1_ecall(SP1_BN254_ADD, p, q);
}

/* p = 2p for a point other than infinity. */
static inline void sp1_bn254_double(sp1_point *p)
{
    sp1_ecall(SP1_BN254_DOUBLE, p, 0);
}

#endif

#define ZKVM_EOK 0
#define ZKVM_EFAIL (-1)

#define WINDOW 5
#define TABLE_ENTRIES (1 << (WINDOW - 2))
/* Scalars are below r < 2^254; one more position absorbs the final wNAF carry. */
#define MAX_DIGITS 256

static const uint64_t FIELD_P[4] = {
    0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL};
static const uint64_t HALF_R[4] = {
    0xa1f0fac9f8000000ULL, 0x9419f4243cdcb848ULL, 0xdc2822db40c0ac2eULL, 0x183227397098d014ULL};
static const uint64_t ORDER_R[4] = {
    0x43e1f593f0000001ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL};

static const mulmod_operand ONE_MOD_R = {
    {1, 0, 0, 0},
    {0x43e1f593f0000001ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL}};

/* GLV decomposition. The lattice basis (a1, b1), (a2, b2) of {(x, y) : x + y*lambda = 0 (mod r)} has
 * b1 = -0x6f4d8248eeb859fc8211bbeb7d4f1128 and b2 = 0x89d3256894d213e3; c1 = round(k*b2/r) and
 * c2 = round(-k*b1/r) come from GLV_G1 = round(2^320*b2/r) and GLV_G2 = round(-2^320*b1/r). The
 * shift is 320, not libsecp256k1's 384, because r has 254 bits and 2^384*|b1|/r would not fit in
 * 256. */
static const uint64_t GLV_G1[4] = {0x6eb9c714773a6ef3ULL, 0xd91d232ec7e0b3d7ULL, 0x0000000000000002ULL, 0};
static const uint64_t GLV_G2[4] = {
    0xa5e38cfb5eaa26daULL, 0x7a7bd9d4391eb18dULL, 0x4ccef014a773d2cfULL, 0x0000000000000002ULL};

static const mulmod_operand MINUS_B1_MOD_R = {
    {0x8211bbeb7d4f1128ULL, 0x6f4d8248eeb859fcULL, 0, 0},
    {0x43e1f593f0000001ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL}};
static const mulmod_operand MINUS_B2_MOD_R = {
    {0xba0ed02b5b2dec1eULL, 0x2833e84879b97090ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL},
    {0x43e1f593f0000001ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL}};
static const mulmod_operand MINUS_LAMBDA_MOD_R = {
    {0xb8ca0b2d36636f24ULL, 0xcc37a73fec2bc5e9ULL, 0x048b6e193fd84104ULL, 0x30644e72e131a029ULL},
    {0x43e1f593f0000001ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL}};
/* A cube root of unity mod p: (x, y) -> (BETA*x, y) multiplies a G1 point by lambda. */
static const mulmod_operand BETA_MOD_P = {
    {0x5763473177fffffeULL, 0xd4f263f1acdb5c4fULL, 0x59e26bcea0d48bacULL, 0},
    {0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL}};

/* Decodes x || y, big-endian: 1 for a point on the curve, 0 for (0, 0), the
 * point at infinity, and -1 for anything else. */
static int decode(sp1_point *p, const uint8_t *b)
{
    static const uint64_t three[4] = {3, 0, 0, 0};
    uint64_t lhs[4], rhs[4];
    load_be(p->x, b);
    load_be(p->y, b + 32);
    if (!less_than(p->x, FIELD_P) || !less_than(p->y, FIELD_P))
        return -1;
    if (is_zero(p->x) && is_zero(p->y))
        return 0;
    mul_mod(lhs, p->y, p->y, FIELD_P);
    mul_mod(rhs, p->x, p->x, FIELD_P);
    mul_mod(rhs, rhs, p->x, FIELD_P);
    add_mod(rhs, rhs, three, FIELD_P);
    return equal(lhs, rhs) ? 1 : -1;
}

static void encode(uint8_t *b, const sp1_point *p, int infinity)
{
    if (infinity)
    {
        for (int i = 0; i < 64; i++)
            b[i] = 0;
        return;
    }
    store_be(b, p->x);
    store_be(b + 32, p->y);
}

/* acc += q, with acc's infinity tracked in *infinity. y is never 0 on this
 * curve (no point of order 2), so equal points always double. */
static void add_point(sp1_point *acc, int *infinity, const sp1_point *q)
{
    if (*infinity)
    {
        *acc = *q;
        *infinity = 0;
    }
    else if (acc->x[0] == q->x[0] && equal(acc->x, q->x))
    {
        if (equal(acc->y, q->y))
            sp1_bn254_double(acc);
        else
            *infinity = 1;
    }
    else
    {
        sp1_bn254_add(acc, q);
    }
}

/* acc += table entry |digit|, negated when the signs disagree. */
static void add_term(sp1_point *acc, int *infinity, const sp1_point *table, int digit, int negate)
{
    sp1_point negated;
    if (digit < 0)
    {
        digit = -digit;
        negate = !negate;
    }
    const sp1_point *q = &table[digit >> 1];
    if (negate)
    {
        copy4(negated.x, q->x);
        sub_borrow(negated.y, FIELD_P, q->y);
        q = &negated;
    }
    add_point(acc, infinity, q);
}

/* r = round(a * b / 2^320), the GLV rounding step; the result fits in 192 bits. */
static void mul_shift_320(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
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
    uint64_t round = product[4] >> 63;
    r[0] = product[5] + round;
    uint64_t carry = r[0] < round;
    r[1] = product[6] + carry;
    carry = r[1] < carry;
    r[2] = product[7] + carry;
    r[3] = 0;
}

/* Splits k < r into k1 + k2*lambda (mod r), returning each part as a
 * magnitude and a sign. The parts stay below 2^127; nothing below relies on
 * the bound beyond the cost. */
static void split_lambda(uint64_t k1[5], int *neg1, uint64_t k2[5], int *neg2, const uint64_t k[4])
{
    uint64_t c1[4], c2[4];
    mul_shift_320(c1, k, GLV_G1);
    mul_shift_320(c2, k, GLV_G2);
    sp1_uint256_mulmod(c1, &MINUS_B1_MOD_R);
    sp1_uint256_mulmod(c2, &MINUS_B2_MOD_R);
    add_mod(k2, c1, c2, ORDER_R);
    copy4(k1, k2);
    sp1_uint256_mulmod(k1, &MINUS_LAMBDA_MOD_R);
    add_mod(k1, k1, k, ORDER_R);

    *neg1 = less_than(HALF_R, k1);
    if (*neg1)
        sub_borrow(k1, ORDER_R, k1);
    *neg2 = less_than(HALF_R, k2);
    if (*neg2)
        sub_borrow(k2, ORDER_R, k2);
    k1[4] = 0;
    k2[4] = 0;
}

int zkvm_bn254_g1_add(const uint8_t *p1, const uint8_t *p2, uint8_t *result)
{
    if (p1 == NULL || p2 == NULL || result == NULL)
        return ZKVM_EFAIL;
    sp1_point a, b;
    int on_a = decode(&a, p1);
    int on_b = decode(&b, p2);
    if (on_a < 0 || on_b < 0)
        return ZKVM_EFAIL;
    int infinity = !on_a;
    if (on_b)
        add_point(&a, &infinity, &b);
    encode(result, &a, infinity);
    return ZKVM_EOK;
}

int zkvm_bn254_g1_mul(const uint8_t *point, const uint8_t *scalar, uint8_t *result)
{
    if (point == NULL || scalar == NULL || result == NULL)
        return ZKVM_EFAIL;
    sp1_point p;
    int on_curve = decode(&p, point);
    if (on_curve < 0)
        return ZKVM_EFAIL;
    /* Every point has order r, so the scalar only matters mod r. */
    uint64_t k[4];
    load_be(k, scalar);
    sp1_uint256_mulmod(k, &ONE_MOD_R);
    if (!on_curve || is_zero(k))
    {
        encode(result, &p, 1);
        return ZKVM_EOK;
    }

    uint64_t scalars[2][5];
    int negative[2];
    split_lambda(scalars[0], &negative[0], scalars[1], &negative[1], k);

    /* Odd multiples P, 3P, ..., 15P and their lambda images. No addition here
     * can meet equal x: jP = +-2P would need (j -+ 2)P = 0. */
    sp1_point table[TABLE_ENTRIES], lambda_table[TABLE_ENTRIES];
    sp1_point twice = p;
    sp1_bn254_double(&twice);
    table[0] = p;
    for (int i = 1; i < TABLE_ENTRIES; i++)
    {
        table[i] = table[i - 1];
        sp1_bn254_add(&table[i], &twice);
    }
    for (int i = 0; i < TABLE_ENTRIES; i++)
    {
        lambda_table[i] = table[i];
        sp1_uint256_mulmod(lambda_table[i].x, &BETA_MOD_P);
    }

    int length = bit_length(scalars[0]);
    int bits = bit_length(scalars[1]);
    if (bits > length)
        length = bits;
    length++;

    /* Digit j of position i is byte j of digits[i], so a position where both
     * digits are zero costs one load. */
    uint16_t digits[MAX_DIGITS];
    for (int i = 0; i < length; i++)
        digits[i] = 0;
    wnaf((int8_t *)digits + 0, 2, scalars[0], WINDOW, length);
    wnaf((int8_t *)digits + 1, 2, scalars[1], WINDOW, length);

    sp1_point acc = p;
    int infinity = 1;
    for (int i = length - 1; i >= 0; i--)
    {
        if (!infinity)
            sp1_bn254_double(&acc);
        uint16_t d = digits[i];
        if (d == 0)
            continue;
        if ((int8_t)d)
            add_term(&acc, &infinity, table, (int8_t)d, negative[0]);
        if ((int8_t)(d >> 8))
            add_term(&acc, &infinity, lambda_table, (int8_t)(d >> 8), negative[1]);
    }

    encode(result, &acc, infinity);
    return ZKVM_EOK;
}
