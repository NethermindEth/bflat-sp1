/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Host harness for src/secp256k1/ecrecover.c. It emulates the SP1
 * precompiles and hooks the recovery runs on, and aborts the moment one is
 * used outside its contract (equal x on SECP256K1_ADD, a point off the
 * curve, infinity), so a vector that would make the real precompile fail is
 * a test failure here.
 *
 * stdin, one command per line:
 *   recover <hint-mode> <msg hex32> <sig hex64> <recid>
 *       -> "ok <pubkey hex64> <doubles> <adds>" or "fail <doubles> <adds>"
 *   split <k hex32>
 *       -> "<k1 hex32> <neg1> <k2 hex32> <neg2>"
 * hint-mode: honest | garbage | missing | lying. */

#define SECP256K1_HOST_TEST
#include "../../src/secp256k1/ecrecover.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum hint_mode
{
    HINT_HONEST,
    HINT_GARBAGE,
    HINT_MISSING,
    HINT_LYING,
};

static enum hint_mode hint_mode;
static unsigned long doubles, adds;
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t next_random(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void fail(const char *what)
{
    fprintf(stderr, "PRECONDITION VIOLATED: %s\n", what);
    exit(2);
}

/* ---- Generic 256-bit modular multiplication (UINT256_MUL) ------------- */

static void generic_mul_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4])
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
    uint64_t rem[5] = {0};
    for (int bit = 511; bit >= 0; bit--)
    {
        for (int i = 4; i > 0; i--)
            rem[i] = (rem[i] << 1) | (rem[i - 1] >> 63);
        rem[0] = (rem[0] << 1) | ((product[bit >> 6] >> (bit & 63)) & 1);
        if (rem[4] || !less_than(rem, m))
        {
            uint64_t borrow = sub_borrow(rem, rem, m);
            rem[4] -= borrow;
        }
    }
    copy4(r, rem);
}

void sp1_uint256_mulmod(uint64_t x[4], const mulmod_operand *operand)
{
    if (is_zero(operand->m))
        fail("UINT256_MUL with a zero modulus");
    generic_mul_mod(x, x, operand->y, operand->m);
}

/* ---- Field arithmetic for the curve emulation ------------------------- */

/* p = 2^256 - C, so 2^256 = C (mod p). */
static void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    const uint64_t c = 0x1000003d1ULL;
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
    uint64_t folded[4];
    unsigned __int128 t = 0;
    for (int i = 0; i < 4; i++)
    {
        t += (unsigned __int128)product[i + 4] * c + product[i];
        folded[i] = (uint64_t)t;
        t >>= 64;
    }
    uint64_t top = (uint64_t)t;
    while (top)
    {
        t = (unsigned __int128)top * c;
        for (int i = 0; i < 4; i++)
        {
            t += folded[i];
            folded[i] = (uint64_t)t;
            t >>= 64;
        }
        top = (uint64_t)t;
    }
    while (!less_than(folded, FIELD_P))
        sub_borrow(folded, folded, FIELD_P);
    copy4(r, folded);
}

static void fe_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    if (sub_borrow(r, a, b))
        add_carry(r, r, FIELD_P);
}

static void fe_pow(uint64_t r[4], const uint64_t a[4], const uint64_t e[4])
{
    uint64_t acc[4] = {1, 0, 0, 0};
    for (int i = 255; i >= 0; i--)
    {
        fe_mul(acc, acc, acc);
        if ((e[i >> 6] >> (i & 63)) & 1)
            fe_mul(acc, acc, a);
    }
    copy4(r, acc);
}

static void fe_inv(uint64_t r[4], const uint64_t a[4])
{
    static const uint64_t p_minus_2[4] = {
        0xfffffffefffffc2dULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL};
    fe_pow(r, a, p_minus_2);
}

static void check_on_curve(const secp256k1_point *p, const char *what)
{
    static const uint64_t seven[4] = {7, 0, 0, 0};
    uint64_t lhs[4], rhs[4];
    if (!less_than(p->x, FIELD_P) || !less_than(p->y, FIELD_P))
        fail(what);
    fe_mul(lhs, p->y, p->y);
    fe_mul(rhs, p->x, p->x);
    fe_mul(rhs, rhs, p->x);
    add_mod(rhs, rhs, seven, FIELD_P);
    if (!equal(lhs, rhs))
        fail(what);
}

static void finish(secp256k1_point *p, const uint64_t slope[4], const uint64_t x2[4])
{
    uint64_t x[4], y[4], t[4];
    fe_mul(x, slope, slope);
    fe_sub(x, x, p->x);
    fe_sub(x, x, x2);
    fe_sub(t, p->x, x);
    fe_mul(y, slope, t);
    fe_sub(y, y, p->y);
    copy4(p->x, x);
    copy4(p->y, y);
}

void sp1_secp256k1_add(secp256k1_point *p, const secp256k1_point *q)
{
    uint64_t dx[4], dy[4], slope[4];
    adds++;
    if ((uintptr_t)p % 8 || (uintptr_t)q % 8)
        fail("SECP256K1_ADD on an unaligned point");
    if ((const secp256k1_point *)p == q)
        fail("SECP256K1_ADD aliasing its operands");
    check_on_curve(p, "SECP256K1_ADD with p off the curve");
    check_on_curve(q, "SECP256K1_ADD with q off the curve");
    if (equal(p->x, q->x))
        fail("SECP256K1_ADD with equal x coordinates");
    fe_sub(dy, q->y, p->y);
    fe_sub(dx, q->x, p->x);
    fe_inv(dx, dx);
    fe_mul(slope, dy, dx);
    finish(p, slope, q->x);
}

void sp1_secp256k1_double(secp256k1_point *p)
{
    uint64_t num[4], den[4], slope[4];
    doubles++;
    if ((uintptr_t)p % 8)
        fail("SECP256K1_DOUBLE on an unaligned point");
    check_on_curve(p, "SECP256K1_DOUBLE off the curve");
    fe_mul(num, p->x, p->x);
    add_mod(den, num, num, FIELD_P);
    add_mod(num, den, num, FIELD_P);
    add_mod(den, p->y, p->y, FIELD_P);
    fe_inv(den, den);
    fe_mul(slope, num, den);
    finish(p, slope, p->x);
}

/* ---- Hooks ------------------------------------------------------------ */

static void random4(uint64_t r[4])
{
    for (int i = 0; i < 4; i++)
        r[i] = next_random();
}

int secp256k1_hint_inverse(uint64_t r[4], const uint64_t a[4], const uint64_t m[4])
{
    uint64_t exponent[4];
    switch (hint_mode)
    {
    case HINT_MISSING:
        return 0;
    case HINT_GARBAGE:
        random4(r);
        return 1;
    default:
        sub_borrow(exponent, m, (const uint64_t[4]){2, 0, 0, 0});
        {
            mulmod_operand base;
            copy4(base.y, a);
            copy4(base.m, m);
            uint64_t acc[4] = {1, 0, 0, 0};
            for (int i = 255; i >= 0; i--)
            {
                generic_mul_mod(acc, acc, acc, m);
                if ((exponent[i >> 6] >> (i & 63)) & 1)
                    generic_mul_mod(acc, acc, a, m);
            }
            copy4(r, acc);
        }
        if (hint_mode == HINT_LYING)
            r[0] ^= 1;
        return 1;
    }
}

int secp256k1_hint_sqrt(uint64_t r[4], int *is_square, const uint64_t a[4], const uint64_t m[4])
{
    uint64_t check[4], minus_a[4];
    if (!equal(m, FIELD_P))
        fail("sqrt hint for a modulus other than p");
    switch (hint_mode)
    {
    case HINT_MISSING:
        return 0;
    case HINT_GARBAGE:
        random4(r);
        *is_square = (int)(next_random() & 1);
        return 1;
    default:
        fe_pow(r, a, SQRT_EXPONENT);
        fe_mul(check, r, r);
        *is_square = equal(check, a);
        if (!*is_square)
        {
            sub_borrow(minus_a, FIELD_P, a);
            fe_pow(r, minus_a, SQRT_EXPONENT);
        }
        /* A lying host claims the opposite and sends a root of the other one. */
        if (hint_mode == HINT_LYING)
            *is_square = !*is_square;
        return 1;
    }
}

/* ---- Driver ----------------------------------------------------------- */

static int parse_hex(uint8_t *out, size_t len, const char *hex)
{
    if (strlen(hex) != 2 * len)
        return 0;
    for (size_t i = 0; i < len; i++)
    {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static void print_hex(const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", b[i]);
}

static void print_scalar(const uint64_t a[4])
{
    uint8_t b[32];
    store_be(b, a);
    print_hex(b, 32);
}

int main(void)
{
    char line[1024], cmd[16], mode[16], hex_msg[128], hex_sig[256], hex_k[128];
    unsigned recid;
    while (fgets(line, sizeof line, stdin))
    {
        if (sscanf(line, "%15s", cmd) != 1)
            continue;
        if (strcmp(cmd, "recover") == 0)
        {
            uint8_t msg[32], sig[64], out[64];
            if (sscanf(line, "%*s %15s %127s %255s %u", mode, hex_msg, hex_sig, &recid) != 4 ||
                !parse_hex(msg, 32, hex_msg) || !parse_hex(sig, 64, hex_sig))
            {
                fprintf(stderr, "bad line: %s", line);
                return 1;
            }
            hint_mode = strcmp(mode, "garbage") == 0   ? HINT_GARBAGE
                        : strcmp(mode, "missing") == 0 ? HINT_MISSING
                        : strcmp(mode, "lying") == 0   ? HINT_LYING
                                                       : HINT_HONEST;
            doubles = adds = 0;
            if (zkvm_secp256k1_ecrecover(msg, sig, (uint8_t)recid, out) == ZKVM_EOK)
            {
                printf("ok ");
                print_hex(out, 64);
            }
            else
            {
                printf("fail");
            }
            printf(" %lu %lu\n", doubles, adds);
        }
        else if (strcmp(cmd, "split") == 0)
        {
            uint8_t kb[32];
            uint64_t k[4], k1[5], k2[5];
            int neg1, neg2;
            if (sscanf(line, "%*s %127s", hex_k) != 1 || !parse_hex(kb, 32, hex_k))
            {
                fprintf(stderr, "bad line: %s", line);
                return 1;
            }
            load_be(k, kb);
            split_lambda(k1, &neg1, k2, &neg2, k);
            print_scalar(k1);
            printf(" %d ", neg1);
            print_scalar(k2);
            printf(" %d\n", neg2);
        }
        fflush(stdout);
    }
    return 0;
}
