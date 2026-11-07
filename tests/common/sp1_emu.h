/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Host emulation of the SP1 precompiles the accelerators in src/ run on. Each
 * aborts the moment it is used outside its contract, so a vector that would
 * make the real precompile fail is a test failure. Include after the source
 * under test, built with SP1_HOST_TEST. */

#ifndef SP1_EMU_H
#define SP1_EMU_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long emu_mulmods, emu_doubles, emu_adds;

static inline void emu_fail(const char *what)
{
    fprintf(stderr, "PRECONDITION VIOLATED: %s\n", what);
    exit(2);
}

static inline void emu_mul_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4])
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
    emu_mulmods++;
    if ((uintptr_t)x % 8 || (uintptr_t)operand % 8)
        emu_fail("UINT256_MUL on an unaligned operand");
    if (is_zero(operand->m))
        emu_fail("UINT256_MUL with a zero modulus");
    emu_mul_mod(x, x, operand->y, operand->m);
}

/* Affine short-Weierstrass y^2 = x^3 + b over the prime field mod p, for the
 * curve precompiles. */
typedef struct
{
    uint64_t p[4];
    uint64_t b[4];
    const char *name;
} emu_curve;

static inline void emu_pow(uint64_t r[4], const uint64_t a[4], const uint64_t e[4], const uint64_t m[4])
{
    uint64_t acc[4] = {1, 0, 0, 0};
    for (int i = 255; i >= 0; i--)
    {
        emu_mul_mod(acc, acc, acc, m);
        if ((e[i >> 6] >> (i & 63)) & 1)
            emu_mul_mod(acc, acc, a, m);
    }
    copy4(r, acc);
}

static inline void emu_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4])
{
    if (sub_borrow(r, a, b))
        add_carry(r, r, m);
}

static inline void emu_check_on_curve(const emu_curve *c, const sp1_point *q, const char *what)
{
    uint64_t lhs[4], rhs[4];
    if (!less_than(q->x, c->p) || !less_than(q->y, c->p))
        emu_fail(what);
    emu_mul_mod(lhs, q->y, q->y, c->p);
    emu_mul_mod(rhs, q->x, q->x, c->p);
    emu_mul_mod(rhs, rhs, q->x, c->p);
    add_mod(rhs, rhs, c->b, c->p);
    if (!equal(lhs, rhs))
        emu_fail(what);
}

static inline void emu_finish(const emu_curve *c, sp1_point *q, const uint64_t slope[4], const uint64_t x2[4])
{
    uint64_t x[4], y[4], t[4];
    emu_mul_mod(x, slope, slope, c->p);
    emu_sub(x, x, q->x, c->p);
    emu_sub(x, x, x2, c->p);
    emu_sub(t, q->x, x, c->p);
    emu_mul_mod(y, slope, t, c->p);
    emu_sub(y, y, q->y, c->p);
    copy4(q->x, x);
    copy4(q->y, y);
}

static inline void emu_inverse(uint64_t r[4], const uint64_t a[4], const uint64_t p[4])
{
    uint64_t exponent[4];
    sub_borrow(exponent, p, (const uint64_t[4]){2, 0, 0, 0});
    emu_pow(r, a, exponent, p);
}

static inline void emu_add(const emu_curve *c, sp1_point *p, const sp1_point *q)
{
    uint64_t dx[4], dy[4], slope[4];
    emu_adds++;
    if ((uintptr_t)p % 8 || (uintptr_t)q % 8)
        emu_fail("ADD on an unaligned point");
    if ((const sp1_point *)p == q)
        emu_fail("ADD aliasing its operands");
    emu_check_on_curve(c, p, "ADD with p off the curve");
    emu_check_on_curve(c, q, "ADD with q off the curve");
    if (equal(p->x, q->x))
        emu_fail("ADD with equal x coordinates");
    emu_sub(dy, q->y, p->y, c->p);
    emu_sub(dx, q->x, p->x, c->p);
    emu_inverse(dx, dx, c->p);
    emu_mul_mod(slope, dy, dx, c->p);
    emu_finish(c, p, slope, q->x);
}

static inline void emu_double(const emu_curve *c, sp1_point *p)
{
    uint64_t num[4], den[4], slope[4];
    emu_doubles++;
    if ((uintptr_t)p % 8)
        emu_fail("DOUBLE on an unaligned point");
    emu_check_on_curve(c, p, "DOUBLE off the curve");
    if (is_zero(p->y))
        emu_fail("DOUBLE of a point of order 2");
    emu_mul_mod(num, p->x, p->x, c->p);
    add_mod(den, num, num, c->p);
    add_mod(num, den, num, c->p);
    add_mod(den, p->y, p->y, c->p);
    emu_inverse(den, den, c->p);
    emu_mul_mod(slope, num, den, c->p);
    emu_finish(c, p, slope, p->x);
}

/* ---- Driver helpers ---------------------------------------------------- */

/* Parses hex into out, "-" for no bytes. Returns the byte count, or -1. */
static inline long parse_hex(uint8_t *out, size_t capacity, const char *hex)
{
    if (strcmp(hex, "-") == 0)
        return 0;
    size_t len = strlen(hex);
    if (len % 2 || len / 2 > capacity)
        return -1;
    for (size_t i = 0; i < len / 2; i++)
    {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return (long)(len / 2);
}

static inline void print_hex(const uint8_t *b, size_t len)
{
    if (len == 0)
        printf("-");
    for (size_t i = 0; i < len; i++)
        printf("%02x", b[i]);
}

#endif
