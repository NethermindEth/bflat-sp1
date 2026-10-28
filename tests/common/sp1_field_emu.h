/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Host emulation of the SP1 BN254 and BLS12-381 field and G1 point precompiles behind
 * sp1_syscall(). Stricter than the real ones: operands must be canonical and must not alias, and
 * the incomplete point additions abort on equal x or a point off the curve, so code that only
 * works on the real executor by accident fails here. Include after the source under test. */

#ifndef SP1_FIELD_EMU_H
#define SP1_FIELD_EMU_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EMU_MAX 6

static unsigned long emu_calls[0x200];

static void emu_die(const char *what, uint64_t id)
{
    fprintf(stderr, "PRECONDITION VIOLATED: %s (syscall 0x%llx)\n", what, (unsigned long long)id);
    exit(2);
}

typedef struct
{
    int n;
    uint64_t p[EMU_MAX];
    uint64_t b;
} emu_field;

static const emu_field EMU_BN254 = {
    4, {0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL}, 3};
static const emu_field EMU_BLS = {
    6,
    {0xb9feffffffffaaabULL, 0x1eabfffeb153ffffULL, 0x6730d2a0f6b0f624ULL, 0x64774b84f38512bfULL,
     0x4b1ba7b6434bacd7ULL, 0x1a0111ea397fe69aULL},
    4};

static int emu_lt(const uint64_t *a, const uint64_t *b, int n)
{
    for (int i = n - 1; i >= 0; i--)
        if (a[i] != b[i])
            return a[i] < b[i];
    return 0;
}

static uint64_t emu_sub_n(uint64_t *r, const uint64_t *a, const uint64_t *b, int n)
{
    uint64_t borrow = 0;
    for (int i = 0; i < n; i++)
    {
        uint64_t d = a[i] - b[i];
        uint64_t next = a[i] < b[i];
        r[i] = d - borrow;
        borrow = next | (d < borrow);
    }
    return borrow;
}

static uint64_t emu_add_n(uint64_t *r, const uint64_t *a, const uint64_t *b, int n)
{
    uint64_t carry = 0;
    for (int i = 0; i < n; i++)
    {
        uint64_t s = a[i] + carry;
        carry = s < carry;
        r[i] = s + b[i];
        carry += r[i] < s;
    }
    return carry;
}

static void emu_fadd(const emu_field *f, uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t t[EMU_MAX];
    uint64_t c = emu_add_n(t, a, b, f->n);
    if (c || !emu_lt(t, f->p, f->n))
        emu_sub_n(t, t, f->p, f->n);
    memcpy(r, t, 8 * f->n);
}

static void emu_fsub(const emu_field *f, uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t t[EMU_MAX];
    if (emu_sub_n(t, a, b, f->n))
        emu_add_n(t, t, f->p, f->n);
    memcpy(r, t, 8 * f->n);
}

static void emu_fmul(const emu_field *f, uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    int n = f->n;
    uint64_t prod[2 * EMU_MAX] = {0};
    for (int i = 0; i < n; i++)
    {
        uint64_t carry = 0;
        for (int j = 0; j < n; j++)
        {
            unsigned __int128 t = (unsigned __int128)a[i] * b[j] + prod[i + j] + carry;
            prod[i + j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        prod[i + n] = carry;
    }
    uint64_t rem[EMU_MAX + 1] = {0};
    for (int bit = 128 * n - 1; bit >= 0; bit--)
    {
        for (int i = n; i > 0; i--)
            rem[i] = (rem[i] << 1) | (rem[i - 1] >> 63);
        rem[0] = (rem[0] << 1) | ((prod[bit >> 6] >> (bit & 63)) & 1);
        if (rem[n] || !emu_lt(rem, f->p, n))
            rem[n] -= emu_sub_n(rem, rem, f->p, n);
    }
    memcpy(r, rem, 8 * n);
}

static void emu_finv(const emu_field *f, uint64_t *r, const uint64_t *a)
{
    uint64_t e[EMU_MAX], acc[EMU_MAX] = {1}, two[EMU_MAX] = {2};
    emu_sub_n(e, f->p, two, f->n);
    for (int i = 64 * f->n - 1; i >= 0; i--)
    {
        emu_fmul(f, acc, acc, acc);
        if ((e[i >> 6] >> (i & 63)) & 1)
            emu_fmul(f, acc, acc, a);
    }
    memcpy(r, acc, 8 * f->n);
}

static void emu_canonical(const emu_field *f, const uint64_t *a, int count, uint64_t id)
{
    for (int k = 0; k < count; k++)
        if (!emu_lt(a + k * f->n, f->p, f->n))
            emu_die("non-canonical operand", id);
}

static int emu_on_curve(const emu_field *f, const uint64_t *pt)
{
    int n = f->n;
    uint64_t l[EMU_MAX], r[EMU_MAX], b[EMU_MAX] = {f->b};
    emu_fmul(f, l, pt + n, pt + n);
    emu_fmul(f, r, pt, pt);
    emu_fmul(f, r, r, pt);
    emu_fadd(f, r, r, b);
    return memcmp(l, r, 8 * n) == 0;
}

/* p = p + q (add) or p = 2p (double), affine, as the incomplete SP1 point precompiles. */
static void emu_point(const emu_field *f, uint64_t *p, const uint64_t *q, int dbl, uint64_t id)
{
    int n = f->n;
    uint64_t lam[EMU_MAX], t[EMU_MAX], u[EMU_MAX], x3[EMU_MAX], y3[EMU_MAX];
    emu_canonical(f, p, 2, id);
    if (!emu_on_curve(f, p))
        emu_die("point off the curve", id);
    if (dbl)
    {
        uint64_t zero[EMU_MAX] = {0};
        if (memcmp(p + n, zero, 8 * n) == 0)
            emu_die("double of a point of order 2", id);
        emu_fmul(f, t, p, p);
        emu_fadd(f, u, t, t);
        emu_fadd(f, t, u, t);
        emu_fadd(f, u, p + n, p + n);
        emu_finv(f, u, u);
        emu_fmul(f, lam, t, u);
        q = p;
    }
    else
    {
        emu_canonical(f, q, 2, id);
        if (!emu_on_curve(f, q))
            emu_die("point off the curve", id);
        if (memcmp(p, q, 8 * n) == 0)
            emu_die("add with equal x", id);
        emu_fsub(f, t, q + n, p + n);
        emu_fsub(f, u, q, p);
        emu_finv(f, u, u);
        emu_fmul(f, lam, t, u);
    }
    emu_fmul(f, x3, lam, lam);
    emu_fsub(f, x3, x3, p);
    emu_fsub(f, x3, x3, q);
    emu_fsub(f, t, p, x3);
    emu_fmul(f, y3, lam, t);
    emu_fsub(f, y3, y3, p + n);
    memcpy(p, x3, 8 * n);
    memcpy(p + n, y3, 8 * n);
}

void sp1_syscall(uint64_t id, void *xv, const void *yv)
{
    uint64_t *x = xv;
    const uint64_t *y = yv;
    emu_calls[id & 0x1ff]++;
    if ((uintptr_t)x % 8 || (uintptr_t)y % 8)
        emu_die("unaligned operand", id);
    if ((const uint64_t *)x == y)
        emu_die("aliased operands", id);
    switch (id)
    {
    case 0x0001010eULL: emu_point(&EMU_BN254, x, y, 0, id); return;
    case 0x0000010fULL: emu_point(&EMU_BN254, x, y, 1, id); return;
    case 0x0001011eULL: emu_point(&EMU_BLS, x, y, 0, id); return;
    case 0x0000011fULL: emu_point(&EMU_BLS, x, y, 1, id); return;
    default: break;
    }
    const emu_field *f;
    int op;
    switch (id)
    {
    case 0x00010126ULL: case 0x00010127ULL: case 0x00010128ULL:
        f = &EMU_BN254; op = (int)(id - 0x00010126ULL); break;
    case 0x00010129ULL: case 0x0001012aULL: case 0x0001012bULL:
        f = &EMU_BN254; op = 3 + (int)(id - 0x00010129ULL); break;
    case 0x00010120ULL: case 0x00010121ULL: case 0x00010122ULL:
        f = &EMU_BLS; op = (int)(id - 0x00010120ULL); break;
    case 0x00010123ULL: case 0x00010124ULL: case 0x00010125ULL:
        f = &EMU_BLS; op = 3 + (int)(id - 0x00010123ULL); break;
    default:
        emu_die("unknown syscall", id);
        return;
    }
    int n = f->n;
    emu_canonical(f, x, op < 3 ? 1 : 2, id);
    emu_canonical(f, y, op < 3 ? 1 : 2, id);
    if (op == 0) emu_fadd(f, x, x, y);
    else if (op == 1) emu_fsub(f, x, x, y);
    else if (op == 2) emu_fmul(f, x, x, y);
    else if (op == 3) { emu_fadd(f, x, x, y); emu_fadd(f, x + n, x + n, y + n); }
    else if (op == 4) { emu_fsub(f, x, x, y); emu_fsub(f, x + n, x + n, y + n); }
    else
    {
        uint64_t a[EMU_MAX], b[EMU_MAX], c0[EMU_MAX], c1[EMU_MAX];
        emu_fmul(f, a, x, y);
        emu_fmul(f, b, x + n, y + n);
        emu_fsub(f, c0, a, b);
        emu_fmul(f, a, x, y + n);
        emu_fmul(f, b, x + n, y);
        emu_fadd(f, c1, a, b);
        memcpy(x, c0, 8 * n);
        memcpy(x + n, c1, 8 * n);
    }
}

static unsigned long emu_total(void)
{
    unsigned long s = 0;
    for (int i = 0; i < 0x200; i++)
        s += emu_calls[i];
    return s;
}

static long emu_parse_hex(uint8_t *out, size_t capacity, const char *hex)
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

#endif
