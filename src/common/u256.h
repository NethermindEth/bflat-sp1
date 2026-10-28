/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * 256-bit little-endian limb arithmetic and the UINT256_MUL precompile, shared by
 * the accelerators that replace the zkEVM SDK's. A host build (SP1_HOST_TEST)
 * declares the precompile instead, for the tests to emulate. */

#ifndef SP1_U256_H
#define SP1_U256_H

#include <stddef.h>
#include <stdint.h>

/* The UINT256_MUL precompile's second operand: a multiplier and a modulus,
 * contiguous. */
typedef struct
{
    uint64_t y[4];
    uint64_t m[4];
} mulmod_operand;

/* An affine point as the SP1 curve precompiles take it: x then y, each four
 * little-endian limbs. */
typedef struct
{
    uint64_t x[4];
    uint64_t y[4];
} sp1_point;

#ifdef SP1_HOST_TEST

void sp1_uint256_mulmod(uint64_t x[4], const mulmod_operand *operand);
void sp1_syscall(uint64_t id, void *x, const void *y);

#else

#define SP1_UINT256_MUL 0x0001011dULL

static inline void sp1_ecall(uint64_t id, const void *a, const void *b)
{
    register uint64_t t0 __asm__("t0") = id;
    register const void *a0 __asm__("a0") = a;
    register const void *a1 __asm__("a1") = b;
    __asm__ volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
}

/* A precompile taking two pointers whose result overwrites the first: x op= y. */
static inline void sp1_syscall(uint64_t id, void *x, const void *y)
{
    sp1_ecall(id, x, y);
}

/* x = x * operand->y mod operand->m, for any x and y below 2^256 and m != 0. */
static inline void sp1_uint256_mulmod(uint64_t x[4], const mulmod_operand *operand)
{
    sp1_ecall(SP1_UINT256_MUL, x, operand);
}

#endif

static inline void copy4(uint64_t r[4], const uint64_t a[4])
{
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
}

static inline void set_small(uint64_t r[4], uint64_t v)
{
    r[0] = v;
    r[1] = r[2] = r[3] = 0;
}

static inline int is_zero(const uint64_t a[4])
{
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

static inline int equal(const uint64_t a[4], const uint64_t b[4])
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
}

static inline int less_than(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; i--)
    {
        if (a[i] != b[i])
            return a[i] < b[i];
    }
    return 0;
}

/* r = a + b, returning the carry out. */
static inline uint64_t add_carry(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
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
static inline uint64_t sub_borrow(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
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
static inline void add_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4])
{
    if (add_carry(r, a, b) || !less_than(r, m))
        sub_borrow(r, r, m);
}

/* r = a * b mod m, through the UINT256_MUL precompile. */
static inline void mul_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4])
{
    mulmod_operand operand;
    copy4(operand.y, b);
    copy4(operand.m, m);
    copy4(r, a);
    sp1_uint256_mulmod(r, &operand);
}

/* r = the big-endian integer in b[0..len), len <= 32. */
static inline void load_be_n(uint64_t r[4], const uint8_t *b, size_t len)
{
    set_small(r, 0);
    for (size_t i = 0; i < len; i++)
    {
        size_t bit = 8 * (len - 1 - i);
        r[bit >> 6] |= (uint64_t)b[i] << (bit & 63);
    }
}

static inline void load_be(uint64_t r[4], const uint8_t *b)
{
    for (int i = 0; i < 4; i++)
    {
        const uint8_t *w = b + 8 * (3 - i);
        r[i] = ((uint64_t)w[0] << 56) | ((uint64_t)w[1] << 48) | ((uint64_t)w[2] << 40) |
               ((uint64_t)w[3] << 32) | ((uint64_t)w[4] << 24) | ((uint64_t)w[5] << 16) |
               ((uint64_t)w[6] << 8) | (uint64_t)w[7];
    }
}

/* Writes the low len bytes of a, big-endian, to b[0..len), len <= 32. */
static inline void store_be_n(uint8_t *b, const uint64_t a[4], size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        size_t bit = 8 * (len - 1 - i);
        b[i] = (uint8_t)(a[bit >> 6] >> (bit & 63));
    }
}

static inline void store_be(uint8_t *b, const uint64_t a[4])
{
    for (int i = 0; i < 4; i++)
    {
        uint8_t *w = b + 8 * (3 - i);
        for (int j = 0; j < 8; j++)
            w[j] = (uint8_t)(a[i] >> (56 - 8 * j));
    }
}

/* RV64IM has no count-leading-zeros instruction, and the freestanding
 * archive has no libgcc to supply __clzdi2. */
static inline int bit_length(const uint64_t a[4])
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

/* Writes the width-w NAF of s into digits[stride * i] for i < len: odd digits
 * in (-2^(w-1), 2^(w-1)), at least w - 1 zeros between two of them. len must
 * exceed the bit length of s for the last carry to land inside it. */
static inline void wnaf(int8_t *digits, int stride, const uint64_t s[5], int w, int len)
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
        digits[stride * bit] = (int8_t)word;
        bit += now;
    }
}

#endif
