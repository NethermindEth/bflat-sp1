/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * The SP1 precompiles and hooks ecrecover.c runs on. A host build
 * (SECP256K1_HOST_TEST) declares them instead, for tests/secp256k1 to
 * emulate. */

#ifndef SECP256K1_OPS_H
#define SECP256K1_OPS_H

#ifdef SECP256K1_HOST_TEST

void sp1_secp256k1_add(secp256k1_point *p, const secp256k1_point *q);
void sp1_secp256k1_double(secp256k1_point *p);
void sp1_uint256_mulmod(uint64_t x[4], const mulmod_operand *operand);
int secp256k1_hint_inverse(uint64_t r[4], const uint64_t a[4], const uint64_t m[4]);
int secp256k1_hint_sqrt(uint64_t r[4], int *is_square, const uint64_t a[4], const uint64_t m[4]);

#else

#include <stdbool.h>

#define SP1_SECP256K1_ADD 0x0001010aULL
#define SP1_SECP256K1_DOUBLE 0x0000010bULL
#define SP1_UINT256_MUL 0x0001011dULL
/* LOWEST_ALLOWED_FD (10) + 10 and + 11, sp1_primitives::consts::fd. */
#define SP1_FD_FP_SQRT 20
#define SP1_FD_FP_INV 21

/* From the zkEVM SDK in the same archive. */
typedef struct
{
    uint8_t *ptr;
    size_t len;
    size_t capacity;
} sp1_read_vec_result;
extern sp1_read_vec_result read_vec_raw(void);
extern bool syscall_enter_unconstrained(void);
extern void syscall_exit_unconstrained(void);
extern void syscall_write(uint32_t fd, const uint8_t *buf, size_t len);

static inline void sp1_ecall(uint64_t id, const void *a, const void *b)
{
    register uint64_t t0 __asm__("t0") = id;
    register const void *a0 __asm__("a0") = a;
    register const void *a1 __asm__("a1") = b;
    __asm__ volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
}

/* p += q. p and q must be distinct points with distinct x coordinates. */
static inline void sp1_secp256k1_add(secp256k1_point *p, const secp256k1_point *q)
{
    sp1_ecall(SP1_SECP256K1_ADD, p, q);
}

/* p = 2p for a point other than infinity. */
static inline void sp1_secp256k1_double(secp256k1_point *p)
{
    sp1_ecall(SP1_SECP256K1_DOUBLE, p, 0);
}

/* x = x * operand->y mod operand->m. */
static inline void sp1_uint256_mulmod(uint64_t x[4], const mulmod_operand *operand)
{
    sp1_ecall(SP1_UINT256_MUL, x, operand);
}

static void put_be32(uint8_t *b, const uint64_t a[4])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
            b[8 * (3 - i) + j] = (uint8_t)(a[i] >> (56 - 8 * j));
    }
}

static int read_be32(uint64_t r[4], sp1_read_vec_result v)
{
    if (v.ptr == NULL || v.len != 32)
        return 0;
    for (int i = 0; i < 4; i++)
    {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++)
            w = (w << 8) | v.ptr[8 * (3 - i) + j];
        r[i] = w;
    }
    return 1;
}

/* Sends [len | a | m (| nqr)] to a hook, as the k256 crate's call_*_hook do.
 * Unconstrained execution is rolled back - registers, pc and memory - when it
 * exits, which is why this is its own frame: only the hook's output, queued
 * on the hint stream, survives. */
__attribute__((noinline)) static void sp1_call_hook(uint32_t fd, const uint64_t a[4], const uint64_t m[4], const uint64_t *nqr)
{
    if (syscall_enter_unconstrained())
    {
        uint8_t buf[4 + 3 * 32];
        size_t len = 4 + 2 * 32;
        buf[0] = buf[1] = buf[2] = 0;
        buf[3] = 32;
        put_be32(buf + 4, a);
        put_be32(buf + 36, m);
        if (nqr != NULL)
        {
            put_be32(buf + 68, nqr);
            len += 32;
        }
        syscall_write(fd, buf, len);
        syscall_exit_unconstrained();
    }
}

/* Asks the host for a^-1 mod m. The caller checks the answer. */
static int secp256k1_hint_inverse(uint64_t r[4], const uint64_t a[4], const uint64_t m[4])
{
    sp1_call_hook(SP1_FD_FP_INV, a, m, NULL);
    return read_be32(r, read_vec_raw());
}

/* Asks the host for a square root of a mod m, or, when a is not a square, of
 * -a (the hook's non-residue argument is m - 1). The caller checks the
 * answer. */
static int secp256k1_hint_sqrt(uint64_t r[4], int *is_square, const uint64_t a[4], const uint64_t m[4])
{
    uint64_t minus_one[4] = {m[0] - 1, m[1], m[2], m[3]};
    sp1_call_hook(SP1_FD_FP_SQRT, a, m, minus_one);
    sp1_read_vec_result status = read_vec_raw();
    sp1_read_vec_result root = read_vec_raw();
    if (status.ptr == NULL || status.len != 1 || status.ptr[0] > 1)
        return 0;
    *is_square = status.ptr[0];
    return read_be32(r, root);
}

#endif

#endif
