/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * zkvm_modexp for SP1, replacing the zkEVM SDK's for moduli up to 256 bits.
 *
 * The SDK computes every modexp in software with num-bigint-dig, built
 * without its u64_digit feature, so a 256-bit exponentiation costs on the
 * order of a million instructions of 32-bit limb arithmetic. Moduli that fit
 * in 256 bits - the ones zk-proof verifiers use for field inversions - run
 * here on the UINT256_MUL precompile instead: a fixed 4-bit window, so a
 * 256-bit exponent takes 256 squarings, at most 64 multiplications and 14 to
 * build the table. Larger moduli still go to the SDK, renamed
 * sp1_sdk_zkvm_modexp by build.sh. */

#include "../common/u256.h"

#define ZKVM_EOK 0
#define ZKVM_EFAIL (-1)

#define WINDOW_BITS 4
#define WINDOW_ENTRIES (1 << WINDOW_BITS)

/* Below this many exponent bytes the window table costs more than it saves. */
#define BINARY_MAX_EXP_BYTES 8

int sp1_sdk_zkvm_modexp(const uint8_t *base, size_t base_len, const uint8_t *exp, size_t exp_len,
                        const uint8_t *modulus, size_t mod_len, uint8_t *output);

/* r = the big-endian integer b[0..len) mod m, Horner over 32-byte chunks. */
static void reduce(uint64_t r[4], const uint8_t *b, size_t len, const uint64_t m[4])
{
    mulmod_operand one = {{1, 0, 0, 0}, {m[0], m[1], m[2], m[3]}};
    while (len > 0 && *b == 0)
    {
        b++;
        len--;
    }
    set_small(r, 0);
    if (len == 0)
        return;

    size_t head = len % 32 == 0 ? 32 : len % 32;
    load_be_n(r, b, head);
    sp1_uint256_mulmod(r, &one);
    b += head;
    len -= head;
    if (len == 0)
        return;

    /* 2^256 mod m, from 2^256 - m. */
    static const uint64_t zero[4] = {0, 0, 0, 0};
    mulmod_operand shift;
    copy4(shift.m, m);
    sub_borrow(shift.y, zero, m);
    sp1_uint256_mulmod(shift.y, &one);
    for (; len > 0; b += 32, len -= 32)
    {
        uint64_t chunk[4];
        load_be(chunk, b);
        sp1_uint256_mulmod(chunk, &one);
        sp1_uint256_mulmod(r, &shift);
        add_mod(r, r, chunk, m);
    }
}

static void square(uint64_t acc[4], mulmod_operand *scratch)
{
    copy4(scratch->y, acc);
    sp1_uint256_mulmod(acc, scratch);
}

/* acc = base^e mod m, e big-endian with a non-zero first byte. */
static void pow_binary(uint64_t acc[4], const uint64_t base[4], const uint8_t *e, size_t len, const uint64_t m[4])
{
    mulmod_operand multiplier, scratch;
    copy4(multiplier.y, base);
    copy4(multiplier.m, m);
    copy4(scratch.m, m);
    int started = 0;
    for (size_t i = 0; i < len; i++)
    {
        for (int bit = 7; bit >= 0; bit--)
        {
            if (started)
                square(acc, &scratch);
            if ((e[i] >> bit) & 1)
            {
                if (started)
                    sp1_uint256_mulmod(acc, &multiplier);
                else
                {
                    copy4(acc, base);
                    started = 1;
                }
            }
        }
    }
}

/* acc = base^e mod m, e big-endian with a non-zero first byte. */
static void pow_window(uint64_t acc[4], const uint64_t base[4], const uint8_t *e, size_t len, const uint64_t m[4])
{
    mulmod_operand table[WINDOW_ENTRIES], scratch;
    copy4(table[1].y, base);
    copy4(table[1].m, m);
    for (int i = 2; i < WINDOW_ENTRIES; i++)
    {
        copy4(table[i].y, table[i - 1].y);
        sp1_uint256_mulmod(table[i].y, &table[1]);
        copy4(table[i].m, m);
    }
    copy4(scratch.m, m);

    int started = 0;
    for (size_t i = 0; i < 2 * len; i++)
    {
        unsigned digit = (e[i >> 1] >> (i & 1 ? 0 : WINDOW_BITS)) & (WINDOW_ENTRIES - 1);
        if (started)
        {
            for (int j = 0; j < WINDOW_BITS; j++)
                square(acc, &scratch);
            if (digit)
                sp1_uint256_mulmod(acc, &table[digit]);
        }
        else if (digit)
        {
            copy4(acc, table[digit].y);
            started = 1;
        }
    }
}

int zkvm_modexp(const uint8_t *base, size_t base_len, const uint8_t *exp, size_t exp_len,
                const uint8_t *modulus, size_t mod_len, uint8_t *output)
{
    if ((base == NULL && base_len != 0) || (exp == NULL && exp_len != 0) ||
        (modulus == NULL && mod_len != 0) || (output == NULL && mod_len != 0))
        return ZKVM_EFAIL;

    size_t skip = 0;
    while (skip < mod_len && modulus[skip] == 0)
        skip++;
    size_t width = mod_len - skip;
    if (width > 32)
        return sp1_sdk_zkvm_modexp(base, base_len, exp, exp_len, modulus, mod_len, output);

    for (size_t i = 0; i < mod_len; i++)
        output[i] = 0;
    /* EIP-198: a zero modulus gives zero, and so does every residue mod 1. */
    if (width == 0)
        return ZKVM_EOK;
    uint64_t m[4];
    load_be_n(m, modulus + skip, width);
    if (m[0] == 1 && (m[1] | m[2] | m[3]) == 0)
        return ZKVM_EOK;

    while (exp_len > 0 && *exp == 0)
    {
        exp++;
        exp_len--;
    }
    uint64_t result[4];
    if (exp_len == 0)
    {
        set_small(result, 1);
    }
    else
    {
        uint64_t b[4];
        reduce(b, base, base_len, m);
        if (exp_len <= BINARY_MAX_EXP_BYTES)
            pow_binary(result, b, exp, exp_len, m);
        else
            pow_window(result, b, exp, exp_len, m);
    }
    store_be_n(output + skip, result, width);
    return ZKVM_EOK;
}
