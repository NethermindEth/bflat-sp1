/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Host harness for src/modexp/modexp.c on an emulated UINT256_MUL.
 *
 * stdin, one command per line, "-" for an empty operand:
 *   modexp <base hex> <exp hex> <modulus hex>
 *       -> "ok <output hex> <mulmods> <fallback>" or "fail"
 * fallback is 1 when the call went to the SDK, which this harness stubs. */

#define SP1_HOST_TEST
#include "../../src/modexp/modexp.c"
#include "../common/sp1_emu.h"

#define MAX_OPERAND 4096

static int fallbacks;

int sp1_sdk_zkvm_modexp(const uint8_t *base, size_t base_len, const uint8_t *exp, size_t exp_len,
                        const uint8_t *modulus, size_t mod_len, uint8_t *output)
{
    (void)base, (void)base_len, (void)exp, (void)exp_len, (void)modulus;
    fallbacks++;
    memset(output, 0, mod_len);
    return ZKVM_EOK;
}

int main(void)
{
    static char line[6 * MAX_OPERAND + 64], hb[2 * MAX_OPERAND + 2], he[2 * MAX_OPERAND + 2], hm[2 * MAX_OPERAND + 2];
    static uint8_t base[MAX_OPERAND], exp[MAX_OPERAND], modulus[MAX_OPERAND], output[MAX_OPERAND];
    while (fgets(line, sizeof line, stdin))
    {
        if (sscanf(line, "modexp %8193s %8193s %8193s", hb, he, hm) != 3)
            continue;
        long bl = parse_hex(base, MAX_OPERAND, hb), el = parse_hex(exp, MAX_OPERAND, he),
             ml = parse_hex(modulus, MAX_OPERAND, hm);
        if (bl < 0 || el < 0 || ml < 0)
        {
            fprintf(stderr, "bad line: %s", line);
            return 1;
        }
        emu_mulmods = 0;
        fallbacks = 0;
        memset(output, 0xa5, sizeof output);
        if (zkvm_modexp(bl ? base : NULL, (size_t)bl, el ? exp : NULL, (size_t)el, ml ? modulus : NULL, (size_t)ml,
                        ml ? output : NULL) == ZKVM_EOK)
        {
            printf("ok ");
            print_hex(output, (size_t)ml);
            printf(" %lu %d\n", emu_mulmods, fallbacks);
        }
        else
        {
            printf("fail\n");
        }
        fflush(stdout);
    }
    return 0;
}
