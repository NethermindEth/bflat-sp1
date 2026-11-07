/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Host harness for src/bn254/g1.c on emulated BN254_ADD, BN254_DOUBLE and
 * UINT256_MUL precompiles.
 *
 * stdin, one command per line:
 *   add <p1 hex64> <p2 hex64>   -> "ok <point hex64> <doubles> <adds>" or "fail"
 *   mul <p hex64> <scalar hex32> -> "ok <point hex64> <doubles> <adds>" or "fail"
 *   split <k hex32>             -> "<k1 hex32> <neg1> <k2 hex32> <neg2>" */

#define SP1_HOST_TEST
#include "../../src/bn254/g1.c"
#include "../common/sp1_emu.h"

static const emu_curve BN254 = {
    {0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL},
    {3, 0, 0, 0},
    "bn254"};

void sp1_bn254_add(sp1_point *p, const sp1_point *q)
{
    emu_add(&BN254, p, q);
}

void sp1_bn254_double(sp1_point *p)
{
    emu_double(&BN254, p);
}

int main(void)
{
    char line[512], cmd[16], ha[160], hb[160];
    while (fgets(line, sizeof line, stdin))
    {
        if (sscanf(line, "%15s %159s %159s", cmd, ha, hb) < 2)
            continue;
        if (strcmp(cmd, "split") == 0)
        {
            uint8_t kb[32];
            uint64_t k[4], k1[5], k2[5];
            int neg1, neg2;
            if (parse_hex(kb, 32, ha) != 32)
                return 1;
            load_be(k, kb);
            split_lambda(k1, &neg1, k2, &neg2, k);
            store_be(kb, k1);
            print_hex(kb, 32);
            printf(" %d ", neg1);
            store_be(kb, k2);
            print_hex(kb, 32);
            printf(" %d\n", neg2);
            fflush(stdout);
            continue;
        }
        uint8_t a[64], b[64], out[64];
        int is_add = strcmp(cmd, "add") == 0;
        if (parse_hex(a, 64, ha) != 64 || parse_hex(b, 64, hb) != (is_add ? 64 : 32))
        {
            fprintf(stderr, "bad line: %s", line);
            return 1;
        }
        emu_doubles = emu_adds = 0;
        int rc = is_add ? zkvm_bn254_g1_add(a, b, out) : zkvm_bn254_g1_mul(a, b, out);
        if (rc == ZKVM_EOK)
        {
            printf("ok ");
            print_hex(out, 64);
        }
        else
        {
            printf("fail");
        }
        printf(" %lu %lu\n", emu_doubles, emu_adds);
        fflush(stdout);
    }
    return 0;
}
