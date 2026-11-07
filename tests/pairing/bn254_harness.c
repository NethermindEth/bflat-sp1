/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Host harness for src/pairing/bn254_pairing.c on emulated BN254 field precompiles.
 *
 * stdin, one command per line ("-" for no pairs):
 *   pair <pairs hex>   -> "ok <verified> <syscalls>" or "fail <syscalls>" */

#define SP1_HOST_TEST
#include "../../src/pairing/bn254_pairing.c"
#include "../common/sp1_field_emu.h"

int main(void)
{
    static char line[1 << 16], hex[1 << 16];
    static uint8_t pairs[1 << 15];
    while (fgets(line, sizeof line, stdin))
    {
        if (sscanf(line, "pair %65535s", hex) != 1)
            continue;
        long len = emu_parse_hex(pairs, sizeof pairs, hex);
        if (len < 0 || len % 192)
        {
            fprintf(stderr, "bad line: %.80s\n", line);
            return 1;
        }
        memset(emu_calls, 0, sizeof emu_calls);
        bool verified = false;
        if (zkvm_bn254_pairing(len ? pairs : NULL, (size_t)len / 192, &verified) == ZKVM_EOK)
            printf("ok %d %lu\n", verified ? 1 : 0, emu_total());
        else
            printf("fail %lu\n", emu_total());
        fflush(stdout);
    }
    return 0;
}
