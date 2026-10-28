/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Host harness for src/pairing/bls12_381_kzg.c on emulated BLS12-381 field and point precompiles.
 *
 * stdin, one command per line:
 *   kzg <commitment hex48> <z hex32> <y hex32> <proof hex48>   -> "ok <verified> <syscalls>" */

#define SP1_HOST_TEST
#include "../../src/pairing/bls12_381_kzg.c"
#include "../common/sp1_field_emu.h"

int main(void)
{
    char line[1024], hc[128], hz[128], hy[128], hp[128];
    while (fgets(line, sizeof line, stdin))
    {
        uint8_t c[48], z[32], y[32], p[48];
        if (sscanf(line, "kzg %127s %127s %127s %127s", hc, hz, hy, hp) != 4)
            continue;
        if (emu_parse_hex(c, 48, hc) != 48 || emu_parse_hex(z, 32, hz) != 32 || emu_parse_hex(y, 32, hy) != 32 ||
            emu_parse_hex(p, 48, hp) != 48)
        {
            fprintf(stderr, "bad line: %s", line);
            return 1;
        }
        memset(emu_calls, 0, sizeof emu_calls);
        bool verified = true;
        if (zkvm_kzg_point_eval(c, z, y, p, &verified) == ZKVM_EOK)
            printf("ok %d %lu\n", verified ? 1 : 0, emu_total());
        else
            printf("fail %lu\n", emu_total());
        fflush(stdout);
    }
    return 0;
}
