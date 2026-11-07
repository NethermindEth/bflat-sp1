// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

// Runs the records of the input through the accelerators replacing the SDK's and commits keccak256 over
// (ok | output) per record. The first input byte picks the records:
//   0: (u32le base_len | u32le exp_len | u32le mod_len | base | exp | modulus) for zkvm_modexp,
//      output mod_len bytes;
//   1: (op | a64 | b64) for zkvm_bn254_g1_add (op 0) or zkvm_bn254_g1_mul (op 1, scalar in b's first 32
//      bytes), output 64 bytes, all zero on failure;
//   2: (u32le len | pairs) for zkvm_bn254_pairing, len a multiple of 192, output (verified);
//   3: (commitment48 | z32 | y32 | proof48) for zkvm_kzg_point_eval, output (verified).
// Expected output: tests/modexp/test_modexp.py, tests/bn254/test_g1.py, tests/bn254/test_pairing.py or
// tests/kzg/test_kzg.py --sp1-vectors.
using System.Collections.Generic;
using System.Runtime.InteropServices;

internal static unsafe class Accel
{
    [DllImport("__Internal")] internal static extern int zkvm_keccak256(byte* data, nuint len, byte* output);
    [DllImport("__Internal")] internal static extern int zkvm_modexp(byte* b, nuint bl, byte* e, nuint el, byte* m, nuint ml, byte* o);
    [DllImport("__Internal")] internal static extern int zkvm_bn254_g1_add(byte* p1, byte* p2, byte* o);
    [DllImport("__Internal")] internal static extern int zkvm_bn254_g1_mul(byte* p, byte* s, byte* o);
    [DllImport("__Internal")] internal static extern int zkvm_bn254_pairing(byte* pairs, nuint count, bool* verified);
    [DllImport("__Internal")] internal static extern int zkvm_kzg_point_eval(byte* c, byte* z, byte* y, byte* proof, bool* verified);
    [DllImport("__Internal")] internal static extern void read_input(byte** buf, nuint* size);
    [DllImport("__Internal")] internal static extern void write_output(byte* output, nuint size);
}

internal static unsafe class Program
{
    private static uint U32(byte* p) => (uint)(p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24);

    private static int Main()
    {
        byte* p; nuint n;
        Accel.read_input(&p, &n);
        byte* end = p + n;
        byte kind = *p++;
        List<byte> results = new();
        byte[] output = new byte[4096];
        fixed (byte* o = output)
        {
            while (p < end)
            {
                int rc, len;
                if (kind == 0)
                {
                    uint bl = U32(p), el = U32(p + 4), ml = U32(p + 8);
                    byte* b = p + 12, e = b + bl, m = e + el;
                    rc = Accel.zkvm_modexp(b, bl, e, el, m, ml, o);
                    len = (int)ml;
                    p = m + ml;
                }
                else if (kind >= 2)
                {
                    bool verified = false;
                    if (kind == 2)
                    {
                        uint pl = U32(p);
                        rc = Accel.zkvm_bn254_pairing(p + 4, pl / 192, &verified);
                        p += 4 + pl;
                    }
                    else
                    {
                        rc = Accel.zkvm_kzg_point_eval(p, p + 48, p + 80, p + 112, &verified);
                        p += 160;
                    }
                    o[0] = verified ? (byte)1 : (byte)0;
                    len = 1;
                }
                else
                {
                    rc = p[0] == 0 ? Accel.zkvm_bn254_g1_add(p + 1, p + 65, o) : Accel.zkvm_bn254_g1_mul(p + 1, p + 65, o);
                    len = 64;
                    if (rc != 0)
                        for (int i = 0; i < len; i++) o[i] = 0;
                    p += 129;
                }
                results.Add(rc == 0 ? (byte)1 : (byte)0);
                for (int i = 0; i < len; i++) results.Add(o[i]);
            }
        }
        byte[] all = results.ToArray();
        byte[] digest = new byte[32];
        fixed (byte* a = all, d = digest)
        {
            Accel.zkvm_keccak256(a, (nuint)all.Length, d);
            Accel.write_output(d, 32);
        }
        return 0;
    }
}
