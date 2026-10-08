// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

// Runs every (msg32 | sig64 | recid) record of the input through zkvm_secp256k1_ecrecover and
// commits keccak256 over (ok | pubkey or 64 zero bytes) per record, then the u32le success count.
// Expected output: tests/secp256k1/test_ecrecover.py --sp1-vectors.
using System.Runtime.InteropServices;

internal static class Accel
{
    [DllImport("__Internal")] internal static extern int zkvm_keccak256(ref byte data, nuint len, ref byte output);
    [DllImport("__Internal")] internal static extern int zkvm_secp256k1_ecrecover(ref byte m, ref byte s, byte recid, ref byte o);
    [DllImport("__Internal")] internal static extern unsafe void read_input(byte** buf, nuint* size);
    [DllImport("__Internal")] internal static extern void write_output(ref byte output, nuint size);
}

internal static class Program
{
    private static unsafe int Main()
    {
        byte* p; nuint n;
        Accel.read_input(&p, &n);
        int count = (int)n / 97;
        byte[] results = new byte[count * 65 + 1];
        byte[] msg = new byte[32], sig = new byte[64], pub = new byte[64];
        int ok = 0;
        for (int i = 0; i < count; i++)
        {
            byte* rec = p + i * 97;
            for (int j = 0; j < 32; j++) msg[j] = rec[j];
            for (int j = 0; j < 64; j++) sig[j] = rec[32 + j];
            for (int j = 0; j < 64; j++) pub[j] = 0;
            int rc = Accel.zkvm_secp256k1_ecrecover(ref msg[0], ref sig[0], rec[96], ref pub[0]);
            results[i * 65] = rc == 0 ? (byte)1 : (byte)0;
            if (rc == 0) { ok++; for (int j = 0; j < 64; j++) results[i * 65 + 1 + j] = pub[j]; }
        }
        byte[] output = new byte[36];
        Accel.zkvm_keccak256(ref results[0], (nuint)(count * 65), ref output[0]);
        output[32] = (byte)ok; output[33] = (byte)(ok >> 8); output[34] = (byte)(ok >> 16); output[35] = (byte)(ok >> 24);
        Accel.write_output(ref output[0], 36);
        return 0;
    }
}
