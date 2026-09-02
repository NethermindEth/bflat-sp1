// Integration guest: calls every entry point of the eth-act zkVM interface
// exactly the way Nethermind.Zkvm.Abstractions does - [DllImport("__Internal")]
// resolved by bflat's direct P/Invoke against the statically linked archive.
//
// It is not run; it is LINKED. That is the point: with direct P/Invoke a
// missing or mis-localized symbol is an undefined reference at link time, so
// building this guest proves the archive presents the whole interface to a
// real bflat guest, in the real memory map, with no symbol colliding against
// musl, pal or the guest's own entry point.

using System.Runtime.InteropServices;

internal static class Accel
{
    [DllImport("__Internal")] internal static extern int zkvm_keccak256(ref byte data, nuint len, ref byte output);
    [DllImport("__Internal")] internal static extern int zkvm_sha256(ref byte data, nuint len, ref byte output);
    [DllImport("__Internal")] internal static extern int zkvm_ripemd160(ref byte data, nuint len, ref byte output);
    [DllImport("__Internal")] internal static extern int zkvm_modexp(ref byte b, nuint bl, ref byte e, nuint el, ref byte m, nuint ml, ref byte o);
    [DllImport("__Internal")] internal static extern int zkvm_secp256k1_verify(ref byte m, ref byte s, ref byte p, ref byte ok);
    [DllImport("__Internal")] internal static extern int zkvm_secp256k1_ecrecover(ref byte m, ref byte s, byte recid, ref byte o);
    [DllImport("__Internal")] internal static extern int zkvm_secp256r1_verify(ref byte m, ref byte s, ref byte p, ref byte ok);
    [DllImport("__Internal")] internal static extern int zkvm_bn254_g1_add(ref byte a, ref byte b, ref byte r);
    [DllImport("__Internal")] internal static extern int zkvm_bn254_g1_mul(ref byte p, ref byte s, ref byte r);
    [DllImport("__Internal")] internal static extern int zkvm_bn254_pairing(ref byte pairs, nuint n, ref byte ok);
    [DllImport("__Internal")] internal static extern int zkvm_blake2f(uint rounds, ref byte h, ref byte m, ref byte t, byte f);
    [DllImport("__Internal")] internal static extern int zkvm_kzg_point_eval(ref byte c, ref byte z, ref byte y, ref byte p, ref byte ok);
    [DllImport("__Internal")] internal static extern int zkvm_bls12_g1_add(ref byte a, ref byte b, ref byte r);
    [DllImport("__Internal")] internal static extern int zkvm_bls12_g1_msm(ref byte pairs, nuint n, ref byte r);
    [DllImport("__Internal")] internal static extern int zkvm_bls12_g2_add(ref byte a, ref byte b, ref byte r);
    [DllImport("__Internal")] internal static extern int zkvm_bls12_g2_msm(ref byte pairs, nuint n, ref byte r);
    [DllImport("__Internal")] internal static extern int zkvm_bls12_pairing(ref byte pairs, nuint n, ref byte ok);
    [DllImport("__Internal")] internal static extern int zkvm_bls12_map_fp_to_g1(ref byte fe, ref byte r);
    [DllImport("__Internal")] internal static extern int zkvm_bls12_map_fp2_to_g2(ref byte fe, ref byte r);
    [DllImport("__Internal")] internal static extern unsafe void read_input(byte** buf, nuint* size);
    [DllImport("__Internal")] internal static extern void write_output(ref byte output, nuint size);
}

internal static class Program
{
    private static unsafe int Main()
    {
        byte[] b = new byte[256];
        byte ok = 0;
        int rc = 0;
        byte* p; nuint n;
        Accel.read_input(&p, &n);
        rc |= Accel.zkvm_keccak256(ref b[0], 64, ref b[0]);
        rc |= Accel.zkvm_sha256(ref b[0], 64, ref b[0]);
        rc |= Accel.zkvm_ripemd160(ref b[0], 64, ref b[0]);
        rc |= Accel.zkvm_modexp(ref b[0], 32, ref b[0], 32, ref b[0], 32, ref b[0]);
        rc |= Accel.zkvm_secp256k1_verify(ref b[0], ref b[0], ref b[0], ref ok);
        rc |= Accel.zkvm_secp256k1_ecrecover(ref b[0], ref b[0], 0, ref b[0]);
        rc |= Accel.zkvm_secp256r1_verify(ref b[0], ref b[0], ref b[0], ref ok);
        rc |= Accel.zkvm_bn254_g1_add(ref b[0], ref b[0], ref b[0]);
        rc |= Accel.zkvm_bn254_g1_mul(ref b[0], ref b[0], ref b[0]);
        rc |= Accel.zkvm_bn254_pairing(ref b[0], 1, ref ok);
        rc |= Accel.zkvm_blake2f(12, ref b[0], ref b[0], ref b[0], 1);
        rc |= Accel.zkvm_kzg_point_eval(ref b[0], ref b[0], ref b[0], ref b[0], ref ok);
        rc |= Accel.zkvm_bls12_g1_add(ref b[0], ref b[0], ref b[0]);
        rc |= Accel.zkvm_bls12_g1_msm(ref b[0], 1, ref b[0]);
        rc |= Accel.zkvm_bls12_g2_add(ref b[0], ref b[0], ref b[0]);
        rc |= Accel.zkvm_bls12_g2_msm(ref b[0], 1, ref b[0]);
        rc |= Accel.zkvm_bls12_pairing(ref b[0], 1, ref ok);
        rc |= Accel.zkvm_bls12_map_fp_to_g1(ref b[0], ref b[0]);
        rc |= Accel.zkvm_bls12_map_fp2_to_g2(ref b[0], ref b[0]);
        Accel.write_output(ref b[0], 32);
        return rc + ok;
    }
}
