/**
 * @file
 * @brief SP1 precompiles (ecall-based)
 *
 * SP1 takes the syscall id in t0 - NOT the Linux a7 - and the arguments in
 * a0.. by the ordinary C ABI, so every precompile is a three-instruction leaf:
 * load the id, ecall, return. Ids and argument counts are taken from
 * sp1/crates/zkvm/entrypoint/src/syscalls (SP1 v6).
 *
 * An id SP1 does not recognise is a hard ExecutionError, so this file is the
 * ONLY place a guest may issue an ecall besides pal's halt/console path.
 *
 * Copyright (C) 2026 Demerzel Solutions Limited (Nethermind)
 *
 * @author Maxim Menshikov <maksim.menshikov@nethermind.io>
 */
.option norelax

/* Precompiles taking one pointer. SP1's own wrappers pass a1 = 0 for these,
 * so do the same rather than leaving the caller's register visible to the
 * executor. */
.macro SP1_SYSCALL_1 name, id
    .section .text, "ax", @progbits
    .balign 4
    .global \name
    .type \name, @function
\name:
    .cfi_startproc
    /* leaf: no stack frame */
    li      t0, \id
    li      a1, 0
    ecall
    ret
    .cfi_endproc
    .size \name, .-\name
.endm

/* Precompiles taking two or more pointers: the arguments are already in
 * a0..a4 by the C ABI, so only the id has to be materialised. */
.macro SP1_SYSCALL_N name, id
    .section .text, "ax", @progbits
    .balign 4
    .global \name
    .type \name, @function
\name:
    .cfi_startproc
    /* leaf: no stack frame */
    li      t0, \id
    ecall
    ret
    .cfi_endproc
    .size \name, .-\name
.endm

/* Syscalls whose result comes back in t0 rather than a0. */
.macro SP1_SYSCALL_RET_T0 name, id
    .section .text, "ax", @progbits
    .balign 4
    .global \name
    .type \name, @function
\name:
    .cfi_startproc
    /* leaf: no stack frame */
    li      t0, \id
    ecall
    mv      a0, t0
    ret
    .cfi_endproc
    .size \name, .-\name
.endm

/* ---- Hashes ------------------------------------------------------------ */
SP1_SYSCALL_1     zkvm_keccak_permute,          0x00010109  /* [u64; 25]      */
SP1_SYSCALL_1     zkvm_sha256_extend,           0x00300105  /* [u32; 64]      */
SP1_SYSCALL_N     zkvm_sha256_compress,         0x00010106  /* w, state       */
SP1_SYSCALL_1     zkvm_poseidon2,               0x00000133  /* in/out         */

/* ---- Edwards / short-Weierstrass curves -------------------------------- */
SP1_SYSCALL_N     zkvm_ed_add,                  0x00010107
SP1_SYSCALL_1     zkvm_ed_decompress,           0x00000108
SP1_SYSCALL_N     zkvm_secp256k1_add,           0x0001010a
SP1_SYSCALL_1     zkvm_secp256k1_double,        0x0000010b
SP1_SYSCALL_N     zkvm_secp256k1_decompress,    0x0000010c
SP1_SYSCALL_N     zkvm_secp256r1_add,           0x0001012c
SP1_SYSCALL_1     zkvm_secp256r1_double,        0x0000012d
SP1_SYSCALL_N     zkvm_secp256r1_decompress,    0x0000012e
SP1_SYSCALL_N     zkvm_bn254_add,               0x0001010e
SP1_SYSCALL_1     zkvm_bn254_double,            0x0000010f
SP1_SYSCALL_N     zkvm_bls12381_add,            0x0001011e
SP1_SYSCALL_1     zkvm_bls12381_double,         0x0000011f
SP1_SYSCALL_N     zkvm_bls12381_decompress,     0x0000011c

/* ---- Field arithmetic (Fp / Fp2) --------------------------------------- */
SP1_SYSCALL_N     zkvm_bn254_fp_addmod,         0x00010126
SP1_SYSCALL_N     zkvm_bn254_fp_submod,         0x00010127
SP1_SYSCALL_N     zkvm_bn254_fp_mulmod,         0x00010128
SP1_SYSCALL_N     zkvm_bn254_fp2_addmod,        0x00010129
SP1_SYSCALL_N     zkvm_bn254_fp2_submod,        0x0001012a
SP1_SYSCALL_N     zkvm_bn254_fp2_mulmod,        0x0001012b
SP1_SYSCALL_N     zkvm_bls12381_fp_addmod,      0x00010120
SP1_SYSCALL_N     zkvm_bls12381_fp_submod,      0x00010121
SP1_SYSCALL_N     zkvm_bls12381_fp_mulmod,      0x00010122
SP1_SYSCALL_N     zkvm_bls12381_fp2_addmod,     0x00010123
SP1_SYSCALL_N     zkvm_bls12381_fp2_submod,     0x00010124
SP1_SYSCALL_N     zkvm_bls12381_fp2_mulmod,     0x00010125

/* ---- Big-integer arithmetic -------------------------------------------- */
SP1_SYSCALL_N     zkvm_uint256_mulmod,          0x0001011d  /* x, y          */
SP1_SYSCALL_N     zkvm_uint256_add_with_carry,  0x00010130  /* a,b,c,d,e     */
SP1_SYSCALL_N     zkvm_uint256_mul_with_carry,  0x00010131  /* a,b,c,d,e     */
SP1_SYSCALL_N     zkvm_u256x2048_mul,           0x0001012f  /* a,b,lo,hi     */

/* ---- Guest I/O ---------------------------------------------------------
 * Not precompiles, but the only way a guest reads its input and commits
 * public values. write() takes (fd, buf, len); FD_PUBLIC_VALUES is 13 and
 * FD_HINT 14 (LOWEST_ALLOWED_FD 10 + 3/4, sp1_primitives::consts::fd). */
SP1_SYSCALL_N     zkvm_write,                   0x00000002
SP1_SYSCALL_RET_T0 zkvm_hint_len,               0x000000f0
SP1_SYSCALL_N     zkvm_hint_read,               0x000000f1
