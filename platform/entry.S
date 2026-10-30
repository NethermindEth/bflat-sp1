/**
 * @file
 * @brief ZKVM SP1 implementation.
 *
 * SP1 (succinctlabs/sp1 v6+) proves the riscv64im-succinct-zkvm-elf target:
 * RV64IM, lp64, no A and no C extension. The loader
 * (crates/core/executor/src/disassembler/elf.rs) reads PT_LOAD program
 * headers only, takes the entry from e_entry, and does NOT set up sp -
 * _start must point it at the stack itself, exactly as SP1's own Rust
 * entrypoint does (crates/zkvm/entrypoint/src/lib.rs).
 *
 * Copyright (C) 2026 Demerzel Solutions Limited (Nethermind)
 *
 * @author Maxim Menshikov <maksim.menshikov@nethermind.io>
 */
.option norelax

/* SP1 syscalls (sp1/crates/zkvm/entrypoint/src/syscalls/mod.rs): the id goes
 * in t0, the arguments in a0.. - NOT the Linux a7 convention. An id SP1 does
 * not know is a hard ExecutionError, so nothing may leak a stray ecall. */
.equ SP1_HALT,                   0x00
.equ SP1_WRITE,                  0x02
.equ SP1_COMMIT,                 0x10
.equ SP1_COMMIT_DEFERRED_PROOFS, 0x1A

.section .rodata
    .balign 8
app_str:
    .asciz "app"

    .section .data
    .balign 8
argv_vec:
    .dword app_str
    .dword 0

/* sp1-zkvm's runtime entry, or 0 when no bindings library is linked. See the
 * note in _start for why the address is materialised from .data. */
.weak __start
    .balign 8
sp1_start_ptr:
    .dword __start

/* SP1's own halt, from libzkevm (the zkEVM SDK repackaged as the bindings
 * library). Weak for the same reason as __start, and taken through .data for
 * the same reason. */
.weak zkvm_halt
    .balign 8
sp1_halt_ptr:
    .dword zkvm_halt

/* Nethermind's KeccakHash reaches the permutation through
 * Accelerators.KeccakF, whose binding is named for ziskos: syscall_keccak_f.
 * SP1 spells the same operation zkvm_keccak_permute and OpenVM zkvm_keccakf -
 * the eth-act standard covers zkvm_keccak256 and defines no permutation at
 * all, so the name was never agreed on. Rather than make the managed side
 * target-aware, each target's entry-point module carries a tail call under
 * the name the binding uses.
 *
 * In its own section on purpose: --gc-sections then drops it, and the
 * reference to the bindings library with it, in a guest built without
 * --extlib. The ABI is identical everywhere - a0 points at the 25 u64 state
 * words - so this is a jump, not a thunk. */
.section .text.syscall_keccak_f,"ax",@progbits
.global syscall_keccak_f
.type   syscall_keccak_f, @function
syscall_keccak_f:
    .cfi_startproc
    tail    zkvm_keccak_permute
    .cfi_endproc
    .size   syscall_keccak_f, .-syscall_keccak_f

/* ------------------------------------------------------------------------
 * The platform interface of bflat's modules (docs/manifest.md in
 * bflat-riscv64, "Platform interface"). bflat's pal calls these; it holds no
 * code for any one zkVM. SP1 defines no zkvm_platform_syscall: it has no
 * Linux syscalls, so pal's syscall fails instead.
 * ------------------------------------------------------------------------ */

/* SHA-256 of the empty byte string, as the eight little-endian u32 words
 * SP1's syscall_halt commits before halting. SP1 hashes everything the guest
 * writes to FD_PUBLIC_VALUES and commits the digest; without the bindings
 * library nothing can write that descriptor (write_output lives in libzkevm;
 * console output goes to fd 1), so the stream is empty and its digest is
 * constant. Any future code path that writes public values without libzkevm
 * would invalidate it: the proof would carry a digest that does not match its
 * public values. Execution is unaffected either way; only proving is. */
.section .rodata.sp1_empty_pv_digest,"a",@progbits
    .balign 4
sp1_empty_pv_digest:
    .word 0x42c4b0e3, 0x141cfc98, 0xc8f4fb9a, 0x24b96f99
    .word 0xe441ae27, 0x4c939b64, 0x1b9995a4, 0x55b85278

/* zkvm_platform_exit(long code): SP1 halts on its HALT syscall, and expects
 * the public-values and deferred-proof digests committed first. That commit
 * has to hash whatever the guest wrote to FD_PUBLIC_VALUES, so it belongs to
 * whoever owns write_output - libzkevm - and this hands over to its zkvm_halt
 * when it is linked. The open-coded sequence is the fallback for a guest
 * built without the bindings library: the digest of the empty stream, eight
 * zero words of deferred proofs (this guest verifies none, but SP1's own
 * entrypoint commits the eight words unconditionally), then HALT with the
 * low byte of the code. It never returns, so it keeps its state in s1-s3. */
.section .text.zkvm_platform_exit,"ax",@progbits
.global zkvm_platform_exit
.type   zkvm_platform_exit, @function
zkvm_platform_exit:
    .cfi_startproc
    andi    s1, a0, 0xff     # the exit code SP1 takes: one byte
    la      t1, sp1_halt_ptr
    ld      t1, 0(t1)
    beqz    t1, 1f
    mv      a0, s1
    jalr    t1               # zkvm_halt(code): commits and halts
1:  la      s2, sp1_empty_pv_digest
    li      s3, 0
2:  li      t0, SP1_COMMIT
    mv      a0, s3           # word index
    lwu     a1, 0(s2)        # word value
    ecall
    addi    s2, s2, 4
    addi    s3, s3, 1
    li      t1, 8
    blt     s3, t1, 2b
    li      s3, 0
3:  li      t0, SP1_COMMIT_DEFERRED_PROOFS
    mv      a0, s3
    li      a1, 0
    ecall
    addi    s3, s3, 1
    li      t1, 8
    blt     s3, t1, 3b
    li      t0, SP1_HALT
    mv      a0, s1
    ecall
4:  j       4b               # HALT ends the program; loop is just in case
    .cfi_endproc
    .size   zkvm_platform_exit, .-zkvm_platform_exit

/* zkvm_platform_write(int fd, const char *buf, int len): the WRITE syscall,
 * which prints descriptors 1 and 2 on the host and warns about any other
 * (sp1/crates/core/executor/src/minimal/write.rs), so the descriptor is
 * passed straight through. pal calls it only with len > 0. */
.section .text.zkvm_platform_write,"ax",@progbits
.global zkvm_platform_write
.type   zkvm_platform_write, @function
zkvm_platform_write:
    .cfi_startproc
    li      t0, SP1_WRITE    # a0 = fd, a1 = buf, a2 = len
    ecall
    ret
    .cfi_endproc
    .size   zkvm_platform_write, .-zkvm_platform_write

.section .text.init
.global _start
    .cfi_sections .eh_frame
_start:
    .cfi_startproc
    .cfi_def_cfa sp, 0
    .cfi_undefined ra
    .option push
    .option norelax
    la      gp, _global_pointer
    .option pop
    la      sp, _init_stack_top

    /* Enter through SP1's own runtime entry (sp1-zkvm __start, exported by
     * the bindings library): it initialises the Rust allocator and the
     * public-values hasher that syscall_write / syscall_halt depend on, calls
     * main() and halts with main's return value through the full commit
     * protocol. Bypassing it left both uninitialised: the first Rust
     * allocation in the bindings failed and write_output faulted.
     *
     * WEAK, because a guest built without --extlib links no bindings library
     * and has no __start at all - the sample guests in CI are exactly that.
     * There is nothing to initialise in that case (the Rust allocator and the
     * public-values stream both live in the bindings), so the fallback enters
     * the .NET start-up directly, and its exit reaches zkvm_platform_exit
     * above, which keeps the open-coded commit-and-halt sequence for this
     * case.
     *
     * The address is taken through a word in .data rather than `la`: a
     * PC-relative reference to an undefined weak symbol resolves to absolute
     * 0 and overflows the auipc/addi pair. */
    la      t0, sp1_start_ptr
    ld      t0, 0(t0)
    beqz    t0, 2f
    jalr    t0
    # Unreachable: __start never returns. Kept as a backstop - a bare HALT
    # ecall (syscall id in t0, exit code in a0).
    li      t0, 0            # SP1 HALT
    li      a0, 0
    ecall
1:  j       1b               # loop forever
2:  /* No bindings library: uBootstrap_main is reached the way OpenVM reaches
     * it, and termination goes through pal into zkvm_platform_exit. */
    li      a0, 1            # argc = 1
    la      a1, argv_vec     # argv = &argv_vec[0]
    call    noos_start_main
3:  j       3b               # noos_start_main never returns
    .cfi_endproc
    .size   _start, .-_start

/* main(), as SP1's __start calls it: extern "C" fn main() -> i32. The .NET
 * side of the start-up (thread pointer, .init_array, uBootstrap_main) is
 * noos_main, the returning half of noos_start_main. Reached through
 * --wrap=main (declared in sp1.bflat.manifest): libbootstrapper.o also
 * defines a main, the desktop runtime's, which a zkVM guest never enters. */
.section .text.__wrap_main,"ax",@progbits
.global __wrap_main
.type   __wrap_main, @function
__wrap_main:
    .cfi_startproc
    addi    sp, sp, -16
    .cfi_adjust_cfa_offset 16
    sd      ra, 8(sp)
    .cfi_rel_offset ra, 8
    li      a0, 1            # argc = 1
    la      a1, argv_vec     # argv = &argv_vec[0]
    call    noos_main
    ld      ra, 8(sp)
    addi    sp, sp, 16
    .cfi_adjust_cfa_offset -16
    ret
    .cfi_endproc
    .size   __wrap_main, .-__wrap_main

/* void *__wrap_memcpy(void *dst, const void *src, size_t n), reached through
 * --wrap=memcpy (declared in sp1.bflat.manifest).
 *
 * musl's generic C memcpy moves 32-bit words and merges a misaligned source
 * with 32-bit shifts. SP1 has no DMA copy, so every byte costs instructions,
 * and a guest's copies mostly come from an unaligned source (data decoded out
 * of the input). This aligns the destination, then moves 64-bit words,
 * merging a misaligned source from the aligned words that hold it. SP1
 * rejects misaligned loads and stores, so every access is a byte or a
 * naturally aligned half, word or doubleword; reading a whole aligned word
 * that holds a needed byte never reaches past the source's last word.
 *
 * Weak so a guest that still links its own __wrap_memcpy keeps it rather than
 * failing the link on a duplicate definition. */
.section .text.__wrap_memcpy,"ax",@progbits
.weak   __wrap_memcpy
.type   __wrap_memcpy, @function
.p2align 2
__wrap_memcpy:
    .cfi_startproc
    mv      t6, a0
    li      t0, 16
    bltu    a2, t0, .Lbytes

    andi    t0, t6, 7
    beqz    t0, .Ldst_aligned
    li      t1, 8
    sub     t0, t1, t0
    sub     a2, a2, t0
.Lhead:
    lbu     t1, 0(a1)
    sb      t1, 0(t6)
    addi    a1, a1, 1
    addi    t6, t6, 1
    addi    t0, t0, -1
    bnez    t0, .Lhead

.Ldst_aligned:
    andi    t0, a1, 7
    bnez    t0, .Lsrc_misaligned

    li      t1, 64
    bltu    a2, t1, .Lhalf
.Lblocks:
    ld      t2, 0(a1)
    ld      t3, 8(a1)
    ld      t4, 16(a1)
    ld      t5, 24(a1)
    ld      a4, 32(a1)
    ld      a5, 40(a1)
    ld      a6, 48(a1)
    ld      a7, 56(a1)
    sd      t2, 0(t6)
    sd      t3, 8(t6)
    sd      t4, 16(t6)
    sd      t5, 24(t6)
    sd      a4, 32(t6)
    sd      a5, 40(t6)
    sd      a6, 48(t6)
    sd      a7, 56(t6)
    addi    a1, a1, 64
    addi    t6, t6, 64
    addi    a2, a2, -64
    bgeu    a2, t1, .Lblocks
.Lhalf:
    li      t1, 32
    bltu    a2, t1, .Lwords
    ld      t2, 0(a1)
    ld      t3, 8(a1)
    ld      t4, 16(a1)
    ld      t5, 24(a1)
    sd      t2, 0(t6)
    sd      t3, 8(t6)
    sd      t4, 16(t6)
    sd      t5, 24(t6)
    addi    a1, a1, 32
    addi    t6, t6, 32
    addi    a2, a2, -32
.Lwords:
    li      t1, 8
    bltu    a2, t1, .Lword_tail
.Lword:
    ld      t2, 0(a1)
    sd      t2, 0(t6)
    addi    a1, a1, 8
    addi    t6, t6, 8
    addi    a2, a2, -8
    bgeu    a2, t1, .Lword
.Lword_tail:
    beqz    a2, .Ldone
    ld      t2, 0(a1)
    j       .Ltail

    /* t0 = src & 7. Each destination word is the high bytes of one aligned
     * source word and the low bytes of the next: t3 and t4 are the two
     * shifts, a3 walks the aligned source, t2 holds its word. Unrolled to
     * 64 bytes because the merge is most of a guest's copying (decoding
     * the input), and the loop's own four instructions were a fifth of it. */
.Lsrc_misaligned:
    slli    t3, t0, 3
    li      t4, 64
    sub     t4, t4, t3
    andi    a3, a1, -8
    ld      t2, 0(a3)
    li      t1, 64
    bltu    a2, t1, .Lmerge_pairs
.Lmerge_block:
    ld      t5, 8(a3)
    srl     a4, t2, t3
    sll     a5, t5, t4
    or      a4, a4, a5
    sd      a4, 0(t6)
    ld      t2, 16(a3)
    srl     a4, t5, t3
    sll     a5, t2, t4
    or      a4, a4, a5
    sd      a4, 8(t6)
    ld      t5, 24(a3)
    srl     a4, t2, t3
    sll     a5, t5, t4
    or      a4, a4, a5
    sd      a4, 16(t6)
    ld      t2, 32(a3)
    srl     a4, t5, t3
    sll     a5, t2, t4
    or      a4, a4, a5
    sd      a4, 24(t6)
    ld      t5, 40(a3)
    srl     a4, t2, t3
    sll     a5, t5, t4
    or      a4, a4, a5
    sd      a4, 32(t6)
    ld      t2, 48(a3)
    srl     a4, t5, t3
    sll     a5, t2, t4
    or      a4, a4, a5
    sd      a4, 40(t6)
    ld      t5, 56(a3)
    srl     a4, t2, t3
    sll     a5, t5, t4
    or      a4, a4, a5
    sd      a4, 48(t6)
    ld      t2, 64(a3)
    srl     a4, t5, t3
    sll     a5, t2, t4
    or      a4, a4, a5
    sd      a4, 56(t6)
    addi    a3, a3, 64
    addi    t6, t6, 64
    addi    a2, a2, -64
    bgeu    a2, t1, .Lmerge_block
.Lmerge_pairs:
    li      t1, 16
    bltu    a2, t1, .Lmerge_word
.Lmerge_pair:
    ld      t5, 8(a3)
    srl     a4, t2, t3
    sll     a5, t5, t4
    or      a4, a4, a5
    sd      a4, 0(t6)
    ld      t2, 16(a3)
    srl     a4, t5, t3
    sll     a5, t2, t4
    or      a4, a4, a5
    sd      a4, 8(t6)
    addi    a3, a3, 16
    addi    t6, t6, 16
    addi    a2, a2, -16
    bgeu    a2, t1, .Lmerge_pair
.Lmerge_word:
    li      t1, 8
    bltu    a2, t1, .Lmerge_done
    ld      t5, 8(a3)
    srl     a4, t2, t3
    sll     a5, t5, t4
    or      a4, a4, a5
    sd      a4, 0(t6)
    mv      t2, t5
    addi    a3, a3, 8
    addi    t6, t6, 8
    addi    a2, a2, -8
.Lmerge_done:
    beqz    a2, .Ldone
    srl     t2, t2, t3
    add     t1, t0, a2
    li      t5, 8
    bleu    t1, t5, .Ltail
    ld      t5, 8(a3)
    sll     t5, t5, t4
    or      t2, t2, t5

    /* The destination is word-aligned and the last 1-7 bytes are the low
     * bytes of t2, so they go out as at most a word, a half and a byte. */
.Ltail:
    andi    t1, a2, 4
    beqz    t1, 1f
    sw      t2, 0(t6)
    srli    t2, t2, 32
    addi    t6, t6, 4
1:  andi    t1, a2, 2
    beqz    t1, 2f
    sh      t2, 0(t6)
    srli    t2, t2, 16
    addi    t6, t6, 2
2:  andi    t1, a2, 1
    beqz    t1, .Ldone
    sb      t2, 0(t6)
    ret

.Lbytes:
    beqz    a2, .Ldone
.Lbyte:
    lbu     t1, 0(a1)
    sb      t1, 0(t6)
    addi    a1, a1, 1
    addi    t6, t6, 1
    addi    a2, a2, -1
    bnez    a2, .Lbyte
.Ldone:
    ret
    .cfi_endproc
    .size   __wrap_memcpy, .-__wrap_memcpy

/* void *__wrap_memmove(void *dst, const void *src, size_t n), reached through
 * --wrap=memmove (declared in sp1.bflat.manifest).
 *
 * musl's memmove checks for overlap and tail-calls memcpy for almost every
 * call, and copies a misaligned overlap byte by byte. A destination below the
 * source, or past its end, is copied forward by __wrap_memcpy, which reads
 * every source word before storing over it. Only a destination inside the
 * source is copied backward, mirroring __wrap_memcpy: align the destination's
 * end, then move aligned doublewords, merging a misaligned source.
 *
 * Weak for the same reason as __wrap_memcpy. */
.section .text.__wrap_memmove,"ax",@progbits
.weak   __wrap_memmove
.type   __wrap_memmove, @function
.p2align 2
__wrap_memmove:
    .cfi_startproc
    sub     t0, a0, a1
    bltu    t0, a2, .Lmove_backward
    tail    __wrap_memcpy

    /* dst - src < n, so n > 0. t6 and a1 walk down from the ends of the
     * destination and source. */
.Lmove_backward:
    add     t6, a0, a2
    add     a1, a1, a2
    li      t0, 16
    bltu    a2, t0, .Lmove_bytes

    andi    t0, t6, 7
    beqz    t0, .Lmove_dst_aligned
    sub     a2, a2, t0
.Lmove_head:
    addi    a1, a1, -1
    addi    t6, t6, -1
    lbu     t1, 0(a1)
    sb      t1, 0(t6)
    addi    t0, t0, -1
    bnez    t0, .Lmove_head

.Lmove_dst_aligned:
    andi    t0, a1, 7
    bnez    t0, .Lmove_src_misaligned

    li      t1, 32
    bltu    a2, t1, .Lmove_words
.Lmove_blocks:
    ld      t2, -8(a1)
    ld      t3, -16(a1)
    ld      t4, -24(a1)
    ld      t5, -32(a1)
    sd      t2, -8(t6)
    sd      t3, -16(t6)
    sd      t4, -24(t6)
    sd      t5, -32(t6)
    addi    a1, a1, -32
    addi    t6, t6, -32
    addi    a2, a2, -32
    bgeu    a2, t1, .Lmove_blocks
.Lmove_words:
    li      t1, 8
    bltu    a2, t1, .Lmove_bytes
.Lmove_word:
    ld      t2, -8(a1)
    sd      t2, -8(t6)
    addi    a1, a1, -8
    addi    t6, t6, -8
    addi    a2, a2, -8
    bgeu    a2, t1, .Lmove_word
    j       .Lmove_bytes

    /* t0 = src end & 7. Each destination word is the low bytes of one aligned
     * source word and the high bytes of the one below it: t3 and t4 are the
     * two shifts, a3 walks the aligned source down, t2 holds its word. */
.Lmove_src_misaligned:
    slli    t3, t0, 3
    li      t4, 64
    sub     t4, t4, t3
    andi    a3, a1, -8
    ld      t2, 0(a3)
    li      t1, 16
    bltu    a2, t1, .Lmove_merge_word
.Lmove_merge_pair:
    ld      t5, -8(a3)
    sll     a4, t2, t4
    srl     a5, t5, t3
    or      a4, a4, a5
    sd      a4, -8(t6)
    ld      t2, -16(a3)
    sll     a4, t5, t4
    srl     a5, t2, t3
    or      a4, a4, a5
    sd      a4, -16(t6)
    addi    a3, a3, -16
    addi    t6, t6, -16
    addi    a2, a2, -16
    bgeu    a2, t1, .Lmove_merge_pair
.Lmove_merge_word:
    li      t1, 8
    bltu    a2, t1, .Lmove_merge_done
    ld      t5, -8(a3)
    sll     a4, t2, t4
    srl     a5, t5, t3
    or      a4, a4, a5
    sd      a4, -8(t6)
    addi    a3, a3, -8
    addi    t6, t6, -8
    addi    a2, a2, -8
.Lmove_merge_done:
    add     a1, a3, t0

.Lmove_bytes:
    beqz    a2, .Lmove_done
.Lmove_byte:
    addi    a1, a1, -1
    addi    t6, t6, -1
    lbu     t1, 0(a1)
    sb      t1, 0(t6)
    addi    a2, a2, -1
    bnez    a2, .Lmove_byte
.Lmove_done:
    ret
    .cfi_endproc
    .size   __wrap_memmove, .-__wrap_memmove

/* void *__wrap_memset(void *dst, int c, size_t n), reached through
 * --wrap=memset (declared in sp1.bflat.manifest).
 *
 * musl's memset stores 32-bit words before its 64-bit loop. This aligns the
 * destination, since SP1 rejects misaligned stores, then stores doublewords,
 * 32 bytes per iteration.
 *
 * Weak for the same reason as __wrap_memcpy. */
.section .text.__wrap_memset,"ax",@progbits
.weak   __wrap_memset
.type   __wrap_memset, @function
.p2align 2
__wrap_memset:
    .cfi_startproc
    mv      t6, a0
    andi    a1, a1, 0xff
    li      t0, 16
    bltu    a2, t0, .Lset_bytes

    /* Most fills are zero, which needs no broadcast. */
    beqz    a1, .Lset_broadcast_done
    slli    t1, a1, 8
    or      a1, a1, t1
    slli    t1, a1, 16
    or      a1, a1, t1
    slli    t1, a1, 32
    or      a1, a1, t1
.Lset_broadcast_done:
    neg     t0, t6
    andi    t0, t0, 7
    beqz    t0, .Lset_aligned
    sub     a2, a2, t0
.Lset_head:
    sb      a1, 0(t6)
    addi    t6, t6, 1
    addi    t0, t0, -1
    bnez    t0, .Lset_head

.Lset_aligned:
    li      t1, 32
    bltu    a2, t1, .Lset_words
.Lset_blocks:
    sd      a1, 0(t6)
    sd      a1, 8(t6)
    sd      a1, 16(t6)
    sd      a1, 24(t6)
    addi    t6, t6, 32
    addi    a2, a2, -32
    bgeu    a2, t1, .Lset_blocks
.Lset_words:
    li      t1, 8
    bltu    a2, t1, .Lset_bytes
.Lset_word:
    sd      a1, 0(t6)
    addi    t6, t6, 8
    addi    a2, a2, -8
    bgeu    a2, t1, .Lset_word

.Lset_bytes:
    beqz    a2, .Lset_done
.Lset_byte:
    sb      a1, 0(t6)
    addi    t6, t6, 1
    addi    a2, a2, -1
    bnez    a2, .Lset_byte
.Lset_done:
    ret
    .cfi_endproc
    .size   __wrap_memset, .-__wrap_memset
