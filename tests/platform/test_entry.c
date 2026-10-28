/**
 * @file
 * @brief Unit tests for the _start bootstrap in platform/entry.S
 *        (run.sh builds and runs them under qemu-user).
 *
 * _start is the guest's very first instruction: it points gp/sp at the
 * linker-script symbols and then hands control to the start-up routine.
 * On SP1, _start calls SP1's own runtime entry, __start(), which initialises the
 * Rust allocator and the public-values hasher and then calls main(); main is
 * the __wrap_main of entry.S, which calls noos_main(argc, argv) and RETURNS
 * its value, because SP1 halts with it. A guest without the bindings library
 * has no __start (the reference is weak), and _start falls back to
 * noos_start_main(argc, argv).
 *
 * The tests moved here from bflat-riscv64 (src/bflat/modules/tests) with the
 * entry point; the start-up stubs of the other shapes stay, unused.
 *
 * The linker symbols _start dereferences are supplied here as real arrays
 * via --defsym, and every routine it calls is a stub that records what it
 * was handed. _start never returns, so those cases run in a forked child
 * and the verdict travels back as the exit status.
 *
 * Copyright (C) 2026 Demerzel Solutions Limited (Nethermind)
 */
#include <inttypes.h>
#include <string.h>

#include "common.h"

/* Guest stack and global-pointer anchor; run.sh --defsym's
 * _init_stack_top / _global_pointer to the ends of these. */
uint8_t zkvm_test_stack[64 * 1024] __attribute__((aligned(16)));
uint8_t zkvm_test_gp[4096] __attribute__((aligned(16)));

/* run.sh objcopy-renames the module's _start and its call to
 * __libc_start_main, which would otherwise collide with crt1.o and libc
 * in this hosted test binary. */
extern void zkvm_module_start(void);
extern int uBootstrap_main(int argc, char *argv[]);

/* Exit codes carrying the verdict out of the child. */
#define OK 0
#define BAD_ENTRY 21
#define BAD_ARGC 22
#define BAD_ARGV0 23
#define BAD_ARGV_TERM 24
#define BAD_STACK 25
#define BAD_GP 26
#define BAD_ENVP 27
#define BAD_AUXV 28

/* Current sp/gp. _start loads both from the linker symbols, so every
 * start-up stub is entered with them already pointing at the arrays
 * above; reading them back is how the test sees what _start did. */
static inline uintptr_t read_sp(void)
{
    uintptr_t v;
    __asm__ volatile("mv %0, sp" : "=r"(v));
    return v;
}

static inline uintptr_t read_gp(void)
{
    uintptr_t v;
    __asm__ volatile("mv %0, gp" : "=r"(v));
    return v;
}

/* sp must sit inside the array _init_stack_top points past the end of.
 * Accept anything within it: the callee's prologue may have pushed a
 * frame already. */
static int stack_ok(uintptr_t sp)
{
    return sp > (uintptr_t)zkvm_test_stack &&
           sp <= (uintptr_t)zkvm_test_stack + sizeof(zkvm_test_stack);
}

static int gp_ok(uintptr_t gp)
{
    return gp == (uintptr_t)zkvm_test_gp;
}

/* argv as the module builds it: exactly one entry, "app", NULL-terminated
 * for the runtime. */
static int argv_verdict(long argc, char **argv)
{
    if (argc != 1)
        return BAD_ARGC;
    if (argv == NULL || argv[0] == NULL || strcmp(argv[0], "app") != 0)
        return BAD_ARGV0;
    if (argv[1] != NULL)
        return BAD_ARGV_TERM;
    return OK;
}

/* uBootstrap_main is only referenced (its ADDRESS is passed on); it must
 * never actually run in this test. */
int uBootstrap_main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    _exit(99);
}

/* Stand-in for musl's __libc_start_main (zisk, zisk_sim): validates the
 * handoff, including the envp/auxv musl derives from argv, and exits. Signature per the riscv64 call in _start:
 *   a0 = main, a1 = argc, a2 = argv, a3..a5 = 0, a6 = stack end */
int test_libc_start_main(int (*main_fn)(int, char **), long argc,
                         char **argv, void (*init)(void), void (*fini)(void),
                         void (*rtld_fini)(void), void *stack_end)
{
    (void)init;
    (void)fini;
    (void)rtld_fini;

    if (main_fn != uBootstrap_main)
        _exit(BAD_ENTRY);
    if (argv_verdict(argc, argv) != OK)
        _exit(argv_verdict(argc, argv));

    /* musl takes envp at argv + argc + 1 and auxv after envp's NULL, so
     * both must be terminated inside the module's vector: an empty envp
     * and an AT_NULL auxv pair. */
    char **envp = argv + argc + 1;
    if (envp[0] != NULL)
        _exit(BAD_ENVP);
    uintptr_t *auxv = (uintptr_t *)(envp + 1);
    if (auxv[0] != 0 || auxv[1] != 0)
        _exit(BAD_AUXV);

    if (!gp_ok(read_gp()))
        _exit(BAD_GP);

    /* sp was repointed at the guest stack before the call, and a6 carries
     * it through. */
    if (!stack_ok((uintptr_t)stack_end))
        _exit(BAD_STACK);

    _exit(OK);
}

/* Stand-in for noos_start_main (openvm): the noreturn half of the .NET
 * start-up. _start passes argc/argv and nothing else - sp and gp are read
 * back from the registers. */
void noos_start_main(int argc, char *argv[])
{
    int verdict = argv_verdict(argc, argv);

    if (verdict != OK)
        _exit(verdict);
    if (!gp_ok(read_gp()))
        _exit(BAD_GP);
    if (!stack_ok(read_sp()))
        _exit(BAD_STACK);

    _exit(OK);
}

/* Stand-in for sp1-zkvm's __start: SP1's runtime entry, called by _start
 * with no arguments. It is the allocator/hasher set-up that the guest
 * must not bypass; all the test can check is that _start handed it a
 * working sp/gp. The real one calls main(); the __wrap_main leg below
 * covers that half.
 *
 * Left UNDEFINED in the ZKVM_ENTRY_SP1_NOBIND build, which is the guest
 * built without --extlib: __start lives in the bindings library, so the
 * module's reference to it is weak and _start must fall back to
 * noos_start_main rather than fail the link. That fallback is what this
 * second binary exercises. */
#ifndef ZKVM_ENTRY_SP1_NOBIND
void __start(void)
{
    if (!gp_ok(read_gp()))
        _exit(BAD_GP);
    if (!stack_ok(read_sp()))
        _exit(BAD_STACK);

    _exit(OK);
}
#endif /* !ZKVM_ENTRY_SP1_NOBIND */

/* Stand-in for noos_main (sp1): the RETURNING half of the .NET start-up.
 * Called from the module's __wrap_main, in-process, so it records rather
 * than exits - the test then checks that __wrap_main passed the value
 * back, which is what SP1 halts with. */
#define NOOS_MAIN_RESULT 77
static volatile int noos_main_verdict = -1;

int noos_main(int argc, char *argv[])
{
    noos_main_verdict = argv_verdict(argc, argv);
    return NOOS_MAIN_RESULT;
}

extern int __wrap_main(void);

/* The platform interface (the functions bflat's pal calls). */
extern void zkvm_platform_exit(long code);

#ifndef ZKVM_ENTRY_SP1_NOBIND
/* libzkevm's zkvm_halt, which owns the commit-and-halt sequence when the
 * bindings library is linked: the child exits with the code it is handed.
 * Without the bindings library (the nobind build) zkvm_platform_exit issues
 * SP1's own syscalls, which qemu-user cannot run. */
void zkvm_halt(unsigned char exit_code)
{
    _exit(exit_code);
}
#endif

int main(void)
{
    /* One shot: _start clobbers sp/gp and never returns, so it only runs
     * in the child. Any verdict other than OK surfaces as its own code. */
    EXPECT_EXIT(OK, zkvm_module_start());

#ifndef ZKVM_ENTRY_SP1_NOBIND
    /* zkvm_platform_exit hands over to zkvm_halt, with the one byte of exit
     * code that SP1 takes. */
    EXPECT_EXIT(42, zkvm_platform_exit(42));
    EXPECT_EXIT(0x2a, zkvm_platform_exit(0x12a));
#endif

    /* main() as SP1's __start calls it: no arguments, and the guest's
     * exit code comes back through the return value. */
    CHECK(__wrap_main() == NOOS_MAIN_RESULT);
    CHECK(noos_main_verdict == OK);

    TEST_MAIN_END(ZKVM_MODULE_NAME);
}
