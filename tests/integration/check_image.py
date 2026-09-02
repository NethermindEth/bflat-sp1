#!/usr/bin/env python3
"""Check a linked zkVM guest image against what the target can actually load.

Two things no amount of inspecting the static archive can tell you: whether the
accelerators survived --gc-sections into the image, and whether anything the
prebuilt musl/runtime blobs dragged in is undecodable for this VM. Both are
properties of the linked ELF, so they are checked here.
"""
import argparse
import collections
import re
import subprocess
import sys

WORD = re.compile(r"^\s+[0-9a-f]+:\s+([0-9a-f]{8})\s")
SYM = re.compile(r"^[0-9a-f]+ <(.+)>:")

# RISC-V major opcodes, low 7 bits.
OP_CUSTOM0 = 0x0B     # OpenVM: keccak, sha2, u256
OP_CUSTOM1 = 0x2B     # OpenVM: algebra, ecc
OP_AMO = 0x2F         # A extension: lr/sc/amo*


def scan(objdump, elf):
    """Count opcodes in the image, and remember which symbol each landed in."""
    out = subprocess.run([objdump, "-d", elf], capture_output=True, text=True, check=True).stdout
    counts = collections.Counter()
    by_symbol = collections.defaultdict(collections.Counter)
    sym = "?"
    for line in out.splitlines():
        m = SYM.match(line)
        if m:
            sym = m.group(1)
            continue
        m = WORD.match(line)
        if m:
            op = int(m.group(1), 16) & 0x7F
            counts[op] += 1
            by_symbol[op][sym] += 1
    return counts, by_symbol


def segments(readelf, elf):
    """PT_LOAD (vaddr, flags) pairs. readelf writes flags as up to three
    space-separated letters, so the trailing align field is the only reliable
    anchor for where they end."""
    out = subprocess.run([readelf, "-lW", elf], capture_output=True, text=True, check=True).stdout
    loads = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 8 or f[0] != "LOAD":
            continue
        # LOAD offset vaddr paddr filesz memsz <flags...> align
        loads.append((int(f[2], 16), "".join(f[6:-1])))
    return loads


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--objdump", default="riscv64-linux-gnu-objdump")
    ap.add_argument("--readelf", default="riscv64-linux-gnu-readelf")
    ap.add_argument("--require-custom", action="store_true",
                    help="OpenVM: require custom-0 and custom-1 instructions")
    ap.add_argument("--no-atomics", action="store_true",
                    help="fail if the image contains A-extension instructions")
    ap.add_argument("--sp1-segments", action="store_true",
                    help="check PT_LOADs against SP1's loader rules")
    args = ap.parse_args()

    counts, by_symbol = scan(args.objdump, args.elf)
    print(f"custom-0 (keccak/sha2/u256): {counts[OP_CUSTOM0]}")
    print(f"custom-1 (algebra/ecc)     : {counts[OP_CUSTOM1]}")
    print(f"A extension (lr/sc/amo)    : {counts[OP_AMO]}")

    failures = []

    if args.require_custom:
        if not counts[OP_CUSTOM0]:
            failures.append("no custom-0 instructions: the hash accelerators did not reach the image")
        if not counts[OP_CUSTOM1]:
            failures.append("no custom-1 instructions: the curve accelerators did not reach the image")

    if counts[OP_AMO]:
        print("\nA-extension instructions by symbol:")
        for sym, n in by_symbol[OP_AMO].most_common(20):
            print(f"  {n:5d}  {sym}")
        if args.no_atomics:
            failures.append(f"{counts[OP_AMO]} A-extension instructions in the image")

    if args.sp1_segments:
        print("\nPT_LOAD segments:")
        for vaddr, flags in segments(args.readelf, args.elf):
            print(f"  0x{vaddr:016x}  {flags}")
            # SP1's loader rejects each of these outright.
            if vaddr < 0x78000000:
                failures.append(f"0x{vaddr:x}: below STACK_TOP")
            if "R" not in flags:
                failures.append(f"0x{vaddr:x}: not readable ({flags})")
            if "W" in flags and "E" in flags:
                failures.append(f"0x{vaddr:x}: writable and executable ({flags})")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  {f}")
        return 1
    print("\nimage OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
