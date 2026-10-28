#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Differential test of src/modexp/modexp.c against Python's pow, with EIP-198 semantics.

Builds tests/modexp/harness.c for the host (CC, default cc) on an emulated UINT256_MUL and checks:
  - moduli up to 256 significant bits give pow(base, exp, modulus) as exactly len(modulus) bytes,
    and never reach the SDK;
  - wider moduli, leading zeros aside, go to the SDK untouched;
  - zero and one moduli, empty operands, zero exponents, bases longer than and multiples of the
    modulus, exponents on both sides of the binary/window switch.

    test_modexp.py [--seed N] [--random N]
    test_modexp.py --sp1-vectors FILE    write the vectors for tests/accelerators/guest.cs to FILE
                                         and print the output the guest must commit, then exit
"""

import argparse
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "common"))
from keccak import keccak256  # noqa: E402

# A BN254 base-field prime and its p - 2: the inversion zk verifiers send through 0x05.
BN254_P = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47


def reference(base, exp, modulus):
    """The 0x05 output for these operands: len(modulus) bytes."""
    m = int.from_bytes(modulus, "big")
    if m == 0:
        return bytes(len(modulus))
    r = pow(int.from_bytes(base, "big"), int.from_bytes(exp, "big"), m)
    return r.to_bytes(len(modulus), "big")


def width(modulus):
    return len(modulus.lstrip(b"\x00"))


def be(v, n):
    return v.to_bytes(n, "big")


def vectors(rng, count):
    p = be(BN254_P, 32)
    yield be(rng.randrange(BN254_P), 32), be(BN254_P - 2, 32), p
    yield be(rng.randrange(BN254_P), 32), be((BN254_P - 1) // 2, 32), p
    yield b"", b"", b""
    yield b"\x02", b"\x03", b""
    yield b"", b"", b"\x05"
    yield b"\x00", b"\x00", b"\x07"
    yield b"\x07", b"", b"\x0b"
    yield b"\x07", b"\x00\x00\x00", b"\x00\x0b"
    yield b"\x00", b"\x05", b"\x0b"
    yield b"\x05", b"\x01", b"\x01"
    yield b"\x05", b"\x01", b"\x00\x00\x01"
    yield b"\x05", b"\x01", b"\x00\x00"
    yield b"\xff" * 32, b"\xff" * 32, b"\xff" * 32
    yield b"\xff" * 64, b"\x02", b"\xff" * 32
    yield be(BN254_P * 5, 33), b"\x09", p
    yield be(BN254_P, 32), b"\x09", p
    yield be(BN254_P + 1, 32), be(2**255, 32), p
    yield b"\x03", b"\x01" + bytes(299), p
    yield b"\x03", b"\xff" * 8, be(2**64 - 59, 8)
    yield b"\x03", b"\xff" * 9, be(2**64 - 59, 8)
    # Leading zeros on a 256-bit modulus stay in the fast path; a 257-bit one falls back.
    yield b"\x02", b"\x05", bytes(10) + p
    yield b"\x02", b"\x05", b"\x01" + bytes(32)
    yield b"\x02", b"\x05", bytes(3) + b"\x01" + bytes(32)
    yield b"\x02", b"\x05", b"\x01" * 256
    for _ in range(count):
        mod_len = rng.choice([1, 2, 7, 8, 9, 16, 31, 32, 32, 32, 33, 40, 64])
        modulus = be(rng.randrange(2 ** (8 * mod_len)), mod_len)
        if rng.random() < 0.2:
            modulus = bytes(rng.randrange(1, 6)) + modulus
        if rng.random() < 0.3:
            modulus = modulus[:-1] + bytes([modulus[-1] | 1])
        base_len = rng.choice([0, 1, 5, 31, 32, 33, 63, 64, 65, 100])
        exp_len = rng.choice([0, 1, 2, 8, 9, 16, 32, 32, 33, 64])
        base = be(rng.randrange(2 ** (8 * base_len)), base_len)
        exp = be(rng.randrange(2 ** (8 * exp_len)), exp_len)
        if rng.random() < 0.2:
            exp = bytes(rng.randrange(1, 4)) + exp
        yield base, exp, modulus


def build(workdir):
    cc = os.environ.get("CC", "cc")
    exe = Path(workdir) / "harness"
    subprocess.run([cc, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(exe), str(HERE / "harness.c")],
                   check=True)
    return exe


def hexarg(b):
    return b.hex() if b else "-"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--random", type=int, default=3000)
    parser.add_argument("--sp1-vectors", type=Path)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    cases = list(vectors(rng, args.random))
    if args.sp1_vectors:
        write_sp1_vectors(cases, args.sp1_vectors)
        return

    with tempfile.TemporaryDirectory() as workdir:
        exe = build(workdir)
        commands = "".join(f"modexp {hexarg(b)} {hexarg(e)} {hexarg(m)}\n" for b, e, m in cases)
        result = subprocess.run([str(exe)], input=commands, capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f"harness failed ({result.returncode}): {result.stderr.strip()}")
        failures, fast, inversion = 0, 0, None
        for (b, e, m), line in zip(cases, result.stdout.splitlines()):
            fields = line.split()
            if fields[0] != "ok":
                failures += 1
                print(f"FAILED base={b.hex()} exp={e.hex()} mod={m.hex()}")
                continue
            got = b"" if fields[1] == "-" else bytes.fromhex(fields[1])
            mulmods, fallback = int(fields[2]), int(fields[3])
            if width(m) > 32:
                if fallback != 1 or mulmods != 0:
                    failures += 1
                    print(f"NOT DELEGATED mod={m.hex()}: fallback={fallback} mulmods={mulmods}")
                continue
            fast += 1
            if fallback or got != reference(b, e, m):
                failures += 1
                print(f"MISMATCH base={b.hex()} exp={e.hex()} mod={m.hex()}\n"
                      f"  got  {got.hex()}\n  want {reference(b, e, m).hex()}")
            if inversion is None:
                inversion = mulmods
        print(f"BN254 inversion (256-bit p - 2): {inversion} UINT256_MUL calls")
        print(f"{len(cases)} vectors, {fast} in the fast path: {'FAILED' if failures else 'OK'} ({failures} failures)")
        sys.exit(1 if failures else 0)


def write_sp1_vectors(cases, path):
    """Records (u32le base_len | u32le exp_len | u32le mod_len | base | exp | modulus) for the guest, which
    commits keccak256 over (ok | output) per record. Wide moduli are left out: the guest runs the real SDK."""
    data, results = bytearray(), bytearray()
    for b, e, m in cases:
        if width(m) > 32:
            continue
        data += len(b).to_bytes(4, "little") + len(e).to_bytes(4, "little") + len(m).to_bytes(4, "little") + b + e + m
        results += b"\x01" + reference(b, e, m)
    path.write_bytes(b"\x00" + bytes(data))
    print(keccak256(bytes(results)).hex())


if __name__ == "__main__":
    main()
