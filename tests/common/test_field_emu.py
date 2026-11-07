#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Check that field overlap validation does not compare unrelated C pointers."""

import os
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

with tempfile.TemporaryDirectory() as workdir:
    exe = Path(workdir) / "harness"
    subprocess.run([os.environ.get("CC", "cc"), "-O1", "-g", "-fsanitize=address,pointer-compare",
                    str(HERE.parent / "pairing" / "bn254_harness.c"), "-o", str(exe)], check=True)
    # G1 generator paired with G2 infinity exercises field ops on distinct stack objects.
    pair = (1).to_bytes(32, "big") + (2).to_bytes(32, "big") + bytes(128)
    env = dict(os.environ, ASAN_OPTIONS="detect_invalid_pointer_pairs=2")
    result = subprocess.run([str(exe)], input=f"pair {pair.hex()}\n", text=True,
                            capture_output=True, env=env, check=True)
    assert result.stdout.split()[:2] == ["ok", "1"], result.stdout
    print("field overlap sanitizer check: OK")
