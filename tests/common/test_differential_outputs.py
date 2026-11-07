#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""A successful harness exit must not hide missing differential-test results."""

import runpy
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

TESTS = Path(__file__).resolve().parents[1]


class DifferentialOutputTests(unittest.TestCase):
    def test_missing_results_fail(self):
        suites = (
            ("modexp/test_modexp.py", "vectors", [(b"", b"", b"")]),
            ("bn254/test_g1.py", "vectors", [(0, bytes(64), bytes(64))]),
            ("pairing/test_bn254_pairing.py", "cases", [(b"", ("ok", 1))]),
            ("kzg/test_kzg.py", "cases", [((bytes(48), bytes(32), bytes(32), bytes(48)), 1)]),
        )
        for suite, source, cases in suites:
            with self.subTest(suite=suite):
                main = runpy.run_path(str(TESTS / suite))["main"]
                with patch.dict(main.__globals__, {
                    source: lambda *args: cases,
                    "build": lambda workdir: Path(workdir) / "harness",
                }), patch("sys.argv", [suite]), patch("subprocess.run", return_value=
                    subprocess.CompletedProcess([], 0, stdout="", stderr="")):
                    with self.assertRaises(ValueError):
                        main()


if __name__ == "__main__":
    unittest.main()
