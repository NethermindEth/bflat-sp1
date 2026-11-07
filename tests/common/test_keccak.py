#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT

import unittest
from keccak import keccak256


class KeccakTests(unittest.TestCase):
    def test_rate_boundaries(self):
        # Keccak-256 reference digests from PyCryptodome, not NIST SHA3-256.
        vectors = {
            0: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            134: "20926439d7d1663c4d224931643bb513f3ebf181ab353278b24399f518dc5f97",
            135: "29e3704feeca7fb9ba229f0fa04d9b36449cf3ad6e1d85d9cfff3a10df9abc3e",
            136: "3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9",
            270: "d1ba1135d558e48490db9c68601fc981e184cee873d98e3e62bc8ada3ff43017",
            271: "3bb611e98ca876adc01436a582979ecfd012389033aca7dbf76dcb424fe02a0c",
            272: "a8005c7a3125b6c3629b4181eca54d18721e41fef639718d205beb00b366ed7d",
        }
        for size, expected in vectors.items():
            with self.subTest(size=size):
                self.assertEqual(keccak256(bytes(size)).hex(), expected)


if __name__ == "__main__":
    unittest.main()
