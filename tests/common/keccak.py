# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Keccak-256 (the pre-NIST padding Ethereum uses), for the digests the SP1 test guests commit."""


def keccak256(data):
    """Keccak-256 (the pre-NIST padding Ethereum uses), for the known-vector addresses."""
    rate = 136
    state = [0] * 25
    data = bytearray(data) + b"\x01" + b"\x00" * ((-len(data) - 2) % rate) + b"\x80"
    if len(data) % rate:
        raise AssertionError
    rotations = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
    constants = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
                 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
                 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    mask = 2**64 - 1

    def rotl(v, n):
        return ((v << n) | (v >> (64 - n))) & mask if n else v

    for offset in range(0, len(data), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(data[offset + 8 * i:offset + 8 * i + 8], "little")
        for rc in constants:
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
            state = [state[i] ^ d[i % 5] for i in range(25)]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], rotations[x + 5 * y])
            state = [b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
            state[0] ^= rc
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))
