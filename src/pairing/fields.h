/* SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
 * SPDX-License-Identifier: MIT
 *
 * Field and twist types of the pairing code, laid out as the SP1 field precompiles take them:
 * an Fp element is NL little-endian limbs, an Fp2 element c0 then c1. Include after defining NL. */

#ifndef PAIRING_FIELDS_H
#define PAIRING_FIELDS_H

typedef struct
{
    uint64_t v[NL];
} fp;

typedef struct
{
    fp c0, c1;
} fp2;

typedef struct
{
    fp2 c0, c1, c2;
} fp6;

typedef struct
{
    fp6 c0, c1;
} fp12;

typedef struct
{
    fp2 x, y;
} g2_affine;

/* Homogeneous projective: x = X/Z, y = Y/Z. */
typedef struct
{
    fp2 x, y, z;
} g2_proj;

#endif
