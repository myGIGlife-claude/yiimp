/*
 * Equihash solution verifier (any n, k with n a multiple of 8, n/(k+1) <= 31).
 *
 * Copyright (c) 2026 the yiimp developers, GPL-3.0-or-later (see the yiimp LICENSE).
 *
 * Checks what zcashd's EhIsValidSolution / librustzcash eh_isvalid check (the Equihash
 * algorithm of Biryukov and Khovratovich, and the zcash protocol specification section
 * "Equihash"), written from the specification: the minimal encoding of the 2^k indices,
 * the BLAKE2b hashes with the 16 byte personalization "<8 bytes>" || le32(n) || le32(k),
 * the k collision rounds, the ordering of the index subtrees, distinct indices and the
 * final zero hash.
 */

#ifndef EQUIHASH_VERIFY_H
#define EQUIHASH_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 1 if (n, k) can be verified by this code */
int equihash_params_ok(unsigned int n, unsigned int k);

/* size of a solution (without the compact size prefix), 0 for unsupported parameters:
 * 1344 for 200,9, 400 for 192,7, 100 for 144,5, 68 for 96,5, 36 for 48,5 */
size_t equihash_solution_size(unsigned int n, unsigned int k);

/* input: the 140 byte header (the 108 byte "I" and the 32 byte nonce) or any input,
 * pers: the 8 first bytes of the personalization ("ZcashPoW", "BgoldPoW"...),
 * soln: the solution without the compact size prefix.
 * Returns 1 if the solution is valid. */
int equihash_verify(unsigned int n, unsigned int k, const char pers[8],
	const unsigned char *input, size_t input_len,
	const unsigned char *soln, size_t soln_len);

#ifdef __cplusplus
}
#endif

#endif
