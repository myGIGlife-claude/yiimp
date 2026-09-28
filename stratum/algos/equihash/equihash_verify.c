/*
 * Equihash solution verifier, see equihash_verify.h
 *
 * Copyright (c) 2026 the yiimp developers, GPL-3.0-or-later (see the yiimp LICENSE).
 *
 * Notation of the zcash protocol specification: collision length c = n/(k+1) bits,
 * 2^k indices of c+1 bits each (big endian bit packing, the "minimal" encoding),
 * hash X_i = the i % (512/n) th n/8 bytes slice of
 * BLAKE2b-((512/n)*n/8)(personal = pers || le32(n) || le32(k), input || le32(i / (512/n))).
 *
 * A solution is valid if, merging the leaves pairwise k times (level r = 0..k-1):
 *   - the XOR of the two subtrees is zero on bits [r*c, (r+1)*c)
 *   - the first index of the left subtree is lower than the one of the right subtree
 *   - the indices of the two subtrees are distinct (all the indices are distinct)
 * and the XOR of all the leaves is zero on the last c bits.
 */

#include <stdlib.h>
#include <string.h>

#include "equihash_verify.h"
#include "../blake2-ref/blake2.h"

int equihash_params_ok(unsigned int n, unsigned int k)
{
	if (k < 1 || k > 15 || n < 16 || n > 512) return 0;
	if (n % 8) return 0;           /* the hash slices are whole bytes */
	if (n % (k + 1)) return 0;
	if (n / (k + 1) > 31) return 0; /* collision chunks and indices fit 32 bits */
	return 1;
}

size_t equihash_solution_size(unsigned int n, unsigned int k)
{
	if (!equihash_params_ok(n, k)) return 0;
	unsigned int c = n / (k + 1);
	return ((size_t) 1 << k) * (c + 1) / 8;
}

/* bits [pos, pos+len) of a big endian bit string, len <= 32 */
static uint32_t get_bits(const unsigned char *p, size_t pos, unsigned int len)
{
	uint64_t v = 0;
	size_t byte = pos / 8;
	unsigned int skip = pos % 8;
	unsigned int need = (skip + len + 7) / 8; /* <= 5 bytes */
	for (unsigned int i = 0; i < need; i++)
		v = (v << 8) | p[byte + i];
	v >>= need * 8 - skip - len;
	return (uint32_t) (v & ((len == 32) ? 0xffffffffULL : ((1ULL << len) - 1)));
}

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *) a, y = *(const uint32_t *) b;
	return x < y ? -1 : x > y;
}

int equihash_verify(unsigned int n, unsigned int k, const char pers[8],
	const unsigned char *input, size_t input_len,
	const unsigned char *soln, size_t soln_len)
{
	if (!equihash_params_ok(n, k)) return 0;
	if (soln_len != equihash_solution_size(n, k)) return 0;

	const unsigned int c = n / (k + 1);
	const unsigned int nidx = 1u << k;
	const unsigned int per_hash = 512 / n;          /* indices per BLAKE2b output */
	const unsigned int out_len = per_hash * n / 8;  /* BLAKE2b output length */
	const unsigned int words = k + 1;               /* c bit chunks of a hash */

	uint32_t *idx = (uint32_t *) malloc(sizeof(uint32_t) * nidx * 2);
	uint32_t *rows = (uint32_t *) malloc(sizeof(uint32_t) * nidx * words);
	if (!idx || !rows) {
		free(idx); free(rows);
		return 0;
	}
	uint32_t *sorted = idx + nidx;
	int ok = 0;

	/* indices, minimal encoding: c+1 bits each */
	for (unsigned int i = 0; i < nidx; i++)
		idx[i] = get_bits(soln, (size_t) i * (c + 1), c + 1);

	/* all distinct */
	memcpy(sorted, idx, sizeof(uint32_t) * nidx);
	qsort(sorted, nidx, sizeof(uint32_t), cmp_u32);
	for (unsigned int i = 1; i < nidx; i++)
		if (sorted[i] == sorted[i - 1]) goto out;

	/* base state: personalization and input */
	blake2b_state base;
	blake2b_param P;
	memset(&P, 0, sizeof(P));
	P.digest_length = (uint8_t) out_len;
	P.fanout = 1;
	P.depth = 1;
	memcpy(P.personal, pers, 8);
	P.personal[8] = n & 0xff; P.personal[9] = (n >> 8) & 0xff;
	P.personal[10] = (n >> 16) & 0xff; P.personal[11] = (n >> 24) & 0xff;
	P.personal[12] = k & 0xff; P.personal[13] = (k >> 8) & 0xff;
	P.personal[14] = (k >> 16) & 0xff; P.personal[15] = (k >> 24) & 0xff;
	if (blake2b_init_param(&base, &P) < 0) goto out;
	blake2b_update(&base, input, input_len);

	/* leaves */
	for (unsigned int i = 0; i < nidx; i++) {
		unsigned char out[64];
		uint32_t g = idx[i] / per_hash;
		unsigned char le[4] = { (unsigned char) g, (unsigned char) (g >> 8),
			(unsigned char) (g >> 16), (unsigned char) (g >> 24) };
		blake2b_state s = base;
		blake2b_update(&s, le, 4);
		blake2b_final(&s, out, out_len);
		const unsigned char *x = out + (idx[i] % per_hash) * (n / 8);
		for (unsigned int w = 0; w < words; w++)
			rows[i * words + w] = get_bits(x, (size_t) w * c, c);
	}

	/* k rounds: subtrees of 2^r leaves are merged pairwise, the XOR is kept in the left
	 * leaf of each subtree (rows[first leaf]) */
	for (unsigned int r = 0; r < k; r++) {
		unsigned int size = 1u << r;
		for (unsigned int left = 0; left < nidx; left += 2 * size) {
			unsigned int right = left + size;
			uint32_t *a = &rows[left * words], *b = &rows[right * words];
			if (a[r] != b[r]) goto out;            /* collision on the r-th chunk */
			if (idx[left] >= idx[right]) goto out; /* ordering of the subtrees */
			for (unsigned int w = r; w < words; w++)
				a[w] ^= b[w];
		}
	}
	ok = rows[k] == 0; /* last chunk of the XOR of all the leaves */

out:
	free(idx);
	free(rows);
	return ok;
}
