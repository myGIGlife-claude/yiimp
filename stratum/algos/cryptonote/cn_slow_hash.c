// CryptoNight "variant 1" slow hash with the page size / iteration / address mask
// parameters used by GhostRider (Raptoreum), Mike (VKAX) and Flex (Kylacoin).
//
// Derived from Raptoreum Core src/cryptonote/slow-hash.c
// (github.com/Raptor3um/raptoreum, MIT, commit 900794ea94ff11023667765173295b459d32732c)
// and Kylacoin Core src/crypto/flex/cnfiles/cnfn.c
// (github.com/kylacoin/kylacoin, MIT, commit eeeeb47b9e1c847421ba358bc80c87b7882d6999):
//   Copyright (c) 2021 The Raptoreum Project
//   Copyright (c) 2012-2013 The Cryptonote developers
//   Portions Copyright (c) 2018 The Monero developers
//   Portions Copyright (c) 2018 The TurtleCoin Developers
//   Portions Copyright (c) 2024 Flex Labs Developers
//   Distributed under the MIT/X11 software license.
//
// Changes for the stratum: the OpenAES context (which reseeds rand() on every call)
// is replaced by a plain AES-256 key expansion, only variant 1 is kept, an AES-NI
// path is used when the compiler targets it (-march=native), and the final hash
// selection of Flex ("cnfn": blake/groestl/skein table indexed by state[0] & 2)
// is a parameter.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cn_common.h"
#include "c_keccak.h"
#include "c_blake256.h"
#include "c_groestl.h"
#include "c_jh.h"
#include "c_skein.h"
#include "int-util.h"
#include "cn_slow_hash.h"

#if defined(__AES__) && (defined(__x86_64__) || defined(__i386__)) && !defined(CN_NO_AESNI)
#include <wmmintrin.h>
#define CN_USE_AESNI 1
#endif

#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE  (INIT_SIZE_BLK * AES_BLOCK_SIZE)

extern void aesb_single_round(const uint8_t *in, uint8_t *out, uint8_t *expandedKey);
extern void aesb_pseudo_round(const uint8_t *in, uint8_t *out, uint8_t *expandedKey);

#pragma pack(push, 1)
union hash_state {
	uint8_t b[200];
	uint64_t w[25];
};
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

static const uint8_t aes_sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// AES-256 key schedule, first 10 round keys (160 bytes) as used by CryptoNight.
// Same result as oaes_key_import_data() + key->exp_data in the reference code.
static void cn_aes_expand_key(const uint8_t *key, uint8_t *expanded)
{
	static const uint8_t rcon[8] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
	uint8_t *w = expanded;
	int i;

	memcpy(w, key, 32);
	for (i = 8; i < 40; i++) {
		uint8_t t[4];
		memcpy(t, w + 4 * (i - 1), 4);
		if (i % 8 == 0) {
			uint8_t u = t[0];
			t[0] = aes_sbox[t[1]] ^ rcon[i / 8 - 1];
			t[1] = aes_sbox[t[2]];
			t[2] = aes_sbox[t[3]];
			t[3] = aes_sbox[u];
		} else if (i % 8 == 4) {
			t[0] = aes_sbox[t[0]]; t[1] = aes_sbox[t[1]];
			t[2] = aes_sbox[t[2]]; t[3] = aes_sbox[t[3]];
		}
		w[4 * i + 0] = w[4 * (i - 8) + 0] ^ t[0];
		w[4 * i + 1] = w[4 * (i - 8) + 1] ^ t[1];
		w[4 * i + 2] = w[4 * (i - 8) + 2] ^ t[2];
		w[4 * i + 3] = w[4 * (i - 8) + 3] ^ t[3];
	}
}

static void do_blake_hash(const void *input, size_t len, char *output)
{
	blake256_hash((uint8_t *) output, input, len);
}

static void do_groestl_hash(const void *input, size_t len, char *output)
{
	groestl(input, len * 8, (uint8_t *) output);
}

static void do_jh_hash(const void *input, size_t len, char *output)
{
	jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t *) output);
}

static void do_skein_hash(const void *input, size_t len, char *output)
{
	c_skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t *) output);
}

// Kylacoin's cnfn code has HASH_SIZE = 64 (cnfiles/crypto/hash-ops.h), so its skein
// is Skein-512-512 and writes 64 bytes; blake256 and groestl-256 write 32 bytes.
static void do_skein512_hash(const void *input, size_t len, char *output)
{
	c_skein_hash(8 * 64, input, 8 * len, (uint8_t *) output);
}

// GhostRider / Mike (Raptoreum slow-hash.c): extra_hashes[state[0] & 3]
static void (* const extra_hashes_gr[4])(const void *, size_t, char *) = {
	do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

// Flex (Kylacoin cnfn.c): extra_hashes[state[0] & 2], so only blake (0) or skein-512 (2)
static void (* const extra_hashes_flex[3])(const void *, size_t, char *) = {
	do_blake_hash, do_groestl_hash, do_skein512_hash
};

static inline size_t e2i(const uint8_t *a, size_t count)
{
	uint64_t v;
	memcpy(&v, a, 8);
	return (v / AES_BLOCK_SIZE) & (count - 1);
}

static inline void aes_single_round(const uint8_t *in, uint8_t *out, const uint8_t *key)
{
#ifdef CN_USE_AESNI
	__m128i x = _mm_loadu_si128((const __m128i *) in);
	__m128i k = _mm_loadu_si128((const __m128i *) key);
	_mm_storeu_si128((__m128i *) out, _mm_aesenc_si128(x, k));
#else
	aesb_single_round(in, out, (uint8_t *) key);
#endif
}

static inline void aes_pseudo_round(uint8_t *block, const uint8_t *expanded)
{
#ifdef CN_USE_AESNI
	__m128i x = _mm_loadu_si128((const __m128i *) block);
	for (int r = 0; r < 10; r++)
		x = _mm_aesenc_si128(x, _mm_loadu_si128((const __m128i *) (expanded + 16 * r)));
	_mm_storeu_si128((__m128i *) block, x);
#else
	aesb_pseudo_round(block, block, (uint8_t *) expanded);
#endif
}

static inline void xor_blocks(uint8_t *a, const uint8_t *b)
{
	for (int i = 0; i < AES_BLOCK_SIZE; i++) a[i] ^= b[i];
}

int cn_slow_hash_v1(const void *input, size_t len, void *output,
	uint32_t page_size, uint32_t iterations, uint32_t aes_rounds, int flex)
{
	int outlen = HASH_SIZE;
	union cn_slow_hash_state state;
	uint8_t text[INIT_SIZE_BYTE];
	uint8_t a[AES_BLOCK_SIZE];
	uint8_t b[AES_BLOCK_SIZE];
	uint8_t c[AES_BLOCK_SIZE];
	uint8_t expanded[160];
	size_t i, j;
	const size_t init_rounds = page_size / INIT_SIZE_BYTE;
	uint64_t tweak1_2;

	if (len < 43) {
		// variant 1 reads 8 bytes at offset 35 of the input
		memset(output, 0xff, HASH_SIZE);
		return HASH_SIZE;
	}

	uint8_t *long_state = (uint8_t *) malloc(page_size);
	if (!long_state) {
		memset(output, 0xff, HASH_SIZE);
		return HASH_SIZE;
	}

	keccak1600((const uint8_t *) input, (int) len, state.hs.b);
	memcpy(text, state.init, INIT_SIZE_BYTE);

	{
		uint64_t in35;
		memcpy(&in35, (const uint8_t *) input + 35, 8);
		tweak1_2 = in35 ^ state.hs.w[24];
	}

	cn_aes_expand_key(state.hs.b, expanded);
	for (i = 0; i < init_rounds; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			aes_pseudo_round(&text[AES_BLOCK_SIZE * j], expanded);
		memcpy(&long_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
	}

	for (i = 0; i < 16; i++) {
		a[i] = state.k[i] ^ state.k[32 + i];
		b[i] = state.k[16 + i] ^ state.k[48 + i];
	}

	for (i = 0; i < iterations; i++) {
		uint8_t *p;
		uint64_t t0, t1, c0, a0, a1, hi, lo;

		/* Iteration 1 */
		j = e2i(a, aes_rounds);
		p = &long_state[j * AES_BLOCK_SIZE];
		aes_single_round(p, c, a);
		for (int k = 0; k < AES_BLOCK_SIZE; k++) p[k] = c[k] ^ b[k];
		{	/* VARIANT1_1 */
			const uint8_t tmp = p[11];
			static const uint32_t table = 0x75310;
			const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1;
			p[11] = tmp ^ ((table >> index) & 0x30);
		}

		/* Iteration 2 */
		j = e2i(c, aes_rounds);
		p = &long_state[j * AES_BLOCK_SIZE];
		memcpy(&t0, p, 8);
		memcpy(&t1, p + 8, 8);
		memcpy(&c0, c, 8);
		lo = mul128(c0, t0, &hi);

		memcpy(&a0, a, 8);
		memcpy(&a1, a + 8, 8);
		a0 += hi;
		a1 += lo;
		memcpy(p, &a0, 8);
		memcpy(p + 8, &a1, 8);
		a0 ^= t0;
		a1 ^= t1;
		memcpy(a, &a0, 8);
		memcpy(a + 8, &a1, 8);

		{	/* VARIANT1_2 */
			uint64_t w1;
			memcpy(&w1, p + 8, 8);
			w1 ^= tweak1_2;
			memcpy(p + 8, &w1, 8);
		}
		memcpy(b, c, AES_BLOCK_SIZE);
	}

	memcpy(text, state.init, INIT_SIZE_BYTE);
	cn_aes_expand_key(&state.hs.b[32], expanded);
	for (i = 0; i < init_rounds; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++) {
			xor_blocks(&text[j * AES_BLOCK_SIZE], &long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
			aes_pseudo_round(&text[j * AES_BLOCK_SIZE], expanded);
		}
	}
	memcpy(state.init, text, INIT_SIZE_BYTE);
	keccakf(state.hs.w, 24);

	if (flex) {
		extra_hashes_flex[state.hs.b[0] & 2](&state, 200, (char *) output);
		if (state.hs.b[0] & 2) outlen = 64;
	} else
		extra_hashes_gr[state.hs.b[0] & 3](&state, 200, (char *) output);

	free(long_state);
	return outlen;
}

// Parameters of the six CryptoNight variants (Raptoreum slow-hash.h / Kylacoin cnfn.h)
static const struct {
	uint32_t page_size, iterations, aes_rounds;
} cn_gr_params[CN_GR_VARIANTS] = {
	{ 524288, 131072, 32768 },	// dark
	{ 524288, 131072, 16384 },	// darklite
	{ 2097152, 262144, 131072 },	// fast
	{ 1048576, 262144, 65536 },	// lite
	{ 262144, 65536, 16384 },	// turtle
	{ 262144, 65536, 8192 },	// turtlelite
};

int cn_gr_variant_hash(int variant, const void *input, size_t len, void *output, int flex)
{
	if (variant < 0 || variant >= CN_GR_VARIANTS) return 0;
	return cn_slow_hash_v1(input, len, output, cn_gr_params[variant].page_size,
		cn_gr_params[variant].iterations, cn_gr_params[variant].aes_rounds, flex);
}
