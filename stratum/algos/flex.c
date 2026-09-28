// Flex proof of work (Kylacoin KCN, Lyncoin LCN)
//
// Port of flex_hash() from Kylacoin Core src/crypto/flex/flex.cpp
// (github.com/kylacoin/kylacoin, MIT, commit eeeeb47b9e1c847421ba358bc80c87b7882d6999,
// Copyright (c) 2021-2026 Kylacoin Developers / Flex Labs Developers). The CryptoNight
// part ("cnfn") is cryptonote/cn_slow_hash.c with flex = 1.
//
// sha3-512(header) selects an order of 14 core hashes and of the 6 CryptoNight
// variants; the header then goes through 5 cores, CN, 5 cores, CN, 5 cores, CN
// and a final sha3-256 (Kylacoin's sph "keccak" uses the SHA3 padding).

#include <string.h>
#include <stdint.h>

#include "flex.h"
#include "cryptonote/cn_slow_hash.h"
#include "cryptonote/c_keccak.h"

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"

// SHA3 (FIPS 202, 0x06 padding) on top of the Keccak-f[1600] permutation of the CryptoNight
// code. Note: Kylacoin's sph "keccak" (src/crypto/flex/sph/keccak.c) was changed to the SHA3
// padding (eb = 6), so every "keccak512"/"keccak256" of flex_hash() is SHA3-512/SHA3-256.
static void sha3_fips(const uint8_t *in, size_t len, uint8_t *out, size_t outlen)
{
	uint64_t st[25];
	uint8_t block[144];
	const size_t rate = 200 - 2 * outlen;

	memset(st, 0, sizeof(st));
	while (len >= rate) {
		for (size_t i = 0; i < rate / 8; i++) {
			uint64_t w;
			memcpy(&w, in + 8 * i, 8);
			st[i] ^= w;
		}
		keccakf(st, 24);
		in += rate;
		len -= rate;
	}
	memset(block, 0, rate);
	memcpy(block, in, len);
	block[len] ^= 0x06;
	block[rate - 1] ^= 0x80;
	for (size_t i = 0; i < rate / 8; i++) {
		uint64_t w;
		memcpy(&w, block + 8 * i, 8);
		st[i] ^= w;
	}
	keccakf(st, 24);
	memcpy(out, st, outlen);
}

enum {
	FLEX_BLAKE = 0, FLEX_BMW, FLEX_GROESTL, FLEX_KECCAK, FLEX_SKEIN, FLEX_LUFFA,
	FLEX_CUBEHASH, FLEX_SHAVITE, FLEX_SIMD, FLEX_ECHO, FLEX_HAMSI, FLEX_FUGUE,
	FLEX_SHABAL, FLEX_WHIRLPOOL, FLEX_HASH_FUNC_COUNT
};

static void select_algo(unsigned char nibble, int *selected, uint8_t *out, int count, int *current)
{
	uint8_t digit = (nibble & 0x0F) % count;
	if (!selected[digit]) {
		selected[digit] = 1;
		out[(*current)++] = digit;
	}
	digit = (nibble >> 4) % count;
	if (!selected[digit]) {
		selected[digit] = 1;
		out[(*current)++] = digit;
	}
}

// getAlgoString(): only the first half (32 bytes) of the keccak512 hash is used
static void get_algo_string(const uint8_t *hash, uint8_t *out, int count)
{
	int selected[15] = { 0 };
	int n = 0;

	for (int i = 0; i < 32; i++) {
		select_algo(hash[i], selected, out, count, &n);
		if (n == count)
			break;
	}
	if (n < count) {
		for (int i = 0; i < count; i++)
			if (!selected[i])
				out[n++] = i;
	}
}

void flex_hash(const char* input, char* output, uint32_t len)
{
	uint8_t hash[64];
	const void *in = input;
	size_t size = len;
	sha3_fips((const uint8_t *) input, len, hash, 64);

	// 15 slots for 14 core algos: slot 14 (used by round 16) stays 0 = blake, as in the reference
	uint8_t core[15] = { 0 };
	uint8_t cn[6] = { 0 };
	get_algo_string(hash, core, FLEX_HASH_FUNC_COUNT);
	get_algo_string(hash, cn, CN_GR_VARIANTS);

	for (int i = 0; i < 18; i++) {
		int core_sel, cn_sel = -1;

		if (i < 5) core_sel = i;
		else if (i < 11) core_sel = i - 1;
		else core_sel = i - 2;

		if (i == 5) { core_sel = -1; cn_sel = 0; }
		if (i == 11) { core_sel = -1; cn_sel = 1; }
		if (i == 17) { core_sel = -1; cn_sel = 2; }

		if (cn_sel >= 0) {
			// writes 32 bytes (blake: the upper half of hash keeps the previous
			// value) or 64 bytes (skein-512)
			uint8_t tmp[64];
			int n = cn_gr_variant_hash(cn[cn_sel], in, size, tmp, 1);
			memcpy(hash, tmp, n);
		} else {
			union {
				sph_blake512_context blake;
				sph_bmw512_context bmw;
				sph_groestl512_context groestl;
				sph_skein512_context skein;
				sph_luffa512_context luffa;
				sph_cubehash512_context cubehash;
				sph_shavite512_context shavite;
				sph_simd512_context simd;
				sph_echo512_context echo;
				sph_hamsi512_context hamsi;
				sph_fugue512_context fugue;
				sph_shabal512_context shabal;
				sph_whirlpool_context whirlpool;
			} ctx;

			switch (core[core_sel]) {
			case FLEX_BLAKE: sph_blake512_init(&ctx.blake); sph_blake512(&ctx.blake, in, size); sph_blake512_close(&ctx.blake, hash); break;
			case FLEX_BMW: sph_bmw512_init(&ctx.bmw); sph_bmw512(&ctx.bmw, in, size); sph_bmw512_close(&ctx.bmw, hash); break;
			case FLEX_GROESTL: sph_groestl512_init(&ctx.groestl); sph_groestl512(&ctx.groestl, in, size); sph_groestl512_close(&ctx.groestl, hash); break;
			case FLEX_KECCAK: sha3_fips(in, size, hash, 64); break;
			case FLEX_SKEIN: sph_skein512_init(&ctx.skein); sph_skein512(&ctx.skein, in, size); sph_skein512_close(&ctx.skein, hash); break;
			case FLEX_LUFFA: sph_luffa512_init(&ctx.luffa); sph_luffa512(&ctx.luffa, in, size); sph_luffa512_close(&ctx.luffa, hash); break;
			case FLEX_CUBEHASH: sph_cubehash512_init(&ctx.cubehash); sph_cubehash512(&ctx.cubehash, in, size); sph_cubehash512_close(&ctx.cubehash, hash); break;
			case FLEX_SHAVITE: sph_shavite512_init(&ctx.shavite); sph_shavite512(&ctx.shavite, in, size); sph_shavite512_close(&ctx.shavite, hash); break;
			case FLEX_SIMD: sph_simd512_init(&ctx.simd); sph_simd512(&ctx.simd, in, size); sph_simd512_close(&ctx.simd, hash); break;
			case FLEX_ECHO: sph_echo512_init(&ctx.echo); sph_echo512(&ctx.echo, in, size); sph_echo512_close(&ctx.echo, hash); break;
			case FLEX_HAMSI: sph_hamsi512_init(&ctx.hamsi); sph_hamsi512(&ctx.hamsi, in, size); sph_hamsi512_close(&ctx.hamsi, hash); break;
			case FLEX_FUGUE: sph_fugue512_init(&ctx.fugue); sph_fugue512(&ctx.fugue, in, size); sph_fugue512_close(&ctx.fugue, hash); break;
			case FLEX_SHABAL: sph_shabal512_init(&ctx.shabal); sph_shabal512(&ctx.shabal, in, size); sph_shabal512_close(&ctx.shabal, hash); break;
			case FLEX_WHIRLPOOL: sph_whirlpool_init(&ctx.whirlpool); sph_whirlpool(&ctx.whirlpool, in, size); sph_whirlpool_close(&ctx.whirlpool, hash); break;
			}
		}

		in = hash;
		size = 64;
	}

	{
		uint8_t final[32];
		sha3_fips(in, size, final, 32);
		memcpy(output, final, 32);
	}
}

void sha3d_hash(const char* input, char* output, uint32_t len)
{
	uint8_t h[32];
	sha3_fips((const uint8_t *) input, len, h, 32);
	sha3_fips(h, 32, (uint8_t *) output, 32);
}
