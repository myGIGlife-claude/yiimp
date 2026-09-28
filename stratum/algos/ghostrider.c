// GhostRider (Raptoreum) and Mike (VKAX) proof of work.
//
// Port of HashGR() / HashSelection from Raptoreum Core (src/hash.h, src/hash_selection.cpp,
// github.com/Raptor3um/raptoreum, MIT, commit 900794ea94ff11023667765173295b459d32732c,
// Copyright (c) 2020 The Raptoreum Core developers) and of Mike() from VKAX Core
// (src/hash.h, github.com/vkaxproject/vkax, MIT, commit cce5efe129c3b7cfa8ec35379cd7769bece1fa9a,
// Copyright (c) 2022 The Vkax Core developers).
//
// The order of the core hashes and of the CryptoNight variants is taken from the
// nibbles of the previous block hash (header bytes 4..35), so the hash only
// depends on the 80-byte header.

#include <string.h>
#include <stdint.h>

#include "ghostrider.h"
#include "cryptonote/cn_slow_hash.h"

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
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
#include "sha3/sph_sha2.h"

// coreHash() of hash_selection.cpp: 0 blake .. 14 whirlpool, 15 sha512
static void gr_core_hash(const void *in, size_t len, void *out, int algo)
{
	union {
		sph_blake512_context blake;
		sph_bmw512_context bmw;
		sph_groestl512_context groestl;
		sph_jh512_context jh;
		sph_keccak512_context keccak;
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
		sph_sha512_context sha512;
	} ctx;

	switch (algo) {
	case 0: sph_blake512_init(&ctx.blake); sph_blake512(&ctx.blake, in, len); sph_blake512_close(&ctx.blake, out); break;
	case 1: sph_bmw512_init(&ctx.bmw); sph_bmw512(&ctx.bmw, in, len); sph_bmw512_close(&ctx.bmw, out); break;
	case 2: sph_groestl512_init(&ctx.groestl); sph_groestl512(&ctx.groestl, in, len); sph_groestl512_close(&ctx.groestl, out); break;
	case 3: sph_jh512_init(&ctx.jh); sph_jh512(&ctx.jh, in, len); sph_jh512_close(&ctx.jh, out); break;
	case 4: sph_keccak512_init(&ctx.keccak); sph_keccak512(&ctx.keccak, in, len); sph_keccak512_close(&ctx.keccak, out); break;
	case 5: sph_skein512_init(&ctx.skein); sph_skein512(&ctx.skein, in, len); sph_skein512_close(&ctx.skein, out); break;
	case 6: sph_luffa512_init(&ctx.luffa); sph_luffa512(&ctx.luffa, in, len); sph_luffa512_close(&ctx.luffa, out); break;
	case 7: sph_cubehash512_init(&ctx.cubehash); sph_cubehash512(&ctx.cubehash, in, len); sph_cubehash512_close(&ctx.cubehash, out); break;
	case 8: sph_shavite512_init(&ctx.shavite); sph_shavite512(&ctx.shavite, in, len); sph_shavite512_close(&ctx.shavite, out); break;
	case 9: sph_simd512_init(&ctx.simd); sph_simd512(&ctx.simd, in, len); sph_simd512_close(&ctx.simd, out); break;
	case 10: sph_echo512_init(&ctx.echo); sph_echo512(&ctx.echo, in, len); sph_echo512_close(&ctx.echo, out); break;
	case 11: sph_hamsi512_init(&ctx.hamsi); sph_hamsi512(&ctx.hamsi, in, len); sph_hamsi512_close(&ctx.hamsi, out); break;
	case 12: sph_fugue512_init(&ctx.fugue); sph_fugue512(&ctx.fugue, in, len); sph_fugue512_close(&ctx.fugue, out); break;
	case 13: sph_shabal512_init(&ctx.shabal); sph_shabal512(&ctx.shabal, in, len); sph_shabal512_close(&ctx.shabal, out); break;
	case 14: sph_whirlpool_init(&ctx.whirlpool); sph_whirlpool(&ctx.whirlpool, in, len); sph_whirlpool_close(&ctx.whirlpool, out); break;
	case 15: sph_sha512_init(&ctx.sha512); sph_sha512(&ctx.sha512, in, len); sph_sha512_close(&ctx.sha512, out); break;
	}
}

// uint256::GetNibble(i) of the previous block hash (little endian bytes as in the header)
static inline unsigned int prev_nibble(const uint8_t *prev, int i)
{
	int index = 63 - i;
	if (index % 2 == 1)
		return prev[index / 2] >> 4;
	return prev[index / 2] & 0x0F;
}

// HashSelection::getRandomIndexes() for the identity list {0 .. total-1}
static void gr_random_indexes(const uint8_t *prev, int total, int *out)
{
	int indexes[16];
	int count = 0, i;

	for (i = 0; i < total; i++) indexes[i] = i;

	for (i = 63; i >= 0; i--) {
		unsigned int sel = prev_nibble(prev, i);
		if (sel >= (unsigned int) total)
			sel = sel % total;
		if (indexes[sel] >= 0) {
			out[count++] = indexes[sel];
			indexes[sel] = -1;
		}
		if (count == total)
			break;
	}
	if (i < 0 && count < total) {
		for (int j = 0; j < total; j++)
			if (indexes[j] >= 0)
				out[count++] = indexes[j];
	}
}

// rounds: number of steps (18 for GhostRider, 14 for Mike), ncores: size of the core list
static void gr_generic_hash(const char *input, char *output, uint32_t len, int ncores, int steps)
{
	uint8_t hash[18][64];
	int cores[16], cns[CN_GR_VARIANTS];
	const uint8_t *prev = (const uint8_t *) input + 4;

	memset(hash, 0, sizeof(hash)); // uint512 values are zero initialized
	gr_random_indexes(prev, CN_GR_VARIANTS, cns);
	gr_random_indexes(prev, ncores, cores);

	for (int i = 0; i < steps; i++) {
		const void *in = (i == 0) ? (const void *) input : (const void *) hash[i - 1];
		size_t inlen = (i == 0) ? len : 64;
		int core = -1, cn = -1;

		// same schedule for both: 5 cores, CN, 5 cores, CN, then 5 (GR) or 1 (Mike) core(s), CN
		if (i < 5) core = cores[i];
		else if (i == 5) cn = cns[0];
		else if (i < 11) core = cores[i - 1];
		else if (i == 11) cn = cns[1];
		else if (i < steps - 1) core = cores[i - 2];
		else cn = cns[2];

		if (core >= 0)
			gr_core_hash(in, inlen, hash[i], core);
		else
			cn_gr_variant_hash(cn, hash[i - 1], 64, hash[i], 0);
	}

	memcpy(output, hash[steps - 1], 32);
}

void ghostrider_hash(const char* input, char* output, uint32_t len)
{
	gr_generic_hash(input, output, len, 15, 18);
}

void mike_hash(const char* input, char* output, uint32_t len)
{
	gr_generic_hash(input, output, len, 11, 14);
}
