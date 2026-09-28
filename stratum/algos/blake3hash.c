#include <stdint.h>
#include <string.h>

#include <sha3/sph_blake.h>
#include "blake3/blake3.h"
#include "blake3hash.h"

void blake3_hash(const char* input, char* output, uint32_t len)
{
	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, input, len);
	blake3_hasher_finalize(&hasher, (uint8_t *) output, 32);
}

#define DECRED_HEADER_SIZE 180

void decred_hash(const char* input, char* output, uint32_t len)
{
	if (len > DECRED_HEADER_SIZE) len = DECRED_HEADER_SIZE;
	blake3_hash(input, output, len);
}

void decred_block_hash(const char* input, char* output, uint32_t len)
{
	sph_blake256_context ctx_blake;

	if (len > DECRED_HEADER_SIZE) len = DECRED_HEADER_SIZE;

	sph_blake256_set_rounds(14);
	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, len);
	sph_blake256_close(&ctx_blake, output);
}
