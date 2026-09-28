#ifndef BLAKE3HASH_H
#define BLAKE3HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// BLAKE3-256 of the whole input (raw BLAKE3, any header length)
void blake3_hash(const char* input, char* output, uint32_t len);

// Decred (DCP-0011, since block 794368): proof of work hash, BLAKE3-256 of
// the 180-byte block header
void decred_hash(const char* input, char* output, uint32_t len);

// Decred block id: BLAKE-256 (14 rounds) of the 180-byte block header, it
// was also the proof of work hash before DCP-0011
void decred_block_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
