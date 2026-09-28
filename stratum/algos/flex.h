#ifndef FLEX_H
#define FLEX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// Flex (Kylacoin KCN, Lyncoin LCN), 80-byte header in, 32-byte hash out
void flex_hash(const char* input, char* output, uint32_t len);

// SHA3-256(SHA3-256(data)) (FIPS 202 padding): the transaction id / block id of
// Kylacoin and Lyncoin ("Hash3Writer"), used for the coinbase txid
void sha3d_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
