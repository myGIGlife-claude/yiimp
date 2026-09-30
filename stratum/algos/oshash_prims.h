/* OSHash-Y primitives: self-contained SHA-256d and SHA3-256 (prefixed to avoid host symbol clashes). */
#ifndef OSHASH_PRIMS_H
#define OSHASH_PRIMS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void oshash_sha256(const uint8_t *in, size_t len, uint8_t out[32]);
void oshash_sha256d(const uint8_t *in, size_t len, uint8_t out[32]);
void oshash_sha3_256(const uint8_t *in, size_t len, uint8_t out[32]);
#ifdef __cplusplus
}
#endif
#endif
