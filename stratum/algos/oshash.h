/* OSHash-Y: SHA-256d -> yespower 1.0 (N=2048, r=8, 2 MiB) -> SHA3-256. */
#ifndef OSHASH_H
#define OSHASH_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OSHASH_PERS "OSBTC-OSHash-v1"
/* header: 80-byte serialized block header. out: 32 bytes, compare as little-endian uint256.
 * Returns 0 on success, -1 on allocation failure. Thread-safe (yespower_tls). */
int oshash(const uint8_t header[80], uint8_t out[32]);
#ifdef __cplusplus
}
#endif
#endif
