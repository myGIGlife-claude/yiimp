#ifndef CN_SLOW_HASH_H
#define CN_SLOW_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// CryptoNight variant 1 with custom parameters. Returns the number of bytes written:
// flex = 0: GhostRider/Mike final hash (blake/groestl/jh/skein-256 by state[0] & 3), 32 bytes
// flex = 1: Flex final hash (blake-256 or skein-512 by state[0] & 2), 32 or 64 bytes,
//           so the output buffer must hold 64 bytes
int cn_slow_hash_v1(const void *input, size_t len, void *output,
	uint32_t page_size, uint32_t iterations, uint32_t aes_rounds, int flex);

// GhostRider CN variants, same order as Raptoreum's cnVariantMap
enum {
	CN_GR_DARK = 0, CN_GR_DARKLITE, CN_GR_FAST, CN_GR_LITE, CN_GR_TURTLE, CN_GR_TURTLELITE,
	CN_GR_VARIANTS
};

int cn_gr_variant_hash(int variant, const void *input, size_t len, void *output, int flex);

#ifdef __cplusplus
}
#endif

#endif
