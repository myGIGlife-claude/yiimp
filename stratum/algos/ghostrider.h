#ifndef GHOSTRIDER_H
#define GHOSTRIDER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// GhostRider (Raptoreum RTM and clones), 80-byte header in, 32-byte hash out
void ghostrider_hash(const char* input, char* output, uint32_t len);
// Mike (VKAX), GhostRider variant with 11 core hashes
void mike_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
