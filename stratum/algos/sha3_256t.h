#ifndef SHA3_256T_H
#define SHA3_256T_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void sha3_256t_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
