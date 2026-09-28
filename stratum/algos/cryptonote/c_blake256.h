// Imported from Raptoreum Core, github.com/Raptor3um/raptoreum src/cryptonote/c_blake256.h
// (commit 900794ea94ff11023667765173295b459d32732c; original notices below kept).
// Changes: include paths, cn_ name prefixes (cn_common.h), global tables made static.
#ifndef _BLAKE256_H_
#define _BLAKE256_H_

#include <stdint.h>
#include "cn_common.h"

typedef struct {
    uint32_t h[8], s[4], t[2];
    int buflen, nullt;
    uint8_t buf[64];
} state;

typedef struct {
    state inner;
    state outer;
} hmac_state;

void blake256_init(state *);

void blake224_init(state *);

void blake256_update(state *, const uint8_t *, uint64_t);

void blake224_update(state *, const uint8_t *, uint64_t);

void blake256_final(state *, uint8_t *);

void blake224_final(state *, uint8_t *);

void blake256_hash(uint8_t *, const uint8_t *, uint64_t);

void blake224_hash(uint8_t *, const uint8_t *, uint64_t);

/* HMAC functions: */

void hmac_blake256_init(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake224_init(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake256_update(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake224_update(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake256_final(hmac_state *, uint8_t *);

void hmac_blake224_final(hmac_state *, uint8_t *);

void hmac_blake256_hash(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);

void hmac_blake224_hash(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);

#endif /* _BLAKE256_H_ */
