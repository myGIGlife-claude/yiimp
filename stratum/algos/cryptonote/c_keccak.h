// Imported from Raptoreum Core, github.com/Raptor3um/raptoreum src/cryptonote/c_keccak.h
// (commit 900794ea94ff11023667765173295b459d32732c; original notices below kept).
// Changes: include paths, cn_ name prefixes (cn_common.h), global tables made static.
// keccak.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>
#include "cn_common.h"
#include <string.h>

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

// compute a keccak hash (md) of given byte length from "in"
int keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);

// update the state
void keccakf(uint64_t st[25], int norounds);

void keccak1600(const uint8_t *in, int inlen, uint8_t *md);

#endif
