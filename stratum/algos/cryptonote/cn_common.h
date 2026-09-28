// Common definitions for the CryptoNight code used by ghostrider, mike and flex.
// Written for the YiiMP stratum (GPL-3); the files next to it were imported from
// Raptoreum Core (github.com/Raptor3um/raptoreum, MIT, commit
// 900794ea94ff11023667765173295b459d32732c, src/cryptonote), which in turn took
// them from the CryptoNote/Monero code bases (see each file's header).
//
// The public names of the imported helpers are generic (keccak, groestl, jh_hash...),
// so they are renamed here with a cn_ prefix to keep them from clashing with other
// hash libraries linked into the stratum.
#ifndef CN_COMMON_H
#define CN_COMMON_H

#include <stddef.h>
#include <stdint.h>

typedef unsigned char BitSequence;
typedef unsigned long long DataLength;

#ifndef HASH_SIZE
#define HASH_SIZE 32
#endif
#ifndef HASH_DATA_AREA
#define HASH_DATA_AREA 136
#endif

#define keccak             cn_keccak
#define keccakf            cn_keccakf
#define keccak1600         cn_keccak1600
#define groestl            cn_groestl
#define jh_hash            cn_jh_hash
#define c_skein_hash       cn_skein_hash
#define blake256_compress  cn_blake256_compress
#define blake256_init      cn_blake256_init
#define blake224_init      cn_blake224_init
#define blake256_update    cn_blake256_update
#define blake224_update    cn_blake224_update
#define blake256_final_h   cn_blake256_final_h
#define blake256_final     cn_blake256_final
#define blake224_final     cn_blake224_final
#define blake256_hash      cn_blake256_hash
#define blake224_hash      cn_blake224_hash
#define hmac_blake256_init   cn_hmac_blake256_init
#define hmac_blake224_init   cn_hmac_blake224_init
#define hmac_blake256_update cn_hmac_blake256_update
#define hmac_blake224_update cn_hmac_blake224_update
#define hmac_blake256_final  cn_hmac_blake256_final
#define hmac_blake224_final  cn_hmac_blake224_final
#define hmac_blake256_hash   cn_hmac_blake256_hash
#define hmac_blake224_hash   cn_hmac_blake224_hash
#define aesb_single_round  cn_aesb_single_round
#define aesb_pseudo_round  cn_aesb_pseudo_round

#endif
