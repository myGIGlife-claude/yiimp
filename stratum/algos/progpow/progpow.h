/*
 * ProgPoW family (KawPoW, EvrProgPoW, MeowPoW, FiroPoW, SCCPoW, Meraki) for the stratum:
 * epoch light caches and light (cache only) evaluation of the hashes.
 *
 * Byte order: header_hash, mix and final hashes are 32 byte arrays in the order
 * they are written in hexadecimal by the daemons (uint256::GetHex(), "display order")
 * and on the stratum wire (mining.notify header hash, mining.submit mix hash).
 * The final hash is a big endian number, compare it with the target as such.
 */

#ifndef PROGPOW_H
#define PROGPOW_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct progpow_variant;
typedef struct progpow_variant progpow_variant;

/* how the daemon computes the block id (the hash of getblock/blocknotify) */
#define PROGPOW_BLOCKID_FINAL    0 /* the pow (final) hash: RVN, EVR, MEWC, TLS, SCC */
#define PROGPOW_BLOCKID_SHA256D  1 /* sha256d of the 120 byte header: FIRO */

const progpow_variant *progpow_find_variant(const char *algo);
const char *progpow_variant_name(const progpow_variant *v);
int progpow_variant_blockid(const progpow_variant *v);
/* the share difficulty 1 target is diff1_mantissa << diff1_shift bits:
   0xff << 216 (kawpow convention) or 0xffff << 208 (firopow, bitcoin diff 1) */
void progpow_diff1_target(const progpow_variant *v, unsigned char target_be[32]);

int progpow_epoch_number(const progpow_variant *v, int height);
/* seed hash of the epoch of this height (what mining.notify sends) */
void progpow_seed_hash(const progpow_variant *v, int height, unsigned char seed[32]);
/* size in bytes of the light cache of the epoch of this height */
size_t progpow_light_cache_size(const progpow_variant *v, int height);

/* make sure the light cache of the epoch of this height is ready (built once and kept
   while in use: the current and next epoch of each coin, 6 at most); the next epoch is
   prepared in the background when the height is close to its start. Returns 0 on
   allocation failure. */
int progpow_prepare(const progpow_variant *v, int height);

/* full light evaluation (slow: ~64 x 2 KB dataset items computed from the cache) */
int progpow_hash(const progpow_variant *v, int height, const unsigned char header_hash[32],
	uint64_t nonce, unsigned char mix_out[32], unsigned char final_out[32]);

/* final hash from a given mix hash, without the dataset (fast, unverified mix) */
void progpow_hash_no_verify(const progpow_variant *v, int height, const unsigned char header_hash[32],
	uint64_t nonce, const unsigned char mix[32], unsigned char final_out[32]);

/* 1 if the mix hash is the right one for this header/nonce (final_out is always set) */
int progpow_verify_mix(const progpow_variant *v, int height, const unsigned char header_hash[32],
	uint64_t nonce, const unsigned char mix[32], unsigned char final_out[32]);

/* yiimp hash function for g_algos/hashtest: input is a 120 byte header
   (80 bytes up to nHeight, nNonce64, mix_hash as serialized), output the pow hash
   (little endian, like the other yiimp hash functions). The mix hash is recomputed,
   the one of the input is ignored. */
void progpow_header_hash(const progpow_variant *v, const char *input, char *output, uint32_t len);

/* the same for each variant (g_algos hash_function) */
void kawpow_hash(const char *input, char *output, uint32_t len);
void evrprogpow_hash(const char *input, char *output, uint32_t len);
void meowpow_hash(const char *input, char *output, uint32_t len);
void firopow_hash(const char *input, char *output, uint32_t len);
void sccpow_hash(const char *input, char *output, uint32_t len);
void meraki_hash(const char *input, char *output, uint32_t len);

/* override the FIRO epoch clamp (nMaxPPEpoch, nTerminalPPEpoch: mainnet 925/650, regtest 2/1) */
void progpow_set_clamp(int max_epoch, int terminal_epoch);

#ifdef __cplusplus
}
#endif

#endif
