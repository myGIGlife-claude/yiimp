// CryptoNote (Monero) block helpers for the randomx stratum protocol.
// Written for the YiiMP stratum (GPL-3), after the Monero serialization code
// (src/cryptonote_basic/cryptonote_format_utils.cpp, src/crypto/tree-hash.c,
// src/common/base58.cpp).
//
// A block blob (get_block_template "blocktemplate_blob", submit_block) is:
//   header:   major_version (varint), minor_version (varint), timestamp (varint),
//             prev_id (32 bytes), nonce (4 bytes, little endian)
//   miner tx: version (varint), unlock_time (varint), vin (txin_gen: 0xff + height),
//             vout (amount + target), extra (the pool extranonce is in there),
//             then for version 2 the RingCT base (type byte 0 for a miner tx)
//   tx_hashes: count (varint) + count * 32 bytes
//
// The PoW input ("hashing blob", what the miners hash) is
//   header || tree_hash(miner tx hash, tx hashes...) || varint(tx count + 1)
// and the block id is keccak(varint(size of the hashing blob) || hashing blob).
// Hashes are displayed as their bytes in order (no reversal as in Bitcoin).

#ifndef CRYPTONOTE_BLOCK_H
#define CRYPTONOTE_BLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// keccak-256 (original Keccak padding), the CryptoNote cn_fast_hash
void cn_fast_hash(const void *data, size_t len, unsigned char hash[32]);

// Monero tree hash of count hashes (count >= 1)
void cn_tree_hash(const unsigned char (*hashes)[32], size_t count, unsigned char root[32]);

// the tree hash from the first hash (the miner tx, that changes with the extranonce):
// branch of the first hash (at most 64 hashes, returns the depth), and the root from it
size_t cn_tree_branch0(const unsigned char (*hashes)[32], size_t count, unsigned char (*branch)[32]);
void cn_tree_root_branch0(const unsigned char first[32], const unsigned char (*branch)[32], size_t depth,
	unsigned char root[32]);

// RandomX of the input with a fixed key (for hashtest and g_algos only, slow: light mode)
void randomx_hash(const char *input, char *output, uint32_t len);

// varints (7 bits per byte, little endian): the number of bytes read (0 on error)
// or written
int cn_varint_read(const unsigned char *p, size_t len, uint64_t *value);
int cn_varint_write(uint64_t value, unsigned char *out);

struct cn_block_info
{
	uint64_t major_version, minor_version, timestamp;
	size_t header_size;     // header bytes (the nonce is its last 4 bytes)
	size_t nonce_offset;    // offset of the nonce in the blob and in the hashing blob
	size_t miner_tx_offset; // = header_size
	size_t miner_tx_size;
	size_t miner_tx_prefix_size;
	uint64_t miner_tx_version;
	uint64_t miner_tx_height; // txin_gen height
	size_t extra_offset;    // offset of the tx extra bytes in the blob
	size_t extra_size;
	size_t tx_hashes_offset; // offset of the first tx hash
	uint64_t tx_count;       // tx hashes, without the miner tx
};

// parse a block blob; 0 on success, else a negative error code
int cn_block_parse(const unsigned char *blob, size_t size, struct cn_block_info *info);

// hash of the miner tx of the blob
void cn_block_miner_tx_hash(const unsigned char *blob, const struct cn_block_info *info, unsigned char hash[32]);

// the PoW input of the blob: returns its size (at most header_size + 32 + 10 bytes)
size_t cn_block_hashing_blob(const unsigned char *blob, const struct cn_block_info *info, unsigned char *out);

// block id from the hashing blob
void cn_block_id(const unsigned char *hashing_blob, size_t size, unsigned char id[32]);

// CryptoNote base58 address: decode and check the checksum; returns the size of the
// data after the prefix (0 on error), *prefix is the network/address type tag
size_t cn_address_decode(const char *address, uint64_t *prefix, unsigned char *data, size_t maxdata);

// hash * difficulty < 2^256, the hash read as a little endian 256 bit number
// (Monero check_hash), difficulty up to 128 bits
int cn_check_hash(const unsigned char hash[32], uint64_t diff_lo, uint64_t diff_hi);

#ifdef __cplusplus
}
#endif

#endif
