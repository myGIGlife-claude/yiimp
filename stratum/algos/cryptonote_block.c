// CryptoNote (Monero) block helpers, see cryptonote_block.h
// Written for the YiiMP stratum (GPL-3).

#include <string.h>
#include <stdlib.h>

#include "cryptonote_block.h"
#include "cryptonote/c_keccak.h"

void cn_fast_hash(const void *data, size_t len, unsigned char hash[32])
{
	cn_keccak((const uint8_t *) data, (int) len, hash, 32);
}

// 1 << floor(log2(count)), count >= 3 (Monero tree_hash_cnt)
static size_t tree_hash_cnt(size_t count)
{
	size_t pow = 2;
	while (pow < count) pow <<= 1;
	return pow >> 1;
}

void cn_tree_hash(const unsigned char (*hashes)[32], size_t count, unsigned char root[32])
{
	const unsigned char *h = (const unsigned char *) hashes;
	if (count == 0) {
		memset(root, 0, 32);
	} else if (count == 1) {
		memcpy(root, h, 32);
	} else if (count == 2) {
		cn_fast_hash(h, 64, root);
	} else {
		size_t i, j;
		size_t cnt = tree_hash_cnt(count); // >= 2 as count >= 3
		if (cnt < 2 || 2 * cnt < count) return;
		unsigned char *ints = (unsigned char *) calloc(cnt, 32);
		if (!ints) {
			memset(root, 0, 32);
			return;
		}
		memcpy(ints, h, (2 * cnt - count) * 32);
		for (i = 2 * cnt - count, j = 2 * cnt - count; j < cnt; i += 2, ++j)
			cn_fast_hash(h + 32 * i, 64, ints + 32 * j);
		while (cnt > 2) {
			cnt >>= 1;
			for (i = 0, j = 0; j < cnt; i += 2, ++j)
				cn_fast_hash(ints + 32 * i, 64, ints + 32 * j);
		}
		cn_fast_hash(ints, 64, root);
		free(ints);
	}
}

size_t cn_tree_branch0(const unsigned char (*hashes)[32], size_t count, unsigned char (*branch)[32])
{
	const unsigned char *h = (const unsigned char *) hashes;
	if (count <= 1) return 0;
	if (count == 2) {
		memcpy(branch[0], h + 32, 32);
		return 1;
	}
	size_t i, j, depth = 0;
	size_t cnt = tree_hash_cnt(count);
	if (cnt < 2 || 2 * cnt < count) return 0;
	unsigned char *ints = (unsigned char *) calloc(cnt, 32);
	if (!ints) return 0;
	// the first hash is at position 0 of every level, its sibling at position 1
	memcpy(ints, h, (2 * cnt - count) * 32);
	if (2 * cnt == count) memcpy(branch[depth++], h + 32, 32);
	for (i = 2 * cnt - count, j = 2 * cnt - count; j < cnt; i += 2, ++j)
		cn_fast_hash(h + 32 * i, 64, ints + 32 * j);
	while (cnt > 2) {
		memcpy(branch[depth++], ints + 32, 32);
		cnt >>= 1;
		for (i = 0, j = 0; j < cnt; i += 2, ++j)
			cn_fast_hash(ints + 32 * i, 64, ints + 32 * j);
	}
	memcpy(branch[depth++], ints + 32, 32);
	free(ints);
	return depth;
}

void cn_tree_root_branch0(const unsigned char first[32], const unsigned char (*branch)[32], size_t depth,
	unsigned char root[32])
{
	unsigned char buf[64];
	memcpy(root, first, 32);
	for (size_t d = 0; d < depth; d++) {
		memcpy(buf, root, 32);
		memcpy(buf + 32, branch[d], 32);
		cn_fast_hash(buf, 64, root);
	}
}

int cn_varint_read(const unsigned char *p, size_t len, uint64_t *value)
{
	uint64_t v = 0;
	for (size_t i = 0; i < len && i < 10; i++) {
		uint64_t b = p[i] & 0x7f;
		if (i == 9 && b > 1) return 0; // over 64 bits
		v |= b << (7 * i);
		if (!(p[i] & 0x80)) {
			if (i > 0 && p[i] == 0) return 0; // not canonical
			*value = v;
			return (int) i + 1;
		}
	}
	return 0;
}

int cn_varint_write(uint64_t value, unsigned char *out)
{
	int n = 0;
	while (value >= 0x80) {
		out[n++] = (unsigned char) ((value & 0x7f) | 0x80);
		value >>= 7;
	}
	out[n++] = (unsigned char) value;
	return n;
}

////////////////////////////////////////////////////////////////////////////////////////

#define READ_VARINT(v) do { \
	int _n = cn_varint_read(blob + pos, size - pos, &(v)); \
	if (!_n) return -1; \
	pos += _n; \
} while (0)

#define SKIP(n) do { \
	if ((size_t) (n) > size - pos) return -2; \
	pos += (n); \
} while (0)

int cn_block_parse(const unsigned char *blob, size_t size, struct cn_block_info *info)
{
	size_t pos = 0;
	uint64_t n, v;
	memset(info, 0, sizeof(*info));

	// header
	READ_VARINT(info->major_version);
	READ_VARINT(info->minor_version);
	READ_VARINT(info->timestamp);
	SKIP(32); // prev_id
	info->nonce_offset = pos;
	SKIP(4);
	info->header_size = pos;

	// miner tx prefix
	info->miner_tx_offset = pos;
	READ_VARINT(info->miner_tx_version);
	if (info->miner_tx_version < 1 || info->miner_tx_version > 2) return -3;
	READ_VARINT(v); // unlock_time
	READ_VARINT(n); // vin
	if (n != 1) return -4;
	SKIP(1);
	if (blob[pos - 1] != 0xff) return -5; // txin_gen
	READ_VARINT(info->miner_tx_height);
	READ_VARINT(n); // vout
	if (n > 100000) return -6;
	for (uint64_t i = 0; i < n; i++) {
		READ_VARINT(v); // amount
		SKIP(1);
		switch (blob[pos - 1]) {
		case 0x02: SKIP(32); break;     // txout_to_key
		case 0x03: SKIP(33); break;     // txout_to_tagged_key (key, view tag)
		default: return -7;
		}
	}
	READ_VARINT(n); // extra
	if (n > size - pos) return -8;
	info->extra_offset = pos;
	info->extra_size = (size_t) n;
	SKIP(n);
	info->miner_tx_prefix_size = pos - info->miner_tx_offset;

	if (info->miner_tx_version >= 2) {
		SKIP(1);
		if (blob[pos - 1] != 0) return -9; // RCTTypeNull
	}
	info->miner_tx_size = pos - info->miner_tx_offset;

	// transaction hashes
	READ_VARINT(info->tx_count);
	if (info->tx_count > (size - pos) / 32) return -10;
	info->tx_hashes_offset = pos;
	SKIP(info->tx_count * 32);
	if (pos != size) return -11;
	return 0;
}

void cn_block_miner_tx_hash(const unsigned char *blob, const struct cn_block_info *info, unsigned char hash[32])
{
	const unsigned char *tx = blob + info->miner_tx_offset;
	if (info->miner_tx_version == 1) {
		cn_fast_hash(tx, info->miner_tx_size, hash);
		return;
	}
	// hash of the 3 hashes: prefix, RingCT base, RingCT prunable (none: zero hash)
	unsigned char hashes[96];
	cn_fast_hash(tx, info->miner_tx_prefix_size, hashes);
	cn_fast_hash(tx + info->miner_tx_prefix_size, info->miner_tx_size - info->miner_tx_prefix_size, hashes + 32);
	memset(hashes + 64, 0, 32);
	cn_fast_hash(hashes, 96, hash);
}

size_t cn_block_hashing_blob(const unsigned char *blob, const struct cn_block_info *info, unsigned char *out)
{
	size_t count = (size_t) info->tx_count + 1;
	unsigned char (*hashes)[32] = (unsigned char (*)[32]) malloc(count * 32);
	if (!hashes) return 0;
	cn_block_miner_tx_hash(blob, info, hashes[0]);
	memcpy(hashes[1], blob + info->tx_hashes_offset, (count - 1) * 32);

	size_t n = info->header_size;
	memcpy(out, blob, n);
	cn_tree_hash((const unsigned char (*)[32]) hashes, count, out + n);
	n += 32;
	n += cn_varint_write(count, out + n);
	free(hashes);
	return n;
}

void cn_block_id(const unsigned char *hashing_blob, size_t size, unsigned char id[32])
{
	unsigned char *buf = (unsigned char *) malloc(size + 10);
	if (!buf) {
		memset(id, 0, 32);
		return;
	}
	int n = cn_varint_write(size, buf);
	memcpy(buf + n, hashing_blob, size);
	cn_fast_hash(buf, size + n, id);
	free(buf);
}

////////////////////////////////////////////////////////////////////////////////////////

static const char b58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int b58_encoded_block_sizes[] = { 0, 2, 3, 5, 6, 7, 9, 10, 11 };
#define B58_FULL_BLOCK 8
#define B58_FULL_ENCODED_BLOCK 11

static int b58_decoded_size(int encoded)
{
	for (int i = 0; i <= B58_FULL_BLOCK; i++)
		if (b58_encoded_block_sizes[i] == encoded) return i;
	return -1;
}

static int b58_decode_block(const char *in, int inlen, unsigned char *out)
{
	int outlen = b58_decoded_size(inlen);
	if (outlen <= 0) return -1;
	unsigned __int128 v = 0;
	for (int i = 0; i < inlen; i++) {
		const char *p = strchr(b58_alphabet, in[i]);
		if (!p || !in[i]) return -1;
		v = v * 58 + (unsigned) (p - b58_alphabet);
	}
	if (outlen < 8 && (v >> (8 * outlen))) return -1;
	if (v >> 64) return -1;
	for (int i = outlen - 1; i >= 0; i--) {
		out[i] = (unsigned char) (v & 0xff);
		v >>= 8;
	}
	return outlen;
}

size_t cn_address_decode(const char *address, uint64_t *prefix, unsigned char *data, size_t maxdata)
{
	size_t len = strlen(address);
	if (len < 4 || len > 256) return 0;
	unsigned char buf[256];
	size_t n = 0;
	size_t full = len / B58_FULL_ENCODED_BLOCK, last = len % B58_FULL_ENCODED_BLOCK;
	for (size_t b = 0; b < full; b++) {
		if (b58_decode_block(address + b * B58_FULL_ENCODED_BLOCK, B58_FULL_ENCODED_BLOCK, buf + n) != B58_FULL_BLOCK)
			return 0;
		n += B58_FULL_BLOCK;
	}
	if (last) {
		int r = b58_decode_block(address + full * B58_FULL_ENCODED_BLOCK, (int) last, buf + n);
		if (r <= 0) return 0;
		n += r;
	}
	if (n <= 4) return 0;

	unsigned char check[32];
	cn_fast_hash(buf, n - 4, check);
	if (memcmp(check, buf + n - 4, 4)) return 0;

	int t = cn_varint_read(buf, n - 4, prefix);
	if (!t) return 0;
	size_t datalen = n - 4 - t;
	if (datalen > maxdata || !datalen) return 0;
	memcpy(data, buf + t, datalen);
	return datalen;
}

////////////////////////////////////////////////////////////////////////////////////////

int cn_check_hash(const unsigned char hash[32], uint64_t diff_lo, uint64_t diff_hi)
{
	uint64_t h[4];
	for (int i = 0; i < 4; i++) {
		h[i] = 0;
		for (int b = 7; b >= 0; b--) h[i] = (h[i] << 8) | hash[8 * i + b];
	}
	// product of the 256 bit hash by the 128 bit difficulty: 384 bits, the top 128 must be 0
	uint64_t r[6] = { 0 };
	uint64_t d[2] = { diff_lo, diff_hi };
	for (int j = 0; j < 2; j++) {
		unsigned __int128 carry = 0;
		for (int i = 0; i < 4; i++) {
			unsigned __int128 t = (unsigned __int128) h[i] * d[j] + r[i + j] + carry;
			r[i + j] = (uint64_t) t;
			carry = t >> 64;
		}
		for (int k = j + 4; k < 6 && carry; k++) {
			unsigned __int128 t = (unsigned __int128) r[k] + carry;
			r[k] = (uint64_t) t;
			carry = t >> 64;
		}
	}
	return r[4] == 0 && r[5] == 0;
}

////////////////////////////////////////////////////////////////////////////////////////

#include <pthread.h>
#include "randomx/randomx.h"

// g_algos/hashtest only: the stratum hashes the shares with the seed of each job
// (protocol_randomx.cpp)
void randomx_hash(const char *input, char *output, uint32_t len)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	static randomx_cache *cache = NULL;
	static randomx_vm *vm = NULL;
	static const char key[] = "YiiMP RandomX test key";

	pthread_mutex_lock(&mutex);
	if (!vm) {
		randomx_flags flags = randomx_get_flags();
		cache = randomx_alloc_cache(flags);
		if (cache) {
			randomx_init_cache(cache, key, sizeof(key) - 1);
			vm = randomx_create_vm(flags, cache, NULL);
		}
	}
	if (vm) randomx_calculate_hash(vm, input, len, output);
	else memset(output, 0xff, 32);
	pthread_mutex_unlock(&mutex);
}
