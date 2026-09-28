// ProgPoW family for the yiimp stratum: KawPoW (RVN and forks), EvrProgPoW (EVR),
// MeowPoW (MEWC), FiroPoW (FIRO), SCCPoW (SCC), Meraki (TLS).
//
// Derived from the ethash / ProgPoW implementation of Pawel Bylica (chfast/ethash,
// Apache License 2.0), as copied in the coins:
//   Ravencoin   src/crypto/ethash  commit 6d48ae0175b10283248146ae3080e2ba70966739 (kawpow)
//   Evrmore     src/crypto/ethash  commit 0a7ba5aed4f322eaa54af2a11a7658ce6e4ab41b (evrprogpow)
//   Meowcoin    src/crypto/ethash  commit 3b65b001b07e5a7ba19317b4ebc54783f5e4e27f (meowpow)
//   Firo        src/crypto/progpow commit c03cd0a1c68e1af8274349d1234d142ae7d02d1e (firopow, 0.9.4 spec
//               with the upgrade by Andrea Lanfranchi)
//   StakeCubeCoin src/crypto/progpow commit 1542625b0b3b56b8eb2ad8846bd66aa2507d7379 (sccpow)
//   Telestai    src/crypto/ethash  commit 7594e4a4c311673c113f5d160adfa9d14634d13b (meraki)
// The coins only differ in constants, so the algorithm is written once here with the
// constants of each coin in a table (g_variants). Only the light evaluation (from the
// epoch light cache, as the daemons verify blocks) is implemented.
//
// Licensed under the Apache License, Version 2.0 (the original code), modifications
// under the license of this project (GPL-3.0).

#include "progpow.h"
#include "keccak.h"
#include "kiss99.hpp"
#include "primes.h"

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "progpow.cpp is written for little endian hosts"
#endif

extern "C" void sha256_double_hash(const char *input, char *output, unsigned int len);

typedef ethash_hash256 hash256;
typedef ethash_hash512 hash512;
typedef ethash_hash2048 hash2048;

struct progpow_variant
{
	const char *name;
	int epoch_length;
	int max_epoch;            // FIRO: epochs above max_epoch use terminal_epoch (ethash_clamp_memory_usage)
	int terminal_epoch;
	int size_epoch_from;      // MEWC: from this epoch the cache/dataset sizes are the ones of
	int size_epoch_mult;      //   epoch*size_epoch_mult (the seed stays the one of the real epoch)
	uint64_t dataset_init_size;
	int period_length;
	uint32_t num_regs;
	int num_cache_accesses;
	int num_math_operations;
	int num_rounds;
	bool kawpow_keccak;       // kawpow style keccak padding (coin string) or ProgPoW 0.9.4 padding
	uint32_t pad[15];         // kawpow style: the 15 words of the coin string
	int blockid;
	int diff1_bytes;          // 1: 0xff << 216, 2: 0xffff << 208
};

#define S15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o) { a,b,c,d,e,f,g,h,i,j,k,l,m,n,o }

static const progpow_variant g_variants[] = {
	// Ravencoin: ETHASH_EPOCH_LENGTH 7500, full_dataset_init_size 1 << 30, period 3, "rAVENCOINKAWPOW"
	{ "kawpow", 7500, INT_MAX, INT_MAX, INT_MAX, 1, 1ULL << 30, 3, 32, 11, 18, 64, true,
		S15('r','A','V','E','N','C','O','I','N','K','A','W','P','O','W'), PROGPOW_BLOCKID_FINAL, 1 },
	// Evrmore: epoch 12000, dataset init 3 GB, "EVRMORE-PROGPOW"
	{ "evrprogpow", 12000, INT_MAX, INT_MAX, INT_MAX, 1, 3ULL << 30, 3, 32, 11, 18, 64, true,
		S15('E','V','R','M','O','R','E','-','P','R','O','G','P','O','W'), PROGPOW_BLOCKID_FINAL, 1 },
	// Meowcoin meowpow.cpp/hpp: period 6, 16 registers, 6 cache accesses, 9 math operations,
	// "MEOWCOINMEOWPOW"; ethash.cpp: from epoch 110 the sizes are the ones of epoch*4
	{ "meowpow", 7500, INT_MAX, INT_MAX, 110, 4, 1ULL << 30, 6, 16, 6, 9, 64, true,
		S15('M','E','O','W','C','O','I','N','M','E','O','W','P','O','W'), PROGPOW_BLOCKID_FINAL, 1 },
	// Firo: epoch 1300, dataset init 1.5 GB, period 1, 0.9.4 keccak padding;
	// mainnet nMaxPPEpoch = SPARK_NAME_TRANSFER_MAINNET_START_BLOCK/1300 - 1 = 1205100/1300 - 1 = 925,
	// nTerminalPPEpoch = 650 (regtest: 2 and 1, handled by progpow_set_clamp)
	{ "firopow", 1300, 925, 650, INT_MAX, 1, (1ULL << 30) + (1ULL << 29), 1, 32, 11, 18, 64, false,
		S15(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), PROGPOW_BLOCKID_SHA256D, 2 },
	// StakeCubeCoin: FiroPoW with an epoch of 3240 blocks, no clamp, block id = pow hash
	{ "sccpow", 3240, INT_MAX, INT_MAX, INT_MAX, 1, (1ULL << 30) + (1ULL << 29), 1, 32, 11, 18, 64, false,
		S15(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), PROGPOW_BLOCKID_FINAL, 2 },
	// Telestai: epoch 27500, 12 cache accesses, 5 math operations, 32 rounds, "RAVENCOINKAWPOW"
	{ "meraki", 27500, INT_MAX, INT_MAX, INT_MAX, 1, 1ULL << 30, 3, 32, 12, 5, 32, true,
		S15('r','A','V','E','N','C','O','I','N','K','A','W','P','O','W'), PROGPOW_BLOCKID_FINAL, 1 },
	{ NULL }
};

// note: the Ravencoin string really starts with 0x72 (a lower case 'r'), "rAVENCOINKAWPOW"

static const int light_cache_init_size = 1 << 24;
static const int light_cache_growth = 1 << 17;
static const int light_cache_rounds = 3;
static const uint64_t full_dataset_growth = 1 << 23;
static const int full_dataset_item_parents = 512;
static const uint32_t num_lanes = 16;
static const uint32_t max_regs = 32;
static const size_t l1_cache_size = 16 * 1024;
static const size_t l1_cache_num_items = l1_cache_size / sizeof(uint32_t);

static const uint32_t fnv_prime = 0x01000193;
static const uint32_t fnv_offset_basis = 0x811c9dc5;

static inline uint32_t fnv1(uint32_t u, uint32_t v) { return (u * fnv_prime) ^ v; }
static inline uint32_t fnv1a(uint32_t u, uint32_t v) { return (u ^ v) * fnv_prime; }
static inline uint32_t rotl32(uint32_t n, unsigned int c) { c &= 31; return (n << c) | (n >> ((32 - c) & 31)); }
static inline uint32_t rotr32(uint32_t n, unsigned int c) { c &= 31; return (n >> c) | (n << ((32 - c) & 31)); }
static inline uint32_t clz32(uint32_t x) { return x ? (uint32_t) __builtin_clz(x) : 32; }
static inline uint32_t popcount32(uint32_t x) { return (uint32_t) __builtin_popcount(x); }
static inline uint32_t mul_hi32(uint32_t x, uint32_t y) { return (uint32_t) (((uint64_t) x * y) >> 32); }

/////////////////////////////////////////////////////////////////////////////////////////
// epochs

// Firo regtest/testnet use other clamp values; the stratum can override them from the conf
static int g_firo_max_epoch = -1, g_firo_terminal_epoch = -1;

void progpow_set_clamp(int max_epoch, int terminal_epoch)
{
	g_firo_max_epoch = max_epoch;
	g_firo_terminal_epoch = terminal_epoch;
}

extern "C" int progpow_epoch_number(const progpow_variant *v, int height)
{
	int epoch = height / v->epoch_length;
	int max_epoch = v->max_epoch, terminal = v->terminal_epoch;
	if (v->max_epoch != INT_MAX && g_firo_max_epoch >= 0) {
		max_epoch = g_firo_max_epoch;
		terminal = g_firo_terminal_epoch;
	}
	if (epoch > max_epoch) epoch = terminal;
	return epoch;
}

static int size_epoch(const progpow_variant *v, int epoch)
{
	return epoch >= v->size_epoch_from ? epoch * v->size_epoch_mult : epoch;
}

static int light_cache_num_items(const progpow_variant *v, int epoch)
{
	const int item_size = sizeof(hash512);
	int upper = light_cache_init_size / item_size + size_epoch(v, epoch) * (light_cache_growth / item_size);
	return ethash_find_largest_prime(upper);
}

static int full_dataset_num_items(const progpow_variant *v, int epoch)
{
	const uint64_t item_size = 128; // hash1024
	uint64_t upper = v->dataset_init_size / item_size + (uint64_t) size_epoch(v, epoch) * (full_dataset_growth / item_size);
	return ethash_find_largest_prime((int) upper);
}

static hash256 epoch_seed(int epoch)
{
	hash256 seed;
	memset(&seed, 0, sizeof(seed));
	for (int i = 0; i < epoch; ++i)
		seed = ethash_keccak256_32(seed.bytes);
	return seed;
}

struct epoch_context
{
	const progpow_variant *variant;
	int epoch;
	int light_cache_num_items;
	int full_dataset_num_items;
	hash512 *light_cache;
	uint32_t l1_cache[l1_cache_num_items];
	std::atomic<time_t> last_used;

	epoch_context() : light_cache(NULL), last_used(0) {}
	~epoch_context() { free(light_cache); }
};

static void build_light_cache(hash512 *cache, int num_items, const hash256 &seed)
{
	hash512 item = ethash_keccak512(seed.bytes, sizeof(seed));
	cache[0] = item;
	for (int i = 1; i < num_items; ++i) {
		item = ethash_keccak512(item.bytes, sizeof(item));
		cache[i] = item;
	}

	for (int q = 0; q < light_cache_rounds; ++q) {
		for (int i = 0; i < num_items; ++i) {
			const uint32_t index_limit = (uint32_t) num_items;
			const uint32_t v = cache[i].word32s[0] % index_limit;
			const uint32_t w = (uint32_t) (num_items + (i - 1)) % index_limit;
			hash512 x;
			for (size_t j = 0; j < 8; j++)
				x.word64s[j] = cache[v].word64s[j] ^ cache[w].word64s[j];
			cache[i] = ethash_keccak512(x.bytes, sizeof(x));
		}
	}
}

struct item_state
{
	const hash512 *cache;
	int64_t num_cache_items;
	uint32_t seed;
	hash512 mix;

	inline item_state(const epoch_context &ctx, int64_t index)
		: cache(ctx.light_cache), num_cache_items(ctx.light_cache_num_items), seed((uint32_t) index)
	{
		mix = cache[index % num_cache_items];
		mix.word32s[0] ^= seed;
		mix = ethash_keccak512(mix.bytes, sizeof(mix));
	}

	inline void update(uint32_t round)
	{
		const uint32_t t = fnv1(seed ^ round, mix.word32s[round % 16]);
		const int64_t parent_index = t % num_cache_items;
		const hash512 &p = cache[parent_index];
		for (size_t i = 0; i < 16; i++)
			mix.word32s[i] = fnv1(mix.word32s[i], p.word32s[i]);
	}

	inline hash512 final() { return ethash_keccak512(mix.bytes, sizeof(mix)); }
};

static hash2048 dataset_item_2048(const epoch_context &ctx, uint32_t index)
{
	item_state item0(ctx, int64_t(index) * 4);
	item_state item1(ctx, int64_t(index) * 4 + 1);
	item_state item2(ctx, int64_t(index) * 4 + 2);
	item_state item3(ctx, int64_t(index) * 4 + 3);

	for (uint32_t j = 0; j < (uint32_t) full_dataset_item_parents; ++j) {
		item0.update(j);
		item1.update(j);
		item2.update(j);
		item3.update(j);
	}

	hash2048 r;
	r.hash512s[0] = item0.final();
	r.hash512s[1] = item1.final();
	r.hash512s[2] = item2.final();
	r.hash512s[3] = item3.final();
	return r;
}

static epoch_context *create_epoch_context(const progpow_variant *v, int epoch)
{
	epoch_context *ctx = new (std::nothrow) epoch_context;
	if (!ctx) return NULL;
	ctx->variant = v;
	ctx->epoch = epoch;
	ctx->light_cache_num_items = light_cache_num_items(v, epoch);
	ctx->full_dataset_num_items = full_dataset_num_items(v, epoch);
	ctx->light_cache = (hash512 *) malloc((size_t) ctx->light_cache_num_items * sizeof(hash512));
	if (!ctx->light_cache) {
		delete ctx;
		return NULL;
	}
	build_light_cache(ctx->light_cache, ctx->light_cache_num_items, epoch_seed(epoch));

	// the l1 cache is the start of the full dataset
	hash2048 *l1 = (hash2048 *) ctx->l1_cache;
	for (uint32_t i = 0; i < l1_cache_size / sizeof(hash2048); ++i)
		l1[i] = dataset_item_2048(*ctx, i);
	return ctx;
}

// per variant cache of the epoch contexts
struct context_cache
{
	std::mutex mutex;        // protects the list
	std::mutex build_mutex;  // one build at a time (they are big)
	std::vector<std::shared_ptr<epoch_context> > contexts;
	std::atomic<int> building_next;
	context_cache() : building_next(-1) {}
};

static context_cache g_caches[sizeof(g_variants) / sizeof(g_variants[0])];

static context_cache &cache_of(const progpow_variant *v)
{
	return g_caches[v - g_variants];
}

static std::shared_ptr<epoch_context> find_context(context_cache &cc, int epoch)
{
	std::lock_guard<std::mutex> lock(cc.mutex);
	for (auto &c : cc.contexts)
		if (c->epoch == epoch) {
			c->last_used = time(NULL);
			return c;
		}
	return std::shared_ptr<epoch_context>();
}

static std::shared_ptr<epoch_context> get_context(const progpow_variant *v, int epoch)
{
	context_cache &cc = cache_of(v);
	std::shared_ptr<epoch_context> ctx = find_context(cc, epoch);
	if (ctx) return ctx;

	std::lock_guard<std::mutex> build(cc.build_mutex);
	ctx = find_context(cc, epoch); // built by another thread meanwhile?
	if (ctx) return ctx;

	ctx.reset(create_epoch_context(v, epoch));
	if (!ctx) return ctx;

	std::lock_guard<std::mutex> lock(cc.mutex);
	ctx->last_used = time(NULL);
	cc.contexts.push_back(ctx);
	// Keep the epochs in use: the current and next one of each coin mined with this algo
	// (several coins of an algo can be at different epochs). Contexts unused for an hour
	// are freed, and at most max_contexts are kept (least recently used out).
	const size_t max_contexts = 6;
	const time_t now = time(NULL);
	for (size_t i = 0; i < cc.contexts.size(); ) {
		if (cc.contexts[i] != ctx && cc.contexts.size() > 2 && now - cc.contexts[i]->last_used > 3600)
			cc.contexts.erase(cc.contexts.begin() + i);
		else
			i++;
	}
	while (cc.contexts.size() > max_contexts) {
		auto lru = std::min_element(cc.contexts.begin(), cc.contexts.end(),
			[](const std::shared_ptr<epoch_context> &a, const std::shared_ptr<epoch_context> &b) {
				return a->last_used < b->last_used; });
		cc.contexts.erase(lru);
	}
	return ctx;
}

/////////////////////////////////////////////////////////////////////////////////////////
// ProgPoW

namespace {

class mix_rng_state
{
public:
	kiss99 rng;
	uint32_t num_regs;
	size_t dst_counter;
	size_t src_counter;
	uint32_t dst_seq[max_regs];
	uint32_t src_seq[max_regs];

	mix_rng_state(uint64_t seed, uint32_t nregs) : num_regs(nregs), dst_counter(0), src_counter(0)
	{
		const uint32_t seed_lo = (uint32_t) seed;
		const uint32_t seed_hi = (uint32_t) (seed >> 32);

		const uint32_t z = fnv1a(fnv_offset_basis, seed_lo);
		const uint32_t w = fnv1a(z, seed_hi);
		const uint32_t jsr = fnv1a(w, seed_lo);
		const uint32_t jcong = fnv1a(jsr, seed_hi);

		rng = kiss99{z, w, jsr, jcong};

		for (uint32_t i = 0; i < num_regs; ++i) {
			dst_seq[i] = i;
			src_seq[i] = i;
		}
		for (uint32_t i = num_regs; i > 1; --i) {
			std::swap(dst_seq[i - 1], dst_seq[rng() % i]);
			std::swap(src_seq[i - 1], src_seq[rng() % i]);
		}
	}

	uint32_t next_dst() { return dst_seq[(dst_counter++) % num_regs]; }
	uint32_t next_src() { return src_seq[(src_counter++) % num_regs]; }
};

inline uint32_t random_math(uint32_t a, uint32_t b, uint32_t selector)
{
	switch (selector % 11) {
	default:
	case 0: return a + b;
	case 1: return a * b;
	case 2: return mul_hi32(a, b);
	case 3: return std::min(a, b);
	case 4: return rotl32(a, b);
	case 5: return rotr32(a, b);
	case 6: return a & b;
	case 7: return a | b;
	case 8: return a ^ b;
	case 9: return clz32(a) + clz32(b);
	case 10: return popcount32(a) + popcount32(b);
	}
}

inline void random_merge(uint32_t &a, uint32_t b, uint32_t selector)
{
	const uint32_t x = (selector >> 16) % 31 + 1;
	switch (selector % 4) {
	case 0: a = (a * 33) + b; break;
	case 1: a = (a ^ b) * 33; break;
	case 2: a = rotl32(a, x) ^ b; break;
	case 3: a = rotr32(a, x) ^ b; break;
	}
}

typedef uint32_t mix_array[num_lanes][max_regs];

// the state is passed by value: every round restarts from the same program state (as in
// the implementations of the coins)
void progpow_round(const epoch_context &ctx, uint32_t r, mix_array &mix, mix_rng_state state)
{
	const progpow_variant *v = ctx.variant;
	const uint32_t num_regs = v->num_regs;
	const uint32_t num_items = (uint32_t) (ctx.full_dataset_num_items / 2);
	const uint32_t item_index = mix[r % num_lanes][0] % num_items;
	const hash2048 item = dataset_item_2048(ctx, item_index);

	const size_t num_words_per_lane = sizeof(item) / (sizeof(uint32_t) * num_lanes);
	const int max_operations = std::max(v->num_cache_accesses, v->num_math_operations);

	for (int i = 0; i < max_operations; ++i) {
		if (i < v->num_cache_accesses) {
			const uint32_t src = state.next_src();
			const uint32_t dst = state.next_dst();
			const uint32_t sel = state.rng();
			for (size_t l = 0; l < num_lanes; ++l) {
				const size_t offset = mix[l][src] % l1_cache_num_items;
				random_merge(mix[l][dst], ctx.l1_cache[offset], sel);
			}
		}
		if (i < v->num_math_operations) {
			const uint32_t src_rnd = state.rng() % (num_regs * (num_regs - 1));
			const uint32_t src1 = src_rnd % num_regs;
			uint32_t src2 = src_rnd / num_regs;
			if (src2 >= src1) ++src2;

			const uint32_t sel1 = state.rng();
			const uint32_t dst = state.next_dst();
			const uint32_t sel2 = state.rng();
			for (size_t l = 0; l < num_lanes; ++l) {
				const uint32_t data = random_math(mix[l][src1], mix[l][src2], sel1);
				random_merge(mix[l][dst], data, sel2);
			}
		}
	}

	uint32_t dsts[num_words_per_lane];
	uint32_t sels[num_words_per_lane];
	for (size_t i = 0; i < num_words_per_lane; ++i) {
		dsts[i] = i == 0 ? 0 : state.next_dst();
		sels[i] = state.rng();
	}

	for (size_t l = 0; l < num_lanes; ++l) {
		const size_t offset = ((l ^ r) % num_lanes) * num_words_per_lane;
		for (size_t i = 0; i < num_words_per_lane; ++i)
			random_merge(mix[l][dsts[i]], item.word32s[offset + i], sels[i]);
	}
}

void init_mix(uint64_t seed, uint32_t num_regs, mix_array &mix)
{
	const uint32_t z = fnv1a(fnv_offset_basis, (uint32_t) seed);
	const uint32_t w = fnv1a(z, (uint32_t) (seed >> 32));
	for (uint32_t l = 0; l < num_lanes; ++l) {
		const uint32_t jsr = fnv1a(w, l);
		const uint32_t jcong = fnv1a(jsr, l);
		kiss99 rng{z, w, jsr, jcong};
		for (uint32_t i = 0; i < num_regs; i++)
			mix[l][i] = rng();
	}
}

hash256 hash_mix(const epoch_context &ctx, int block_number, uint64_t seed)
{
	const progpow_variant *v = ctx.variant;
	mix_array mix;
	init_mix(seed, v->num_regs, mix);

	const uint64_t number = (uint64_t) (block_number / v->period_length);
	mix_rng_state state(number, v->num_regs);

	for (uint32_t i = 0; i < (uint32_t) v->num_rounds; ++i)
		progpow_round(ctx, i, mix, state);

	uint32_t lane_hash[num_lanes];
	for (size_t l = 0; l < num_lanes; ++l) {
		lane_hash[l] = fnv_offset_basis;
		for (uint32_t i = 0; i < v->num_regs; ++i)
			lane_hash[l] = fnv1a(lane_hash[l], mix[l][i]);
	}

	hash256 mix_hash;
	for (int i = 0; i < 8; i++) mix_hash.word32s[i] = fnv_offset_basis;
	for (size_t l = 0; l < num_lanes; ++l)
		mix_hash.word32s[l % 8] = fnv1a(mix_hash.word32s[l % 8], lane_hash[l]);
	return mix_hash;
}

// first keccak: 8 words of header hash + 2 words of nonce + padding
void keccak_seed(const progpow_variant *v, const hash256 &header_hash, uint64_t nonce, uint32_t seed_out[8])
{
	uint32_t state[25];
	memset(state, 0, sizeof(state));
	for (int i = 0; i < 8; i++)
		state[i] = header_hash.word32s[i];
	state[8] = (uint32_t) nonce;
	state[9] = (uint32_t) (nonce >> 32);
	if (v->kawpow_keccak) {
		for (int i = 10; i < 25; i++)
			state[i] = v->pad[i - 10];
	} else {
		state[10] = 0x00000001;
		state[18] = 0x80008081;
	}
	ethash_keccakf800(state);
	for (int i = 0; i < 8; i++)
		seed_out[i] = state[i];
}

// last keccak: 8 words of the seed keccak + 8 words of mix + padding
hash256 keccak_final(const progpow_variant *v, const uint32_t seed[8], const hash256 &mix_hash)
{
	uint32_t state[25];
	memset(state, 0, sizeof(state));
	for (int i = 0; i < 8; i++)
		state[i] = seed[i];
	for (int i = 8; i < 16; i++)
		state[i] = mix_hash.word32s[i - 8];
	if (v->kawpow_keccak) {
		for (int i = 16; i < 25; i++)
			state[i] = v->pad[i - 16];
	} else {
		state[17] = 0x00000001;
		state[24] = 0x80008081;
	}
	ethash_keccakf800(state);
	hash256 out;
	for (int i = 0; i < 8; i++)
		out.word32s[i] = state[i];
	return out;
}

inline hash256 to_hash256(const unsigned char *b)
{
	hash256 h;
	memcpy(h.bytes, b, 32);
	return h;
}

} // namespace

/////////////////////////////////////////////////////////////////////////////////////////
// C API

extern "C" {

const progpow_variant *progpow_find_variant(const char *algo)
{
	if (!algo) return NULL;
	for (int i = 0; g_variants[i].name; i++)
		if (!strcmp(g_variants[i].name, algo)) return &g_variants[i];
	return NULL;
}

const char *progpow_variant_name(const progpow_variant *v) { return v->name; }
int progpow_variant_blockid(const progpow_variant *v) { return v->blockid; }

void progpow_diff1_target(const progpow_variant *v, unsigned char target_be[32])
{
	memset(target_be, 0, 32);
	target_be[4] = 0xff;
	if (v->diff1_bytes == 2) target_be[5] = 0xff;
}

void progpow_seed_hash(const progpow_variant *v, int height, unsigned char seed[32])
{
	hash256 s = epoch_seed(progpow_epoch_number(v, height));
	memcpy(seed, s.bytes, 32);
}

size_t progpow_light_cache_size(const progpow_variant *v, int height)
{
	return (size_t) light_cache_num_items(v, progpow_epoch_number(v, height)) * sizeof(hash512);
}

int progpow_prepare(const progpow_variant *v, int height)
{
	const int epoch = progpow_epoch_number(v, height);
	if (!get_context(v, epoch)) return 0;

	// build the next epoch in the background when we are close to it
	const int next = progpow_epoch_number(v, height + v->epoch_length / 20 + 10);
	context_cache &cc = cache_of(v);
	if (next != epoch && !find_context(cc, next)) {
		int expected = -1;
		if (cc.building_next.compare_exchange_strong(expected, next)) {
			std::thread([v, next]() {
				get_context(v, next);
				cache_of(v).building_next = -1;
			}).detach();
		}
	}
	return 1;
}

int progpow_hash(const progpow_variant *v, int height, const unsigned char header_hash[32],
	uint64_t nonce, unsigned char mix_out[32], unsigned char final_out[32])
{
	std::shared_ptr<epoch_context> ctx = get_context(v, progpow_epoch_number(v, height));
	if (!ctx) return 0;

	uint32_t seed[8];
	keccak_seed(v, to_hash256(header_hash), nonce, seed);
	const uint64_t seed64 = (uint64_t) seed[0] | ((uint64_t) seed[1] << 32);
	hash256 mix = hash_mix(*ctx, height, seed64);
	hash256 final = keccak_final(v, seed, mix);
	memcpy(mix_out, mix.bytes, 32);
	memcpy(final_out, final.bytes, 32);
	return 1;
}

void progpow_hash_no_verify(const progpow_variant *v, int height, const unsigned char header_hash[32],
	uint64_t nonce, const unsigned char mix[32], unsigned char final_out[32])
{
	uint32_t seed[8];
	keccak_seed(v, to_hash256(header_hash), nonce, seed);
	hash256 final = keccak_final(v, seed, to_hash256(mix));
	memcpy(final_out, final.bytes, 32);
}

int progpow_verify_mix(const progpow_variant *v, int height, const unsigned char header_hash[32],
	uint64_t nonce, const unsigned char mix[32], unsigned char final_out[32])
{
	unsigned char expected_mix[32];
	unsigned char final[32];
	progpow_hash_no_verify(v, height, header_hash, nonce, mix, final_out);
	if (!progpow_hash(v, height, header_hash, nonce, expected_mix, final)) return 0;
	return memcmp(expected_mix, mix, 32) == 0;
}

void progpow_header_hash(const progpow_variant *v, const char *input, char *output, uint32_t len)
{
	// input: 76 bytes version..bits, nHeight (4), nNonce64 (8), mix_hash (32)
	unsigned char hh[32], hh_be[32], mix[32], final[32];
	uint32_t height;
	uint64_t nonce;
	memcpy(&height, input + 76, 4);
	memcpy(&nonce, input + 80, 8);
	sha256_double_hash(input, (char *) hh, 80);
	for (int i = 0; i < 32; i++) hh_be[i] = hh[31 - i];
	if (!progpow_hash(v, (int) height, hh_be, nonce, mix, final)) {
		memset(output, 0xff, 32);
		return;
	}
	for (int i = 0; i < 32; i++) output[i] = (char) final[31 - i];
}

#define PROGPOW_HASH_FUNCTION(algo) \
void algo##_hash(const char *input, char *output, uint32_t len) \
{ \
	static const progpow_variant *v = progpow_find_variant(#algo); \
	progpow_header_hash(v, input, output, len); \
}

PROGPOW_HASH_FUNCTION(kawpow)
PROGPOW_HASH_FUNCTION(evrprogpow)
PROGPOW_HASH_FUNCTION(meowpow)
PROGPOW_HASH_FUNCTION(firopow)
PROGPOW_HASH_FUNCTION(sccpow)
PROGPOW_HASH_FUNCTION(meraki)

} // extern "C"
