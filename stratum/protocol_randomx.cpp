// CryptoNote family stratum: Monero (monerod) and the RandomX coins
//
// monerod is not Bitcoin derived, so this family also replaces the daemon side:
//
// Daemon (JSON-RPC 2.0 at http://rpchost:rpcport/json_rpc, basic or digest authentication):
//   get_block_template {wallet_address: coin master_wallet, reserve_size: 8}
//       -> blocktemplate_blob, reserved_offset, difficulty (wide_difficulty), height,
//          seed_hash, next_seed_hash, blockhashing_blob
//   submit_block ["block blob"] -> {status: "OK"} or an error
//   get_block_count                (new block detection, polled every randomx_poll_ms)
//   monerod --block-notify '/path/blocknotify 127.0.0.1:port coinid %s' confirms the blocks
//   as for the Bitcoin coins (the %s block id is the one the stratum records, see below).
//
// Miners (xmrig and the CryptoNote pool protocol, JSON-RPC 2.0 lines with named params):
//   login  {login: "address[.worker]", pass, agent, algo: [...], rigid}
//          -> {id: session, job: {blob, job_id, target, height, seed_hash, algo}, extensions,
//              status: "OK"}
//   job    notification {blob, job_id, target, height, seed_hash, algo}
//   submit {id: session, job_id, nonce: 8 hex (4 bytes as in the blob), result: 64 hex}
//          -> {status: "OK"}
//   keepalived {id} -> {status: "KEEPALIVED"}, getjob {id} -> job
//   errors are {code, message} objects.
//
// Every miner gets its own blob: the pool extranonce (4 bytes: the connection counter,
// 4 bytes: the process id, so that two stratums of the same coin never share work) is
// written in the reserved space of the miner tx extra; the miner tx hash and the tree hash
// (from the branch of the miner tx, computed once per template) give the hashing blob sent
// to the miner. The nonce is at byte 39 of the blob (after the 3 header varints and the
// previous block id).
//
// Shares are checked with RandomX (light mode: the 256 MiB cache of the seed hash of the job,
// the current and next seeds are kept, a new seed is prepared in the background when the
// template announces it). Difficulty D (CryptoNote convention: D hashes per share) is sent as
// the xmrig target, 32 bits (0xffffffff / D) or 64 bits for large D; a share is valid when
// the last 8 bytes of the hash, as a little endian number, are below 0xffffffffffffffff / D.
// The shares table gets D: the web hashrate constant of randomx is 2^10 (H/s, with the
// 1.024 factor of the other algos). The network difficulty (coind->difficulty, blocks
// difficulty and difficulty_user) is in the units of the other algos, 2^32 hashes, so that
// the web formulas (ttf, profitability) apply: Monero difficulty / 2^32. A block is a hash with hash * block difficulty < 2^256;
// it is submitted with submit_block and recorded with its block id (keccak of the size and
// the hashing blob), the id monerod gives to --block-notify.
//
// Config ([STRATUM] section): randomx_poll_ms (default 1000, 0 disables the polling),
// randomx_v2 (0, RandomX v2 for a future hard fork), randomx_algo (the xmrig algo name,
// "rx/0"), randomx_reserve (extranonce bytes asked to the daemon, 8).

#include "stratum.h"
#include "algos/randomx/randomx.h"

#include <vector>

static int g_rx_poll_ms = 1000;
static bool g_rx_v2 = false;
static char g_rx_algo[32] = "rx/0";
static int g_rx_reserve = 8;
static uint32_t g_rx_instance = 0;
static randomx_flags g_rx_flags = RANDOMX_FLAG_DEFAULT;

#define RX_BLOB_MAX 256

////////////////////////////////////////////////////////////////////////////////////////
// RandomX caches, one per seed hash, with a pool of light VMs each

#define RX_SLOTS 3

struct rx_slot
{
	unsigned char seed[32];
	bool used;
	bool building;
	int users;
	time_t last;
	randomx_cache *cache;
	std::vector<randomx_vm *> *vms;
};

static rx_slot g_rx_slots[RX_SLOTS];
static pthread_mutex_t g_rx_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_rx_cond = PTHREAD_COND_INITIALIZER;

static rx_slot *rx_find(const unsigned char seed[32])
{
	for (int i = 0; i < RX_SLOTS; i++)
		if (g_rx_slots[i].used && !memcmp(g_rx_slots[i].seed, seed, 32)) return &g_rx_slots[i];
	return NULL;
}

// the slot of the seed, its cache built (by this thread or another one); with the mutex held
static rx_slot *rx_get_locked(const unsigned char seed[32])
{
	while (true) {
		rx_slot *slot = rx_find(seed);
		if (slot && slot->building) {
			pthread_cond_wait(&g_rx_cond, &g_rx_mutex);
			continue;
		}
		if (slot) return slot->cache ? slot : NULL;

		// a free slot, or the least recently used one nobody is using
		for (int i = 0; i < RX_SLOTS; i++) {
			rx_slot *s = &g_rx_slots[i];
			if (!s->used) { slot = s; break; }
			if (s->building || s->users) continue;
			if (!slot || s->last < slot->last) slot = s;
		}
		if (!slot) {
			pthread_cond_wait(&g_rx_cond, &g_rx_mutex);
			continue;
		}

		if (slot->used) {
			char hex[80];
			hexlify(hex, slot->seed, 32);
			debuglog("randomx: releasing the cache of seed %s\n", hex);
			for (size_t v = 0; v < slot->vms->size(); v++) randomx_destroy_vm((*slot->vms)[v]);
			slot->vms->clear();
			if (slot->cache) randomx_release_cache(slot->cache);
			slot->cache = NULL;
		}
		if (!slot->vms) slot->vms = new std::vector<randomx_vm *>;
		memcpy(slot->seed, seed, 32);
		slot->used = true;
		slot->building = true;
		slot->users = 0;
		slot->last = time(NULL);

		pthread_mutex_unlock(&g_rx_mutex);
		long long t0 = current_timestamp();
		randomx_cache *cache = randomx_alloc_cache(g_rx_flags);
		if (cache) randomx_init_cache(cache, seed, 32);
		char hex[80];
		hexlify(hex, seed, 32);
		if (cache) stratumlog("%s: randomx cache of seed %s ready in %lld ms\n", g_stratum_algo, hex,
			current_timestamp() - t0);
		else stratumlog("ERROR %s: unable to allocate the randomx cache (256 MiB)\n", g_stratum_algo);
		pthread_mutex_lock(&g_rx_mutex);

		slot->cache = cache;
		slot->building = false;
		if (!cache) slot->used = false;
		pthread_cond_broadcast(&g_rx_cond);
		return cache ? slot : NULL;
	}
}

static bool rx_prepare(const unsigned char seed[32])
{
	pthread_mutex_lock(&g_rx_mutex);
	rx_slot *slot = rx_get_locked(seed);
	if (slot) slot->last = time(NULL);
	pthread_mutex_unlock(&g_rx_mutex);
	return slot != NULL;
}

static void *rx_prepare_thread(void *p)
{
	unsigned char *seed = (unsigned char *) p;
	rx_prepare(seed);
	free(seed);
	return NULL;
}

// build the cache of the next seed without blocking the jobs
static void rx_prepare_background(const unsigned char seed[32])
{
	pthread_mutex_lock(&g_rx_mutex);
	bool known = rx_find(seed) != NULL;
	pthread_mutex_unlock(&g_rx_mutex);
	if (known) return;

	unsigned char *copy = (unsigned char *) malloc(32);
	if (!copy) return;
	memcpy(copy, seed, 32);
	pthread_t thread;
	if (pthread_create(&thread, NULL, rx_prepare_thread, copy) == 0) pthread_detach(thread);
	else free(copy);
}

static bool rx_hash(const unsigned char seed[32], const unsigned char *input, size_t len, unsigned char hash[32])
{
	pthread_mutex_lock(&g_rx_mutex);
	rx_slot *slot = rx_get_locked(seed);
	if (!slot) {
		pthread_mutex_unlock(&g_rx_mutex);
		return false;
	}
	randomx_vm *vm = NULL;
	if (!slot->vms->empty()) {
		vm = slot->vms->back();
		slot->vms->pop_back();
	}
	slot->users++;
	slot->last = time(NULL);
	pthread_mutex_unlock(&g_rx_mutex);

	if (!vm) vm = randomx_create_vm(g_rx_flags, slot->cache, NULL);
	if (vm) randomx_calculate_hash(vm, input, len, hash);

	pthread_mutex_lock(&g_rx_mutex);
	if (vm) slot->vms->push_back(vm);
	slot->users--;
	pthread_cond_broadcast(&g_rx_cond);
	pthread_mutex_unlock(&g_rx_mutex);
	return vm != NULL;
}

////////////////////////////////////////////////////////////////////////////////////////
// settings

static void randomx_config(dictionary *ini)
{
	g_rx_poll_ms = iniparser_getint(ini, "STRATUM:randomx_poll_ms", g_rx_poll_ms);
	g_rx_v2 = iniparser_getint(ini, "STRATUM:randomx_v2", 0) != 0;
	g_rx_reserve = iniparser_getint(ini, "STRATUM:randomx_reserve", g_rx_reserve);
	if (g_rx_reserve < 8) g_rx_reserve = 8;
	if (g_rx_reserve > 64) g_rx_reserve = 64;
	const char *algo = iniparser_getstring(ini, "STRATUM:randomx_algo", NULL);
	if (algo && strlen(algo) < sizeof(g_rx_algo)) strcpy(g_rx_algo, algo);
}

static void *randomx_poll_thread(void *p);

static void randomx_init()
{
	g_rx_flags = randomx_get_flags();
	// the JIT code is not writable while it runs (as monerod does outside the miner)
	if (g_rx_flags & RANDOMX_FLAG_JIT) g_rx_flags = (randomx_flags) (g_rx_flags | RANDOMX_FLAG_SECURE);
	if (g_rx_v2) g_rx_flags = (randomx_flags) (g_rx_flags | RANDOMX_FLAG_V2);
	g_rx_instance = (uint32_t) getpid();

	stratumlog("%s: randomx%s flags %x (jit %d, hard aes %d), light mode, xmrig algo %s\n", g_stratum_algo,
		g_rx_v2 ? " v2" : "", (int) g_rx_flags, (g_rx_flags & RANDOMX_FLAG_JIT) != 0,
		(g_rx_flags & RANDOMX_FLAG_HARD_AES) != 0, g_rx_algo);

	if (g_rx_poll_ms > 0) {
		pthread_t thread;
		pthread_create(&thread, NULL, randomx_poll_thread, NULL);
	}
}

static void randomx_coind_config(YAAMP_COIND *coind)
{
	// monerod JSON-RPC: /json_rpc, digest authentication (--rpc-login), through curl
	strcpy(coind->rpc.path, "/json_rpc");
	coind->rpc.curl = 1;
	coind->rpc.userpwd[0] = '\0';
	if (coind->rpc.credential[0]) {
		char plain[1024] = { 0 };
		base64_decode(plain, coind->rpc.credential);
		if (strcmp(plain, ":")) snprintf(coind->rpc.userpwd, sizeof(coind->rpc.userpwd), "%s", plain);
	}
	if (strcmp(coind->rpcencoding, "XMR")) {
		static time_t last = 0;
		if (time(NULL) - last > 3600) {
			stratumlog("%s: set rpcencoding to XMR (web wallet adapter) for the randomx coin %s\n",
				g_stratum_algo, coind->symbol);
			last = time(NULL);
		}
	}
}

// Monero address types: standard, integrated, subaddress (mainnet, testnet, stagenet)
static const uint64_t xmr_prefixes[][3] = { { 18, 19, 42 }, { 53, 54, 63 }, { 24, 25, 36 } };

static int xmr_network(uint64_t prefix)
{
	for (int n = 0; n < 3; n++)
		for (int t = 0; t < 3; t++)
			if (xmr_prefixes[n][t] == prefix) return n;
	return -1;
}

// a user address of the coin: valid base58 and checksum, standard or subaddress (the
// payouts do not use payment ids), same network as the pool wallet
static bool randomx_valid_address(YAAMP_COIND *coind, const char *address, const char **error)
{
	uint64_t prefix = 0, pool_prefix = 0;
	unsigned char data[128];
	size_t n = cn_address_decode(address, &prefix, data, sizeof(data));
	if (n != 64) {
		*error = n == 72 ? "Integrated addresses are not supported, use a subaddress" : "Invalid address";
		return false;
	}
	if (!coind || !cn_address_decode(coind->wallet, &pool_prefix, data, sizeof(data))) return true;
	int net = xmr_network(pool_prefix);
	if (net >= 0 ? xmr_network(prefix) != net : false) {
		*error = "Address of another network";
		return false;
	}
	return true;
}

static void randomx_coind_init(YAAMP_COIND *coind)
{
	const char *error = "";
	if (!coind->wallet[0])
		stratumlog("ERROR %s: set the master_wallet of %s, the address the daemon pays the blocks to\n",
			g_stratum_algo, coind->symbol);
	else if (!randomx_valid_address(NULL, coind->wallet, &error))
		stratumlog("ERROR %s: %s wallet %s: %s\n", g_stratum_algo, coind->symbol, coind->wallet, error);
}

////////////////////////////////////////////////////////////////////////////////////////
// templates

// compact representation of the CryptoNote target 2^256 / difficulty (logs, decode_compact)
static void rx_nbits(double difficulty, char *nbits)
{
	if (difficulty < 1) difficulty = 1;
	long double t = ldexpl(1.0L, 256) / (long double) difficulty;
	int size = 1;
	while (t >= 256.0L && size < 64) { t /= 256.0L; size++; }
	// t in [1, 256): mantissa of 3 bytes
	uint32_t mantissa = (uint32_t) (t * 65536.0L);
	if (mantissa & 0x800000) { mantissa >>= 8; size++; }
	sprintf(nbits, "%08x", (uint32_t) ((size << 24) | (mantissa & 0x7fffff)));
}

static bool rx_parse_diff(json_value *result, uint64_t diff[2])
{
	const char *wide = json_get_string(result, "wide_difficulty");
	diff[0] = diff[1] = 0;
	if (wide && (!strncmp(wide, "0x", 2) || !strncmp(wide, "0X", 2))) {
		wide += 2;
		size_t len = strlen(wide);
		if (!len || len > 32) return false;
		for (size_t i = 0; i < len; i++) {
			char c = wide[i];
			int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
				(c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
			if (v < 0) return false;
			diff[1] = (diff[1] << 4) | (diff[0] >> 60);
			diff[0] = (diff[0] << 4) | v;
		}
	} else {
		diff[0] = (uint64_t) json_get_int(result, "difficulty");
		diff[1] = (uint64_t) json_get_int(result, "difficulty_top64");
	}
	return diff[0] || diff[1];
}

static YAAMP_JOB_TEMPLATE *randomx_create_template(YAAMP_COIND *coind)
{
	static time_t last_error = 0;
	char params[1024];
	snprintf(params, sizeof(params), "{\"wallet_address\":\"%s\",\"reserve_size\":%d}", coind->wallet, g_rx_reserve);

	json_value *json = rpc_call(&coind->rpc, "get_block_template", params);
	json_value *result = json ? json_get_object(json, "result") : NULL;
	if (!result || result->type != json_object) {
		if (time(NULL) - last_error > 60) {
			json_value *error = json ? json_get_object(json, "error") : NULL;
			const char *message = error ? json_get_string(error, "message") : NULL;
			stratumlog("%s: %s get_block_template failed: %s\n", g_stratum_algo, coind->symbol,
				message ? message : "no answer");
			last_error = time(NULL);
		}
		if (json) json_value_free(json);
		return NULL;
	}

	const char *blob_hex = json_get_string(result, "blocktemplate_blob");
	const char *seed_hex = json_get_string(result, "seed_hash");
	const char *next_seed_hex = json_get_string(result, "next_seed_hash");
	const char *hashing_hex = json_get_string(result, "blockhashing_blob");
	const char *prev_hex = json_get_string(result, "prev_hash");
	int reserved_offset = (int) json_get_int(result, "reserved_offset");
	int height = (int) json_get_int(result, "height");

	uint64_t diff[2];
	size_t blob_len = blob_hex ? strlen(blob_hex) : 0;
	if (!blob_len || blob_len % 2 || !ishexa((char *) blob_hex, (int) blob_len) || !seed_hex || strlen(seed_hex) != 64
		|| !ishexa((char *) seed_hex, 64) || !rx_parse_diff(result, diff) || height <= 0) {
		stratumlog("ERROR %s: %s invalid get_block_template answer\n", g_stratum_algo, coind->symbol);
		json_value_free(json);
		return NULL;
	}

	size_t size = blob_len / 2;
	unsigned char *blob = (unsigned char *) malloc(size);
	if (!blob) {
		json_value_free(json);
		return NULL;
	}
	char *lower = strdup(blob_hex);
	string_lower(lower);
	binlify(blob, lower);
	free(lower);

	struct cn_block_info info;
	int err = cn_block_parse(blob, size, &info);
	if (err || reserved_offset < (int) info.extra_offset
		|| reserved_offset + g_rx_reserve > (int) (info.extra_offset + info.extra_size)
		|| info.miner_tx_size * 2 >= sizeof(((YAAMP_JOB_TEMPLATE *) 0)->proto_coinbase)
		|| info.header_size * 2 >= sizeof(((YAAMP_JOB_TEMPLATE *) 0)->proto_header)) {
		stratumlog("ERROR %s: %s block template not understood (%d, reserved offset %d)\n", g_stratum_algo,
			coind->symbol, err, reserved_offset);
		free(blob);
		json_value_free(json);
		return NULL;
	}

	// check the hashing blob with the one of the daemon (same reserved bytes)
	unsigned char hb[RX_BLOB_MAX];
	size_t hl = cn_block_hashing_blob(blob, &info, hb);
	if (hashing_hex) {
		char hb_hex[2 * RX_BLOB_MAX + 1];
		hexlify(hb_hex, hb, (int) hl);
		if (strcasecmp(hb_hex, hashing_hex)) {
			static time_t last = 0;
			if (time(NULL) - last > 600) {
				stratumlog("ERROR %s: %s hashing blob differs from the daemon's one\n", g_stratum_algo, coind->symbol);
				last = time(NULL);
			}
			free(blob);
			json_value_free(json);
			return NULL;
		}
	}

	YAAMP_JOB_TEMPLATE *templ = new YAAMP_JOB_TEMPLATE;
	memset(templ, 0, sizeof(YAAMP_JOB_TEMPLATE));
	templ->created = time(NULL);
	templ->height = height;
	templ->value = json_get_int(result, "expected_reward");
	sprintf(templ->version, "%02x%02x", (unsigned) info.major_version & 0xff, (unsigned) info.minor_version & 0xff);
	sprintf(templ->ntime, "%08x", (uint32_t) info.timestamp);
	snprintf(templ->prevhash_hex, sizeof(templ->prevhash_hex), "%s", prev_hex ? prev_hex : "");
	strcpy(templ->prevhash_be, templ->prevhash_hex);

	templ->proto_diff[0] = diff[0];
	templ->proto_diff[1] = diff[1];
	// network difficulty in the units of the other algos (2^32 hashes), for the coins/blocks
	// tables and the profitability (Monero difficulty = proto_netdiff * 2^32)
	double netdiff = (double) diff[0] + ldexp((double) diff[1], 64);
	templ->proto_netdiff = netdiff / 4294967296.0;
	rx_nbits(netdiff, templ->nbits);
	templ->proto_reserved = reserved_offset - (int) info.miner_tx_offset;
	templ->proto_nonce = (int) info.nonce_offset;

	hexlify(templ->proto_header, blob, (int) info.header_size);
	hexlify(templ->proto_coinbase, blob + info.miner_tx_offset, (int) info.miner_tx_size);
	snprintf(templ->proto_seed, sizeof(templ->proto_seed), "%s", seed_hex);
	string_lower(templ->proto_seed);

	// tx hashes (for submit_block) and the branch of the miner tx (for the hashing blobs)
	size_t count = (size_t) info.tx_count + 1;
	unsigned char (*hashes)[32] = (unsigned char (*)[32]) malloc(count * 32);
	unsigned char branch[64][32];
	size_t depth = 0;
	if (hashes) {
		cn_block_miner_tx_hash(blob, &info, hashes[0]);
		memcpy(hashes[1], blob + info.tx_hashes_offset, (count - 1) * 32);
		depth = cn_tree_branch0((const unsigned char (*)[32]) hashes, count, branch);
	}
	char hex[80];
	for (size_t i = 1; hashes && i < count; i++) {
		hexlify(hex, hashes[i], 32);
		templ->txdata.push_back(hex);
	}
	for (size_t d = 0; d < depth; d++) {
		hexlify(hex, branch[d], 32);
		templ->txsteps.push_back(hex);
	}
	templ->txcount = (int) count;

	// the tree root identifies the transactions: a new job when they change
	hexlify(templ->coinb2, hb + info.header_size, 32);

	bool ready = hashes != NULL;
	free(hashes);
	free(blob);

	unsigned char seed[32];
	binlify(seed, templ->proto_seed);
	ready = ready && rx_prepare(seed);

	if (next_seed_hex && strlen(next_seed_hex) == 64 && ishexa((char *) next_seed_hex, 64)
		&& strcasecmp(next_seed_hex, seed_hex)) {
		char next[80];
		strcpy(next, next_seed_hex);
		string_lower(next);
		unsigned char next_seed[32];
		binlify(next_seed, next);
		rx_prepare_background(next_seed);
	}
	json_value_free(json);

	if (!ready) {
		templ->txsteps.clear();
		templ->txdata.clear();
		delete templ;
		return NULL;
	}
	return templ;
}

// new block detection between the blocknotify and the db updates of the main loop
static void *randomx_poll_thread(void *p)
{
	while (!g_exiting) {
		usleep(g_rx_poll_ms * YAAMP_MS);

		g_list_coind.Enter();
		for (CLI li = g_list_coind.first; li; li = li->next) {
			YAAMP_COIND *coind = (YAAMP_COIND *) li->data;
			if (coind->deleted || !coind->enable || !coind->auto_ready || !coind->job) continue;

			json_value *json = rpc_call(&coind->rpc, "get_block_count", "{}");
			json_value *result = json ? json_get_object(json, "result") : NULL;
			int count = result ? (int) json_get_int(result, "count") : 0;
			if (json) json_value_free(json);
			if (count <= 0 || count == coind->height + 1) continue;

			if (g_debuglog_client) debuglog("%s: new block, height %d\n", coind->symbol, count - 1);
			coind->newblock = true;
			if (coind_create_job(coind, true)) job_signal();
		}
		g_list_coind.Leave();
	}
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////
// per miner blobs

// the 8 extranonce bytes of the miner: connection counter (extranonce1), stratum process
static void rx_extranonce(YAAMP_CLIENT *client, unsigned char extranonce[8])
{
	uint32_t n1 = (uint32_t) strtoul(client->extranonce1, NULL, 16);
	memcpy(extranonce, &n1, 4);
	memcpy(extranonce + 4, &g_rx_instance, 4);
}

// miner tx of the client (binary), returns its size
static int rx_miner_tx(YAAMP_JOB_TEMPLATE *templ, YAAMP_CLIENT *client, unsigned char *tx, int maxsize)
{
	int size = (int) strlen(templ->proto_coinbase) / 2;
	if (size > maxsize || templ->proto_reserved + 8 > size) return 0;
	binlify(tx, templ->proto_coinbase);
	rx_extranonce(client, tx + templ->proto_reserved);
	return size;
}

// hashing blob of the client, nonce 0 (as in the template); returns its size
static int rx_hashing_blob(YAAMP_JOB_TEMPLATE *templ, YAAMP_CLIENT *client, unsigned char *out)
{
	static __thread unsigned char tx[8*1024];
	int txsize = rx_miner_tx(templ, client, tx, sizeof(tx));
	int hsize = (int) strlen(templ->proto_header) / 2;
	if (!txsize || hsize <= 0 || hsize > RX_BLOB_MAX - 42) return 0;

	struct cn_block_info info;
	memset(&info, 0, sizeof(info));
	info.miner_tx_offset = 0;
	info.miner_tx_size = txsize;
	// the miner tx prefix ends before the RingCT base (1 byte) of a version 2 tx
	uint64_t version = 0;
	cn_varint_read(tx, txsize, &version);
	info.miner_tx_version = version;
	info.miner_tx_prefix_size = version >= 2 ? txsize - 1 : txsize;

	unsigned char txhash[32], root[32];
	cn_block_miner_tx_hash(tx, &info, txhash);

	unsigned char branch[64][32];
	size_t depth = 0;
	for (vector<string>::const_iterator i = templ->txsteps.begin(); i != templ->txsteps.end() && depth < 64; ++i)
		binlify(branch[depth++], (*i).c_str());
	cn_tree_root_branch0(txhash, (const unsigned char (*)[32]) branch, depth, root);

	binlify(out, templ->proto_header);
	memcpy(out + hsize, root, 32);
	int n = hsize + 32;
	n += cn_varint_write((uint64_t) templ->txcount, out + n);
	return n;
}

// xmrig target of the difficulty: 32 bits (0xffffffff / D), 64 bits for large D
static uint64_t rx_target64(double difficulty)
{
	if (difficulty < 1) difficulty = 1;
	uint64_t d = (uint64_t) difficulty;
	return 0xffffffffffffffffULL / d;
}

static void rx_target_hex(double difficulty, char *hex)
{
	uint64_t t64 = rx_target64(difficulty);
	uint32_t t32 = (uint32_t) (t64 >> 32);
	if (t32 >= 0x100) hexlify(hex, (const unsigned char *) &t32, 4); // little endian bytes
	else hexlify(hex, (const unsigned char *) &t64, 8);
}

static void randomx_job_json(YAAMP_JOB *job, YAAMP_CLIENT *client, char *buffer, int size)
{
	YAAMP_JOB_TEMPLATE *templ = job->templ;
	unsigned char blob[RX_BLOB_MAX];
	char blob_hex[2 * RX_BLOB_MAX + 1] = "";
	int n = rx_hashing_blob(templ, client, blob);
	if (n > 0) hexlify(blob_hex, blob, n);

	char target[32];
	rx_target_hex(client->difficulty_actual, target);

	snprintf(buffer, size, "{\"blob\":\"%s\",\"job_id\":\"%x\",\"target\":\"%s\",\"height\":%d,"
		"\"seed_hash\":\"%s\",\"algo\":\"%s\"}", blob_hex, job->id, target, templ->height,
		templ->proto_seed, g_rx_algo);
}

static void randomx_job_notify(YAAMP_JOB *job, YAAMP_CLIENT *client, char *buffer, int size)
{
	if (!client) {
		buffer[0] = '\0';
		return;
	}
	char job_json[1024];
	randomx_job_json(job, client, job_json, sizeof(job_json));
	snprintf(buffer, size, "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":%s}\n", job_json);
}

////////////////////////////////////////////////////////////////////////////////////////
// answers

static void rx_id(YAAMP_CLIENT *client, char *id, int size)
{
	if (client->id_str) snprintf(id, size, "\"%s\"", client->id_str);
	else snprintf(id, size, "%d", client->id_int);
}

static int randomx_send_error(YAAMP_CLIENT *client, int error, const char *message)
{
	char id[64];
	rx_id(client, id, sizeof(id));
	return socket_send(client->sock, "{\"id\":%s,\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"%s\"},\"result\":null}\n",
		id, -error, message);
}

static int rx_send_result(YAAMP_CLIENT *client, const char *result)
{
	char id[64];
	rx_id(client, id, sizeof(id));
	return socket_send(client->sock, "{\"id\":%s,\"jsonrpc\":\"2.0\",\"error\":null,\"result\":%s}\n", id, result);
}

static int randomx_send_difficulty(YAAMP_CLIENT *client, double difficulty)
{
	// the target is sent with the next job
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////
// login

static YAAMP_JOB *rx_last_job(int coinid)
{
	YAAMP_JOB *found = NULL;
	g_list_job.Enter();
	for (CLI li = g_list_job.last; li; li = li->prev) {
		YAAMP_JOB *job = (YAAMP_JOB *) li->data;
		if (!job_can_mine(job) || !job->coind) continue;
		if (coinid > 0 && job->coind->id != coinid) continue;
		// locked for the caller (object_prune frees deleted jobs with no
		// lock), the caller unlocks it
		object_lock(job);
		found = job;
		break;
	}
	g_list_job.Leave();
	return found;
}

static YAAMP_COIND *rx_first_coind()
{
	YAAMP_COIND *found = NULL;
	g_list_coind.Enter();
	for (CLI li = g_list_coind.first; li; li = li->next) {
		YAAMP_COIND *coind = (YAAMP_COIND *) li->data;
		if (coind->deleted) continue;
		found = coind;
		break;
	}
	g_list_coind.Leave();
	return found;
}

static bool randomx_login(YAAMP_CLIENT *client, json_value *params)
{
	if (g_list_client.Find(client)) {
		randomx_send_error(client, 21, "Already logged in");
		return true;
	}
	if (g_list_client.count >= g_stratum_max_cons) {
		randomx_send_error(client, 21, "Server full");
		return false;
	}

	const char *login = json_get_string(params, "login");
	const char *pass = json_get_string(params, "pass");
	const char *agent = json_get_string(params, "agent");
	const char *rigid = json_get_string(params, "rigid");
	if (!login || !login[0]) {
		randomx_send_error(client, 20, "Missing login");
		return false;
	}

	snprintf(client->username, sizeof(client->username), "%s", login);
	snprintf(client->password, sizeof(client->password), "%s", pass ? pass : "");
	snprintf(client->version, sizeof(client->version), "%s", agent ? agent : "");
	db_check_user_input(client->username);

	char *sep = strpbrk(client->username, ".,;:+");
	if (sep) {
		if (*sep != '+') snprintf(client->worker, sizeof(client->worker), "%s", sep + 1);
		*sep = '\0';
		// address+difficulty (fixed difficulty), as other monero pools
		char *plus = strchr(client->worker, '+');
		if (plus) *plus = '\0';
	}
	if (!client->worker[0] && rigid && rigid[0])
		snprintf(client->worker, sizeof(client->worker), "%s", rigid);

	const char *error = "Invalid address";
	int len = strlen(client->username);
	if (!len || len > 106) {
		randomx_send_error(client, 20, error);
		return false;
	}
	YAAMP_COIND *coind = rx_first_coind();
	if (!randomx_valid_address(coind, client->username, &error)) {
		clientlog(client, "%s", error);
		randomx_send_error(client, 20, error);
		return false;
	}

	// session (as mining.subscribe)
	get_next_extraonce1(client->extranonce1_default);
	strcpy(client->extranonce1, client->extranonce1_default);
	strcpy(client->extranonce1_last, client->extranonce1_default);
	strcpy(client->extranonce1_reconnect, client->extranonce1_default);
	client->extranonce2size_default = client->extranonce2size = 0;
	client->extranonce2size_last = client->extranonce2size_reconnect = 0;
	client->reconnectable = false;
	get_random_key(client->notify_id);
	client->difficulty_actual = g_stratum_difficulty;

	// user and worker (as mining.authorize), fixed difficulty with d= in the password
	const char *plus = strchr(login, '+');
	if (plus && atof(plus + 1) > 0 && !strstr(client->password, "d=")) {
		char buf[64];
		snprintf(buf, sizeof(buf), ",d=%g", atof(plus + 1));
		if (strlen(client->password) + strlen(buf) < sizeof(client->password)) strcat(client->password, buf);
	}
	client_initialize_difficulty(client);
	client->difficulty_actual = client_normalize_difficulty(client->difficulty_actual);
	if (client->difficulty_actual < 1) client->difficulty_actual = 1;

	if (g_debuglog_client)
		debuglog("new %s client %s, %s, %s\n", g_stratum_algo, client->username, client->worker, client->version);

	CommonLock(&g_db_mutex);
	db_add_user(g_db, client);
	if (client->userid == -1) {
		CommonUnlock(&g_db_mutex);
		client_block_ip(client, "account locked");
		clientlog(client, "account locked");
		return false;
	}
	db_add_worker(g_db, client);
	CommonUnlock(&g_db_mutex);
	if (!client->userid || !client->workerid) {
		randomx_send_error(client, 20, "Unable to register the worker");
		return false;
	}

	YAAMP_JOB *job = rx_last_job(client->coinid);
	if (!job) job = rx_last_job(0);

	char job_json[1024] = "null";
	if (job) {
		randomx_job_json(job, client, job_json, sizeof(job_json));
		client->jobid_sent = job->id;
		object_unlock(job);
	}

	char result[2048];
	snprintf(result, sizeof(result), "{\"id\":\"%s\",\"job\":%s,\"extensions\":[\"algo\",\"keepalive\"],\"status\":\"OK\"}",
		client->notify_id, job_json);
	if (rx_send_result(client, result) < 0) return false;

	g_list_client.AddTail(client);
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////
// submit

static bool rx_submit_block(YAAMP_CLIENT *client, YAAMP_JOB *job, const unsigned char *hashing_blob,
	int hashing_size, const unsigned char pow[32], const char *nonce_hex, double share_diff)
{
	YAAMP_COIND *coind = job->coind;
	YAAMP_JOB_TEMPLATE *templ = job->templ;
	if (!coind || job->block_found) return false;

	// header with the nonce, miner tx with the extranonce, tx hashes
	size_t size = strlen(templ->proto_header) + strlen(templ->proto_coinbase) + 64 + 64 * templ->txdata.size() + 64;
	char *block_hex = (char *) malloc(size);
	if (!block_hex) return false;

	char *p = block_hex;
	memcpy(p, templ->proto_header, 2 * templ->proto_nonce);
	p += 2 * templ->proto_nonce;
	p += sprintf(p, "%s%s", nonce_hex, templ->proto_header + 2 * templ->proto_nonce + 8);

	static __thread unsigned char tx[8*1024];
	int txsize = rx_miner_tx(templ, client, tx, sizeof(tx));
	hexlify(p, tx, txsize);
	p += 2 * txsize;

	unsigned char count[16];
	int n = cn_varint_write((uint64_t) templ->txdata.size(), count);
	hexlify(p, count, n);
	p += 2 * n;
	for (vector<string>::const_iterator i = templ->txdata.begin(); i != templ->txdata.end(); ++i)
		p += sprintf(p, "%s", (*i).c_str());

	char *params = (char *) malloc(strlen(block_hex) + 16);
	if (!params) {
		free(block_hex);
		return false;
	}
	sprintf(params, "[\"%s\"]", block_hex);
	json_value *json = rpc_call(&coind->rpc, "submit_block", params);
	free(params);

	bool accepted = false;
	const char *message = "no answer";
	json_value *result = json ? json_get_object(json, "result") : NULL;
	json_value *error = json ? json_get_object(json, "error") : NULL;
	if (result && result->type == json_object) {
		const char *status = json_get_string(result, "status");
		accepted = status && !strcmp(status, "OK");
		if (!accepted) message = status ? status : "no status";
	} else if (error && error->type == json_object) {
		const char *m = json_get_string(error, "message");
		message = m ? m : "error";
	}

	unsigned char id[32];
	char blockid[80], powhash[80];
	cn_block_id(hashing_blob, hashing_size, id);
	hexlify(blockid, id, 32);
	hexlify(powhash, pow, 32);

	if (accepted) {
		// blocks table: difficulties in 2^32 hashes, as coins.difficulty
		protocol_block_accepted(client, job, templ->proto_netdiff, share_diff / 4294967296.0, blockid, powhash);
	} else {
		stratumlog("ERROR %s submit_block %d: %s\n", coind->symbol, templ->height, message);
		debuglog("*** REJECTED :( %s block %d %d txs\n", coind->name, templ->height, templ->txcount);
		rejectlog("REJECTED %s block %d (%s) %s\n", coind->symbol, templ->height, message, block_hex);
	}

	if (json) json_value_free(json);
	free(block_hex);
	return accepted;
}

static bool rx_reject(YAAMP_CLIENT *client, YAAMP_JOB *job, int error, const char *message, char *nonce)
{
	randomx_send_error(client, error, message);
	protocol_share_record(client, job, false, nonce, 0, error, message);
	return true;
}

static bool randomx_submit(YAAMP_CLIENT *client, json_value *params)
{
	const char *session = json_get_string(params, "id");
	const char *jobid_str = json_get_string(params, "job_id");
	const char *nonce_str = json_get_string(params, "nonce");
	const char *result_str = json_get_string(params, "result");

	if (!g_list_client.Find(client) || !session || strcmp(session, client->notify_id)) {
		randomx_send_error(client, 24, "Unauthenticated");
		client->submit_bad++;
		return true;
	}
	if (!jobid_str || strlen(jobid_str) > 16 || !nonce_str || !result_str) {
		randomx_send_error(client, 20, "Invalid params");
		client->submit_bad++;
		return true;
	}

	char nonce[16] = { 0 }, result_hex[80] = { 0 };
	bool params_ok = protocol_hex_param(nonce_str, nonce, 8) && protocol_hex_param(result_str, result_hex, 64);

	YAAMP_JOB *job = (YAAMP_JOB *) object_find(&g_list_job, htoi(jobid_str), true);
	if (!job) return rx_reject(client, NULL, 21, "Invalid job id", nonce);
	YAAMP_JOB_TEMPLATE *templ = job->templ;
	// a replaced job of the current height (new transactions) is still valid
	if (job->deleted && !(job->coind && !job->coind->deleted && job->coind->job && job->coind->job->templ
		&& job->coind->job->templ->height == templ->height)) {
		rx_send_result(client, "{\"status\":\"OK\"}"); // stale, not counted
		object_unlock(job);
		return true;
	}
	if (!job->coind || !templ->proto_header[0]) {
		rx_reject(client, job, 21, "Invalid job", nonce);
		object_unlock(job);
		return true;
	}
	if (!params_ok) {
		rx_reject(client, job, 20, "Invalid nonce or result", nonce);
		object_unlock(job);
		return true;
	}
	char empty[2] = "";
	if (share_find(job->id, empty, templ->ntime, nonce, client->extranonce1)) {
		rx_reject(client, job, 22, "Duplicate share", nonce);
		object_unlock(job);
		return true;
	}

	double difficulty = client->difficulty_actual;
	uint64_t target = rx_target64(difficulty);

	// the claimed hash first (cheap), then RandomX
	unsigned char claimed[32];
	binlify(claimed, result_hex);
	uint64_t top;
	memcpy(&top, claimed + 24, 8);
	if (top >= target) {
		rx_reject(client, job, 26, "Low difficulty share", nonce);
		object_unlock(job);
		return true;
	}

	unsigned char blob[RX_BLOB_MAX], seed[32], hash[32];
	int n = rx_hashing_blob(templ, client, blob);
	unsigned char nonce_bin[4];
	binlify(nonce_bin, nonce);
	if (n <= templ->proto_nonce + 4) {
		rx_reject(client, job, 20, "Invalid job", nonce);
		object_unlock(job);
		return true;
	}
	memcpy(blob + templ->proto_nonce, nonce_bin, 4);
	binlify(seed, templ->proto_seed);
	if (!rx_hash(seed, blob, n, hash)) {
		rx_reject(client, job, 20, "Internal error (randomx)", nonce);
		object_unlock(job);
		return true;
	}
	if (memcmp(hash, claimed, 32)) {
		// a forged result costs us a full RandomX hash: drop the connection
		rx_reject(client, job, 25, "Invalid result", nonce);
		object_unlock(job);
		return false;
	}

	// difficulty of the hash: 2^64 / the top 64 bits
	double share_diff = top ? ldexp(1.0, 64) / (double) top : ldexp(1.0, 64);

	if (g_debuglog_hash) {
		char hash_hex[80];
		hexlify(hash_hex, hash, 32);
		debuglog("submit %s (uid %d) job %x nonce %s hash %s diff %.0f/%.0f\n", client->sock->ip,
			client->userid, job->id, nonce, hash_hex, share_diff, difficulty);
	}

	if (cn_check_hash(hash, templ->proto_diff[0], templ->proto_diff[1]) && !job->block_found)
		rx_submit_block(client, job, blob, n, hash, nonce, share_diff);

	rx_send_result(client, "{\"status\":\"OK\"}");
	protocol_share_record(client, job, true, nonce, share_diff, 0, NULL);
	// the speed of the miner (job assignment, compared with coind_nethash) is in 2^32 hash
	// units as for the other algos, share_add counted the difficulty in hashes
	client->speed -= difficulty / g_current_algo->diff_multiplier * 42 * (1.0 - 1.0 / 4294967296.0);
	object_unlock(job);
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////

static bool randomx_request(YAAMP_CLIENT *client, const char *method, json_value *json, bool *keep)
{
	json_value *params = json_get_object(json, "params");

	if (!strcmp(method, "login")) {
		*keep = params && params->type == json_object && randomx_login(client, params);
		if (!params || params->type != json_object) randomx_send_error(client, 20, "Invalid params");
		return true;
	}
	if (!strcmp(method, "submit")) {
		*keep = params && params->type == json_object && randomx_submit(client, params);
		return true;
	}
	if (!strcmp(method, "keepalived")) {
		*keep = rx_send_result(client, "{\"status\":\"KEEPALIVED\"}") >= 0;
		return true;
	}
	if (!strcmp(method, "getjob")) {
		if (!g_list_client.Find(client)) {
			randomx_send_error(client, 24, "Unauthenticated");
			return true;
		}
		YAAMP_JOB *job = rx_last_job(client->coinid);
		if (!job) job = rx_last_job(0);
		char job_json[1024] = "null";
		if (job) {
			randomx_job_json(job, client, job_json, sizeof(job_json));
			client->jobid_sent = job->id;
			object_unlock(job);
		}
		*keep = rx_send_result(client, job_json) >= 0;
		return true;
	}
	// only mining.update_block (blocknotify) goes to the Bitcoin stratum
	// methods: their subscribe/authorize/submit don't handle cryptonote jobs
	if (!strncmp(method, "mining.", 7) && strcmp(method, "mining.update_block")) {
		randomx_send_error(client, 20, "Not supported");
		*keep = false;
		return true;
	}
	return false;
}

extern const YAAMP_PROTOCOL g_protocol_randomx;
const YAAMP_PROTOCOL g_protocol_randomx = {
	"cryptonote",
	YAAMP_PROTOCOL_CRYPTONOTE,
	NULL,                    // subscribe: login
	randomx_send_difficulty,
	NULL,                    // template_prepare: create_template
	randomx_job_notify,
	true,
	NULL,                    // submit: request
	NULL,
	randomx_init,
	randomx_config,
	randomx_request,
	randomx_send_error,
	randomx_create_template,
	randomx_coind_config,
	randomx_coind_init,
};
