// Zcash family stratum: equihash (200,9), equihash144 (144,5), equihash192 (192,7), and the
// template/notify hooks of yespowerRES (Resistance)
//
// Block header of the Zcash family (140 bytes, then the Equihash solution with its compact
// size prefix):
//
//   0 nVersion   4 hashPrevBlock   36 hashMerkleRoot   68 hashReserved (32)
//   100 nTime   104 nBits   108 nNonce (32)   140 compactsize(solution) solution
//
// hashReserved is hashFinalSaplingRoot (Sapling), hashLightClientRoot (Heartwood),
// hashBlockCommitments (NU5) in Zcash and its forks, and nHeight + 28 zero bytes in
// Bitcoin Gold (whose getblocktemplate is the Bitcoin one). The Equihash input is the 140
// byte header (the 108 byte "I" and the nonce), the block id and the proof of work hash is
// sha256d(header || compactsize || solution).
//
// Stratum (ZIP-301, the protocol of the Equihash miners: lolMiner, GMiner, miniZ, EWBF,
// Bminer..., and of the NOMP/MiningCore pools):
//
//  mining.subscribe  -> [session id, nonce1]   nonce1: the first 4 bytes of the header nonce
//  mining.set_target <- ["target"]             64 hex digits, big endian
//  mining.notify     <- [job id, version, prevhash, merkleroot, reserved, time, bits, clean]
//                       the header fields as serialized (little endian hexadecimal)
//  mining.submit     -> [worker, job id, time, nonce2, solution]
//                       nonce2: the other 28 bytes of the nonce, solution: hex with (or
//                       without) its compact size prefix
//
// Coinbase: Zcash forks return the complete coinbase in getblocktemplate ("coinbasetxn",
// with the founders reward, funding streams, lockbox... and paying the -mineraddress or a
// wallet key of the daemon) and the header roots ("defaultroots", or the older
// "finalsaplingroothash"...): the coinbase is used as is, and the extranonce is only the
// header nonce. Without "coinbasetxn" (Bitcoin Gold, forks which removed it), the pool
// coinbase of coinbase_create() is used with a unique extranonce per template (a Sapling
// v4 transaction for the forks with a "finalsaplingroothash").
//
// Share difficulty: difficulty 1 is the target 0x0007ffff... (NOMP/MiningCore, all the
// variants), so a share of difficulty D is 2^13 D solutions. The shares table has D
// (diff_multiplier 1: D / 2^19 would be rounded to 0 by the 6 decimals of share_write() for
// the small GPU difficulties), so the web hashrate constant of these algos is 2^23 (2^13
// solutions per difficulty, times 1024 like the 2^42 of the other algos) for Sol/s. The block
// difficulties (blocks table) are in Bitcoin units like the other algos: a Zcash block of
// Bitcoin difficulty d is d * 2^32 solutions, so the web profitability is per MSol/day.
//
// Conf file ([STRATUM] section): equihash_n, equihash_k (e.g. 48 and 5 for the regtest of
// zcashd), equihash_personalization, equihash_header (auto, zcash or btg); [EQUIHASH]
// section: <coin symbol> = <personalization> for the coins of the stratum. The
// personalization of a coin is, in this order: [EQUIHASH] <symbol>, equihash_personalization,
// the table below, the default of the algo.

#include "stratum.h"
#include "algos/equihash/equihash_verify.h"

#include <map>

#define EQ_NONCE1_HEXLEN 8 // 4 bytes (client->extranonce1)

static const struct {
	const char *algo;
	int n, k;
	const char *pers;
} g_eq_algos[] = {
	{ "equihash",    200, 9, "ZcashPoW" },
	{ "equihash144", 144, 5, "BgoldPoW" },
	{ "equihash192", 192, 7, "ZcashPoW" },
	{ NULL, 0, 0, NULL }
};

// personalization of the coins which do not use "ZcashPoW" (from their crypto/equihash.cpp),
// first match; n = 0 matches any parameters
static const struct {
	const char *symbol;
	int n, k;
	const char *pers;
} g_eq_coins[] = {
	{ "BTG",   200, 9, "ZcashPoW" }, // Bitcoin Gold before its Equihash fork (block 536200)
	{ "BTG",    48, 5, "ZcashPoW" }, // same, regtest
	{ "BTG",     0, 0, "BgoldPoW" }, // 144,5 (96,5 on regtest)
	{ "BTCZ",  144, 5, "BitcoinZ" },
	{ "GLINK", 144, 5, "sngemPoW" }, // GemLink
	{ "BTH",   144, 5, "BethdPoW" }, // Bithereum
	{ "ZER",     0, 0, "ZERO_PoW" }, // Zero (192,7)
	{ NULL, 0, 0, NULL }
};

enum { EQ_HEADER_AUTO = 0, EQ_HEADER_ZCASH, EQ_HEADER_BTG };

static int g_eq_n = 0, g_eq_k = 0;
static char g_eq_pers[16] = "";
static int g_eq_header = EQ_HEADER_AUTO;
static std::map<std::string, std::string> g_eq_coin_pers; // symbol (upper case) -> personalization

static unsigned char g_diff1[32];

static void eq_config(dictionary *ini)
{
	g_eq_n = iniparser_getint(ini, "STRATUM:equihash_n", 0);
	g_eq_k = iniparser_getint(ini, "STRATUM:equihash_k", 0);

	const char *p = iniparser_getstring(ini, "STRATUM:equihash_personalization", NULL);
	if (p) snprintf(g_eq_pers, 9, "%s", p);

	p = iniparser_getstring(ini, "STRATUM:equihash_header", NULL);
	if (p && !strcasecmp(p, "zcash")) g_eq_header = EQ_HEADER_ZCASH;
	else if (p && !strcasecmp(p, "btg")) g_eq_header = EQ_HEADER_BTG;

	char section[] = "equihash";
	int nkeys = iniparser_getsecnkeys(ini, section);
	char **keys = nkeys > 0 ? iniparser_getseckeys(ini, section) : NULL;
	for (int i = 0; keys && i < nkeys; i++) {
		const char *value = iniparser_getstring(ini, keys[i], NULL);
		const char *symbol = strchr(keys[i], ':');
		if (!value || !symbol) continue;
		char sym[64];
		snprintf(sym, sizeof(sym), "%s", symbol + 1);
		string_upper(sym);
		g_eq_coin_pers[sym] = std::string(value).substr(0, 8);
	}
	free(keys);
}

static void eq_init()
{
	int n = 0, k = 0;
	for (int i = 0; g_eq_algos[i].algo; i++)
		if (!strcmp(g_eq_algos[i].algo, g_stratum_algo)) {
			n = g_eq_algos[i].n;
			k = g_eq_algos[i].k;
		}
	if (!g_eq_n || !g_eq_k) {
		g_eq_n = n;
		g_eq_k = k;
	}
	if (!equihash_params_ok(g_eq_n, g_eq_k))
		yaamp_error("unsupported equihash_n/equihash_k");

	// share difficulty 1: 0x0007ffff...
	memset(g_diff1, 0xff, 32);
	g_diff1[0] = 0x00;
	g_diff1[1] = 0x07;

	stratumlog("%s: equihash %d,%d%s%s, solution %d bytes\n", g_stratum_algo, g_eq_n, g_eq_k,
		g_eq_pers[0] ? ", personalization " : "", g_eq_pers, (int) equihash_solution_size(g_eq_n, g_eq_k));
	for (std::map<std::string, std::string>::const_iterator i = g_eq_coin_pers.begin(); i != g_eq_coin_pers.end(); ++i)
		stratumlog("%s: %s personalization %s\n", g_stratum_algo, i->first.c_str(), i->second.c_str());
}

static void eq_personalization(const char *symbol, int n, int k, char *pers)
{
	char sym[64];
	snprintf(sym, sizeof(sym), "%s", symbol ? symbol : "");
	string_upper(sym);

	std::map<std::string, std::string>::const_iterator i = g_eq_coin_pers.find(sym);
	if (i != g_eq_coin_pers.end()) {
		snprintf(pers, 9, "%s", i->second.c_str());
		return;
	}
	if (g_eq_pers[0]) {
		strcpy(pers, g_eq_pers);
		return;
	}
	for (int c = 0; g_eq_coins[c].symbol; c++) {
		if (strcmp(g_eq_coins[c].symbol, sym)) continue;
		if (g_eq_coins[c].n && (g_eq_coins[c].n != n || g_eq_coins[c].k != k)) continue;
		strcpy(pers, g_eq_coins[c].pers);
		return;
	}
	strcpy(pers, "ZcashPoW");
	for (int a = 0; g_eq_algos[a].algo; a++)
		if (!strcmp(g_eq_algos[a].algo, g_stratum_algo) && g_eq_algos[a].n == n && g_eq_algos[a].k == k)
			strcpy(pers, g_eq_algos[a].pers);
}

////////////////////////////////////////////////////////////////////////////////////////
// helpers

static bool hex32(const char *hex)
{
	return hex && strlen(hex) == 64 && ishexa((char *) hex, 64);
}

// displayed uint256 (GetHex) -> serialized bytes
static void uint256_ser(const char *display_hex, unsigned char out[32])
{
	unsigned char b[32];
	binlify(b, display_hex);
	for (int i = 0; i < 32; i++) out[i] = b[31 - i];
}

static const char *gbt_string(json_value *gbt, const char *object, const char *name)
{
	json_value *o = object ? json_get_object(gbt, object) : gbt;
	if (!o || o->type != json_object) return NULL;
	return json_get_string(o, name);
}

// compact size at hex[pos]: value and length in hex digits, false if truncated
static bool read_compactsize(const char *hex, size_t hexlen, size_t pos, uint64_t *value, size_t *len)
{
	if (pos + 2 > hexlen) return false;
	unsigned char b[9];
	binlify(b, string(hex + pos, 2).c_str());
	int bytes = b[0] < 0xfd ? 0 : b[0] == 0xfd ? 2 : b[0] == 0xfe ? 4 : 8;
	if (pos + 2 + 2*bytes > hexlen) return false;
	if (!bytes) {
		*value = b[0];
	} else {
		binlify(b + 1, string(hex + pos + 2, 2*bytes).c_str());
		*value = 0;
		for (int i = bytes; i >= 1; i--) *value = (*value << 8) | b[i];
	}
	*len = 2 + 2*bytes;
	return true;
}

// the coinbase of the daemon ("coinbasetxn" data, transaction version 1 to 4) split around the
// end of its scriptSig, where the pool extranonce (a push of extranonce_size bytes) goes:
// coinbase = coinb1 || extranonce || coinb2
static bool coinbasetxn_split(const char *data, int extranonce_size, char *coinb1, size_t size1,
	char *coinb2, size_t size2)
{
	size_t hexlen = strlen(data);
	if (hexlen < 2*(4+1+36+1+4+1+4) || !ishexa((char *) data, (int) hexlen)) return false;

	unsigned char h[4];
	binlify(h, string(data, 8).c_str());
	uint32_t header = h[0] | (h[1] << 8) | (h[2] << 16) | ((uint32_t) h[3] << 24);
	uint32_t version = header & 0x7fffffff;
	if (version > 4) return false; // v5 (NU5) coinbases are not modified (ZIP-244 txid)

	size_t pos = 8;
	if (header & 0x80000000) pos += 8; // nVersionGroupId

	uint64_t count, script_len;
	size_t l;
	if (!read_compactsize(data, hexlen, pos, &count, &l) || count != 1) return false;
	pos += l + 2*36; // prevout
	if (!read_compactsize(data, hexlen, pos, &script_len, &l)) return false;
	size_t script_pos = pos + l;
	size_t script_end = script_pos + 2*script_len;
	if (script_end > hexlen) return false;

	uint64_t new_len = script_len + 1 + extranonce_size;
	if (new_len > 100) return false; // consensus limit of the coinbase scriptSig

	char len_hex[32];
	ser_compactsize(new_len, len_hex);
	if (script_pos + strlen(len_hex) + 2*script_len + 2 + 1 > size1 || hexlen - script_end + 1 > size2)
		return false;

	string c1 = string(data, pos) + len_hex + string(data + script_pos, 2*script_len);
	char push[8];
	sprintf(push, "%02x", extranonce_size);
	c1 += push;
	strcpy(coinb1, c1.c_str());
	strcpy(coinb2, data + script_end);
	return true;
}

// Bitcoin v1 coinbase of coinbase_create() (coinb1/coinb2) -> Zcash transaction:
// v3 (Overwinter) or v4 (Sapling) header and trailer, nExpiryHeight 0 as zcashd before NU5
static void coinbase_to_zcash(string &coinbase, int version)
{
	string body = coinbase.substr(8, coinbase.size() - 8);
	if (version == 4) coinbase = "04000080" "85202f89" + body + "00000000" "0000000000000000" "000000";
	else coinbase = "03000080" "7082c403" + body + "00000000" "00";
}

////////////////////////////////////////////////////////////////////////////////////////

static bool eq_template_prepare(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, json_value *gbt)
{
	// (n,k): Bitcoin Gold gives them in the template, else the conf/algo
	int n = g_eq_n, k = g_eq_k;
	json_int_t gn = json_get_int(gbt, "equihashn"), gk = json_get_int(gbt, "equihashk");
	if (gn > 0 && gk > 0) {
		n = (int) gn;
		k = (int) gk;
	}
	if (!equihash_params_ok(n, k)) {
		stratumlog("ERROR %s: unsupported equihash parameters %d,%d\n", coind->symbol, n, k);
		return false;
	}
	templ->eq_n = n;
	templ->eq_k = k;
	eq_personalization(coind->symbol, n, k, templ->eq_pers);

	json_value *cbtxn = json_get_object(gbt, "coinbasetxn");
	const char *cb_data = (cbtxn && cbtxn->type == json_object) ? json_get_string(cbtxn, "data") : NULL;
	const char *saplingroot = json_get_string(gbt, "finalsaplingroothash");

	int mode = g_eq_header;
	if (mode == EQ_HEADER_AUTO)
		mode = (cb_data || saplingroot || json_get_object(gbt, "defaultroots")) ? EQ_HEADER_ZCASH : EQ_HEADER_BTG;

	unsigned char merkle[32], reserved[32];
	memset(reserved, 0, 32);

	if (cb_data) {
		// complete coinbase of the daemon, used as is
		if (templ->has_filtered_txs) {
			stratumlog("ERROR %s: max_txs_per_block cannot be used with the coinbase of the daemon\n", coind->symbol);
			return false;
		}
		if (strlen(cb_data) % 2 || !ishexa((char *) cb_data, strlen(cb_data)) ||
			strlen(cb_data) >= sizeof(templ->proto_coinbase)) {
			stratumlog("ERROR %s: invalid coinbasetxn\n", coind->symbol);
			return false;
		}
		strcpy(templ->proto_coinbase, cb_data);

		const char *root = gbt_string(gbt, "defaultroots", "merkleroot");
		if (hex32(root)) {
			uint256_ser(root, merkle);
		} else {
			const char *cb_hash = json_get_string(cbtxn, "hash");
			if (!hex32(cb_hash)) {
				stratumlog("ERROR %s: coinbasetxn without hash\n", coind->symbol);
				return false;
			}
			char first[65];
			string_be(cb_hash, first);
			first[64] = '\0';
			string m = merkle_with_first(templ->txsteps, first);
			binlify(merkle, m.c_str());
		}
	} else {
		// pool coinbase (coinbase_create), unique per template
		if (!templ->coinb1[0] || !templ->coinb2[0]) return false;

		static uint32_t counter = 0;
		CommonLock(&g_job_create_mutex);
		uint32_t c = ++counter;
		CommonUnlock(&g_job_create_mutex);
		char extranonce[32];
		sprintf(extranonce, "%08x%08x", c, (uint32_t) time(NULL));

		string coinbase = string(templ->coinb1) + extranonce + templ->coinb2;
		if (mode == EQ_HEADER_ZCASH && saplingroot)
			coinbase_to_zcash(coinbase, 4);
		if (coinbase.size() >= sizeof(templ->proto_coinbase)) {
			stratumlog("ERROR %s coinbase too large\n", coind->symbol);
			return false;
		}
		strcpy(templ->proto_coinbase, coinbase.c_str());

		unsigned char *bin = (unsigned char *) malloc(coinbase.size() / 2 + 1);
		if (!bin) return false;
		binlify(bin, coinbase.c_str());
		char hash[128] = { 0 };
		sha256_double_hash_hex((char *) bin, hash, (int) coinbase.size() / 2);
		free(bin);
		string m = merkle_with_first(templ->txsteps, hash);
		binlify(merkle, m.c_str());
	}

	if (mode == EQ_HEADER_BTG) {
		uint32_t height = (uint32_t) templ->height;
		memcpy(reserved, &height, 4);
	} else {
		// NU5: hashBlockCommitments; before: the legacy fields (hashFinalSaplingRoot /
		// hashLightClientRoot, the same value), or the chain history root (Heartwood)
		const char *r = gbt_string(gbt, "defaultroots", "blockcommitmentshash");
		if (!hex32(r)) r = json_get_string(gbt, "blockcommitmentshash");
		if (!hex32(r)) r = json_get_string(gbt, "finalsaplingroothash");
		if (!hex32(r)) r = json_get_string(gbt, "lightclientroothash");
		if (!hex32(r)) r = gbt_string(gbt, "defaultroots", "chainhistoryroot");
		if (hex32(r)) uint256_ser(r, reserved);
	}

	// header fields: version, prevhash, merkle root, reserved (100 bytes)
	unsigned char header[100];
	uint32_t version = (uint32_t) strtoul(templ->version, NULL, 16);
	memcpy(header, &version, 4);
	uint256_ser(templ->prevhash_hex, header + 4);
	memcpy(header + 36, merkle, 32);
	memcpy(header + 68, reserved, 32);
	hexlify(templ->proto_header, header, 100);

	// block target: the template one (Komodo staked chains) or bits
	unsigned char target[32];
	const char *t = json_get_string(gbt, "target");
	if (hex32(t)) binlify(target, t);
	else protocol_nbits_to_target(templ->nbits, target);
	hexlify(templ->proto_target, target, 32);

	// mining.notify fields, as serialized
	char ver_hex[16], prev_hex[80], merkle_hex[80], reserved_hex[80], time_hex[16], bits_hex[16];
	uint32_t ntime = (uint32_t) strtoul(templ->ntime, NULL, 16);
	uint32_t nbits = (uint32_t) strtoul(templ->nbits, NULL, 16);
	hexlify(ver_hex, header, 4);
	hexlify(prev_hex, header + 4, 32);
	hexlify(merkle_hex, merkle, 32);
	hexlify(reserved_hex, reserved, 32);
	hexlify(time_hex, (unsigned char *) &ntime, 4);
	hexlify(bits_hex, (unsigned char *) &nbits, 4);
	snprintf(templ->proto_notify, sizeof(templ->proto_notify), "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"",
		ver_hex, prev_hex, merkle_hex, reserved_hex, time_hex, bits_hex);

	return true;
}

////////////////////////////////////////////////////////////////////////////////////////

static int eq_send_difficulty(YAAMP_CLIENT *client, double difficulty)
{
	unsigned char target[32];
	char hex[80];
	protocol_diff_to_target(g_diff1, difficulty, target);
	hexlify(hex, target, 32);
	return client_call(client, "mining.set_target", "[\"%s\"]", hex);
}

static bool eq_subscribe(YAAMP_CLIENT *client, json_value *json_params)
{
	// nonce1: the unique 4 byte extranonce1 of the client, the miner sets the 28 other
	// bytes of the header nonce
	client->extranonce2size_default = client->extranonce2size = 32 - EQ_NONCE1_HEXLEN/2;
	strcpy(client->extranonce1_last, client->extranonce1);
	client->extranonce2size_last = client->extranonce2size;
	strcpy(client->extranonce1_reconnect, client->extranonce1);
	client->extranonce2size_reconnect = client->extranonce2size;
	client->reconnectable = false; // no client.reconnect/set_extranonce with this protocol

	if (g_debuglog_client)
		debuglog("new %s client with nonce %s\n", g_stratum_algo, client->extranonce1);

	return client_send_result(client, "[\"%s\",\"%s\"]", client->notify_id, client->extranonce1) >= 0;
}

static void eq_job_notify(YAAMP_JOB *job, YAAMP_CLIENT *client, char *buffer, int size)
{
	snprintf(buffer, size, "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"%x\",%s,true]}\n",
		job->id, job->templ->proto_notify);
}

static bool valid_string_params(json_value *json_params, int n)
{
	if (json_params->u.array.length < (unsigned int) n) return false;
	for (int p = 0; p < n; p++)
		if (!json_is_string(json_params->u.array.values[p])) return false;
	return true;
}

static bool eq_submit(YAAMP_CLIENT *client, json_value *json_params)
{
	// [worker, job id, time, nonce2, solution]
	if (!valid_string_params(json_params, 5)) {
		debuglog("%s - %s bad message\n", client->username, client->sock->ip);
		client->submit_bad++;
		return false;
	}

	const char *jobid_str = json_params->u.array.values[1]->u.string.ptr;
	if (strlen(jobid_str) > 32) {
		clientlog(client, "bad json, wrong jobid len");
		client->submit_bad++;
		return false;
	}

	char nonce1[80];
	snprintf(nonce1, sizeof(nonce1), "%s", client->extranonce1);
	int nonce2_hexlen = 64 - (int) strlen(nonce1);

	char ntime[16] = { 0 }, nonce2[80] = { 0 }, key[80] = { 0 };
	bool time_ok = protocol_hex_param(json_params->u.array.values[2]->u.string.ptr, ntime, 8);
	bool nonce_ok = nonce2_hexlen > 0 && protocol_hex_param(json_params->u.array.values[3]->u.string.ptr, nonce2, nonce2_hexlen);
	const char *sol_param = json_params->u.array.values[4]->u.string.ptr;

	int jobid = htoi(jobid_str);
	YAAMP_JOB *job = (YAAMP_JOB *) object_find(&g_list_job, jobid, true);
	if (!job) {
		protocol_share_rejected(client, NULL, 21, "Invalid job id", nonce2);
		return true;
	}
	if (job->deleted) {
		client_send_result(client, "true");
		object_unlock(job);
		return true;
	}
	YAAMP_JOB_TEMPLATE *templ = job->templ;
	if (!job->coind || !templ->proto_header[0] || !templ->eq_n) {
		protocol_share_rejected(client, job, 21, "Invalid job", nonce2);
		object_unlock(job);
		return true;
	}
	if (!time_ok || !nonce_ok) {
		protocol_share_rejected(client, job, 20, time_ok ? "Invalid nonce2 size" : "Invalid time", nonce2);
		object_unlock(job);
		return true;
	}

	// time: from the job time to 2 hours in the future (the consensus limit)
	unsigned char t[4];
	binlify(t, ntime);
	uint32_t tsub = t[0] | (t[1] << 8) | (t[2] << 16) | ((uint32_t) t[3] << 24);
	uint32_t tjob = (uint32_t) strtoul(templ->ntime, NULL, 16);
	if (tsub < tjob || tsub > (uint32_t) time(NULL) + 7200) {
		protocol_share_rejected(client, job, 20, "Time out of range", nonce2);
		object_unlock(job);
		return true;
	}

	// solution, with or without its compact size prefix
	size_t sol_size = equihash_solution_size(templ->eq_n, templ->eq_k);
	char prefix[32];
	ser_compactsize(sol_size, prefix);
	if (sol_param[0] == '0' && (sol_param[1] == 'x' || sol_param[1] == 'X')) sol_param += 2;
	size_t sol_hexlen = strlen(sol_param);
	if (sol_hexlen == 2*sol_size + strlen(prefix)) {
		if (strncasecmp(sol_param, prefix, strlen(prefix))) {
			protocol_share_rejected(client, job, 20, "Invalid solution size prefix", nonce2);
			object_unlock(job);
			return true;
		}
		sol_param += strlen(prefix);
	} else if (sol_hexlen != 2*sol_size) {
		protocol_share_rejected(client, job, 20, "Invalid solution size", nonce2);
		object_unlock(job);
		return true;
	}
	if (!ishexa((char *) sol_param, (int) 2*sol_size)) {
		protocol_share_rejected(client, job, 20, "Invalid solution", nonce2);
		object_unlock(job);
		return true;
	}

	// block: header (140) || compact size || solution
	size_t block_len = 140 + strlen(prefix)/2 + sol_size;
	unsigned char *block = (unsigned char *) malloc(block_len);
	char *header_hex = (char *) malloc(2*block_len + 1);
	if (!block || !header_hex) {
		free(block); free(header_hex);
		object_unlock(job);
		return false;
	}
	binlify(block, templ->proto_header);           // version, prev, merkle, reserved
	memcpy(block + 100, t, 4);                     // time (as submitted, serialized)
	uint32_t nbits = (uint32_t) strtoul(templ->nbits, NULL, 16);
	memcpy(block + 104, &nbits, 4);
	binlify(block + 108, nonce1);                  // nonce = nonce1 || nonce2
	binlify(block + 108 + strlen(nonce1)/2, nonce2);
	binlify(block + 140, prefix);
	binlify(block + 140 + strlen(prefix)/2, sol_param);
	hexlify(header_hex, block, (int) block_len);

	unsigned char hash[32], hash_be[32];
	sha256_double_hash((char *) block, (char *) hash, (int) block_len);
	for (int i = 0; i < 32; i++) hash_be[i] = hash[31 - i];
	char hash_hex[80];
	hexlify(hash_hex, hash_be, 32);

	// duplicates: the hash covers the time, the nonce and the solution (a nonce can have
	// several solutions)
	strncpy(key, hash_hex, 48);
	char empty[2] = "";
	if (share_find(job->id, empty, templ->ntime, key, client->extranonce1)) {
		protocol_share_rejected(client, job, 22, "Duplicate share", key);
		free(block); free(header_hex);
		object_unlock(job);
		return true;
	}

	unsigned char share_target[32], block_target[32];
	protocol_diff_to_target(g_diff1, client->difficulty_actual, share_target);
	binlify(block_target, templ->proto_target);
	bool is_block = protocol_hash_le_target(hash_be, block_target);
	if (!is_block && !protocol_hash_le_target(hash_be, share_target)) {
		protocol_share_rejected(client, job, 26, "Low difficulty share", key);
		free(block); free(header_hex);
		object_unlock(job);
		return true;
	}

	if (!equihash_verify(templ->eq_n, templ->eq_k, templ->eq_pers, block, 140,
			block + 140 + strlen(prefix)/2, sol_size)) {
		protocol_share_rejected(client, job, 20, "Invalid solution", key);
		free(block); free(header_hex);
		object_unlock(job);
		return true;
	}

	double share_diff = protocol_target_to_diff(g_diff1, hash_be);
	if (g_debuglog_hash)
		debuglog("submit %s (uid %d) job %x nonce2 %s hash %s diff %.4f/%.4f\n", client->sock->ip,
			client->userid, job->id, nonce2, hash_hex, share_diff, client->difficulty_actual);

	if (is_block && !job->block_found) {
		// block difficulty_user in Bitcoin units, like the network difficulty of the web
		unsigned char btc_diff1[32] = { 0 };
		btc_diff1[4] = 0xff; btc_diff1[5] = 0xff;
		protocol_submit_block(client, job, header_hex, templ->proto_coinbase, hash_hex, hash_hex,
			protocol_target_to_diff(btc_diff1, hash_be));
	}
	free(block);
	free(header_hex);

	protocol_share_accepted(client, job, key, share_diff);
	object_unlock(job);

	if (client->shares <= 200 && (client->shares % 50) == 0) {
		if (!client_ask_stats(client)) client->stats = false;
	}
	return true;
}

static bool eq_method(YAAMP_CLIENT *client, const char *method, json_value *json_params, bool *keep)
{
	// some miners report their hashrate, ask for extranonce updates or suggest a target
	if (!strcmp(method, "mining.hashrate") || !strcmp(method, "mining.extranonce.subscribe") ||
		!strcmp(method, "mining.suggest_target")) {
		*keep = client_send_result(client, "true") >= 0;
		return true;
	}
	return false;
}

extern const YAAMP_PROTOCOL g_protocol_equihash;
const YAAMP_PROTOCOL g_protocol_equihash = {
	"equihash (ZIP-301)",
	YAAMP_PROTOCOL_EQUIHASH,
	eq_subscribe,
	eq_send_difficulty,
	eq_template_prepare,
	eq_job_notify,
	false,
	eq_submit,
	eq_method,
	eq_init,
	eq_config,
};

////////////////////////////////////////////////////////////////////////////////////////
// yespowerRES (Resistance, ResistancePlatform/resistance-core): the Zcash 140 byte header
// (hashFinalSaplingRoot, 256 bit nonce) without Equihash solution, the pow hash is yespower
// 1.0 N=4096 r=32 of these 140 bytes and the block id their sha256d. Its miner
// (ResistancePlatform/resistance-miner, a cpuminer fork) speaks the Bitcoin stratum, with
// hashFinalSaplingRoot as a 10th mining.notify parameter (word swapped, like the prevhash)
// and the 32 bit nonce of the Bitcoin stratum as the first 4 bytes of the header nonce (the
// others are zero), so only the template and the notify message differ from the Bitcoin
// stratum (the 140 byte header is built in client_submit.cpp).
//
// The daemon has no "coinbasevalue", its coinbase ("coinbasetxn", a Sapling v4 transaction)
// is used with the extranonce appended to its scriptSig.

static bool res_template_prepare(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, json_value *gbt)
{
	json_value *cbtxn = json_get_object(gbt, "coinbasetxn");
	const char *cb_data = (cbtxn && cbtxn->type == json_object) ? json_get_string(cbtxn, "data") : NULL;
	if (cb_data) {
		if (templ->has_filtered_txs) {
			stratumlog("ERROR %s: max_txs_per_block cannot be used with the coinbase of the daemon\n", coind->symbol);
			return false;
		}
		// extranonce1 (4 bytes) + extranonce2 (YAAMP_EXTRANONCE2_SIZE)
		if (!coinbasetxn_split(cb_data, 4 + YAAMP_EXTRANONCE2_SIZE, templ->coinb1, sizeof(templ->coinb1),
				templ->coinb2, sizeof(templ->coinb2))) {
			stratumlog("ERROR %s: unable to use the coinbasetxn of the template\n", coind->symbol);
			return false;
		}
	} else if (!templ->coinb1[0] || !templ->coinb2[0]) {
		return false;
	}

	const char *root = json_get_string(gbt, "finalsaplingroothash");
	if (!hex32(root)) root = "0000000000000000000000000000000000000000000000000000000000000000";
	strcpy(templ->extradata_hex, root);
	ser_string_be2(root, templ->extradata_be, 8);
	templ->extradata_be[64] = '\0';
	return true;
}

static void res_job_notify(YAAMP_JOB *job, YAAMP_CLIENT *client, char *buffer, int size)
{
	YAAMP_JOB_TEMPLATE *templ = job->templ;
	snprintf(buffer, size, "{\"id\":null,\"method\":\"mining.notify\",\"params\":"
		"[\"%x\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true,\"%s\"]}\n",
		job->id, templ->prevhash_be, templ->coinb1, templ->coinb2, templ->txmerkles,
		templ->version, templ->nbits, templ->ntime, templ->extradata_be);
}

extern const YAAMP_PROTOCOL g_protocol_resistance;
const YAAMP_PROTOCOL g_protocol_resistance = {
	"resistance (Bitcoin stratum, 140 byte header)",
	YAAMP_PROTOCOL_EQUIHASH,
	NULL,
	NULL,
	res_template_prepare,
	res_job_notify,
	false,
	NULL,
	NULL,
	NULL,
	NULL,
};
