// Stratum protocol families, see protocol.h

#include "stratum.h"

const YAAMP_PROTOCOL *g_protocol = NULL;

extern const YAAMP_PROTOCOL g_protocol_kawpow;
extern const YAAMP_PROTOCOL g_protocol_equihash;
extern const YAAMP_PROTOCOL g_protocol_resistance;

// algo -> protocol family; algos not listed use the Bitcoin stratum (g_protocol NULL)
static const struct {
	const char *algo;
	const YAAMP_PROTOCOL *protocol;
} g_algo_protocols[] = {
	{ "kawpow",     &g_protocol_kawpow }, // RVN, XNA, NEOX, SATOX, ...
	{ "evrprogpow", &g_protocol_kawpow }, // EVR
	{ "meowpow",    &g_protocol_kawpow }, // MEWC
	{ "firopow",    &g_protocol_kawpow }, // FIRO
	{ "sccpow",     &g_protocol_kawpow }, // SCC
	{ "meraki",     &g_protocol_kawpow }, // TLS
	{ "equihash",    &g_protocol_equihash },   // 200,9: ZEC, KMD, ARRR...
	{ "equihash144", &g_protocol_equihash },   // 144,5: BTG, BTCZ, GLINK...
	{ "equihash192", &g_protocol_equihash },   // 192,7: YEC, ZCL, ZER...
	{ "yespowerRES", &g_protocol_resistance }, // RES
	{ NULL, NULL }
};

const YAAMP_PROTOCOL *protocol_for_algo(const char *algo)
{
	if (!algo) return NULL;
	for (int i = 0; g_algo_protocols[i].algo; i++)
		if (!strcmp(g_algo_protocols[i].algo, algo))
			return g_algo_protocols[i].protocol;
	return NULL;
}

void protocol_config(dictionary *ini)
{
	const YAAMP_PROTOCOL *protocol = protocol_for_algo(g_stratum_algo);
	if (protocol && protocol->config) protocol->config(ini);
}

void protocol_init()
{
	g_protocol = protocol_for_algo(g_stratum_algo);
	if (!g_protocol) return;

	stratumlog("%s: %s stratum protocol\n", g_stratum_algo, g_protocol->name);

	// the jobs of the rented remote pools are Bitcoin stratum jobs
	g_stratum_renting = false;

	if (g_protocol->init) g_protocol->init();
}

////////////////////////////////////////////////////////////////////////////////////////

void protocol_nbits_to_target(const char *nbits, unsigned char target[32])
{
	memset(target, 0, 32);
	uint32_t c = (uint32_t) strtoul(nbits, NULL, 16);
	int size = c >> 24;
	uint32_t mantissa = c & 0x007fffff;
	for (int i = 0; i < 3; i++) {
		int pos = 32 - size + i; // byte of the big endian number
		unsigned char b = (mantissa >> (8 * (2 - i))) & 0xff;
		if (pos >= 0 && pos < 32) target[pos] = b;
	}
}

void protocol_diff_to_target(const unsigned char diff1[32], double difficulty, unsigned char target[32])
{
	// target = diff1 / difficulty, with a long double (64 bits of precision are plenty)
	int shift = 0;
	long double t = 0;
	for (int i = 0; i < 32; i++) {
		if (!t && !diff1[i]) continue;
		if (t >= ldexpl(1.0L, 32)) shift += 8; // diff1 is a few significant bytes and zeros
		else t = t * 256.0L + diff1[i];
	}
	if (difficulty > 0) t /= (long double) difficulty;
	// 0xff / 0.002 is 127499.999..., make it 127500 (a clean target for the miners)
	long double r = roundl(t);
	if (r > 0 && fabsl(t - r) < r * 1e-12L) t = r;
	t = ldexpl(t, shift);

	long double max = ldexpl(1.0L, 256);
	if (t >= max) {
		memset(target, 0xff, 32);
		return;
	}
	for (int i = 0; i < 32; i++) {
		long double unit = ldexpl(1.0L, 8 * (31 - i));
		long double b = floorl(t / unit);
		if (b > 255) b = 255;
		if (b < 0) b = 0;
		target[i] = (unsigned char) b;
		t -= b * unit;
	}
}

double protocol_target_to_diff(const unsigned char diff1[32], const unsigned char hash[32])
{
	long double d = 0, h = 0;
	for (int i = 0; i < 32; i++) {
		d = d * 256.0L + diff1[i];
		h = h * 256.0L + hash[i];
	}
	if (h <= 0) return 0;
	return (double) (d / h);
}

bool protocol_hash_le_target(const unsigned char hash[32], const unsigned char target[32])
{
	return memcmp(hash, target, 32) <= 0;
}

bool protocol_hex_param(const char *param, char *out, int hexlen)
{
	if (!param) return false;
	if (param[0] == '0' && (param[1] == 'x' || param[1] == 'X')) param += 2;
	if ((int) strlen(param) != hexlen) return false;
	for (int i = 0; i < hexlen; i++) {
		char c = param[i];
		if (c >= 'A' && c <= 'F') c += 'a' - 'A';
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
		out[i] = c;
	}
	out[hexlen] = '\0';
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////

static bool protocol_submitblock(YAAMP_COIND *coind, const char *block_hex)
{
	size_t len = strlen(block_hex);
	char *params = (char *) malloc(len + 16);
	if (!params) return false;
	sprintf(params, "[\"%s\"]", block_hex);

	json_value *json = rpc_call(&coind->rpc, "submitblock", params);
	free(params);
	if (!json) {
		stratumlog("ERROR %s submitblock, no answer\n", coind->name);
		return false;
	}

	bool b = false;
	json_value *json_error = json_get_object(json, "error");
	if (json_error && json_error->type != json_null) {
		const char *p = json_get_string(json_error, "message");
		stratumlog("ERROR %s submitblock: %s\n", coind->name, p ? p : "error");
	} else {
		json_value *json_result = json_get_object(json, "result");
		b = !json_result || json_result->type == json_null;
		if (!b && json_result->type == json_string)
			stratumlog("ERROR %s submitblock rejected: %s\n", coind->name, json_result->u.string.ptr);
	}
	json_value_free(json);
	return b;
}

bool protocol_submit_block(YAAMP_CLIENT *client, YAAMP_JOB *job, const char *header_hex,
	const char *coinbase_hex, const char *blockid, const char *powhash, double diff_user)
{
	YAAMP_COIND *coind = job->coind;
	YAAMP_JOB_TEMPLATE *templ = job->templ;
	if (!coind || job->block_found) return false;

	size_t size = strlen(header_hex) + strlen(coinbase_hex) + 64;
	for (vector<string>::const_iterator i = templ->txdata.begin(); i != templ->txdata.end(); ++i)
		size += (*i).size();

	char *block_hex = (char *) malloc(size);
	if (!block_hex) return false;

	char count_hex[32];
	ser_compactsize((unsigned int) templ->txcount, count_hex);

	char *p = block_hex;
	p += sprintf(p, "%s%s%s", header_hex, count_hex, coinbase_hex);
	for (vector<string>::const_iterator i = templ->txdata.begin(); i != templ->txdata.end(); ++i)
		p += sprintf(p, "%s", (*i).c_str());

	// POS coins need a zero byte appended to block, the daemon replaces it with the signature
	if (coind->pos) strcat(block_hex, "00");

	bool b = protocol_submitblock(coind, block_hex);
	free(block_hex);

	uint64_t coin_target = decode_compact(templ->nbits);
	if (templ->nbits && !coin_target) coin_target = 0xFFFF000000000000ULL;

	if (b) {
		debuglog("*** ACCEPTED %s %d (diff %g) by %s (id: %d)\n", coind->name, templ->height,
			diff_user, client->sock->ip, client->userid);
		job->block_found = true;

		block_add(client->userid, client->workerid, coind->id, templ->height,
			target_to_diff(coin_target), diff_user, blockid, powhash, templ->has_segwit_txs);

		if (!strcmp(coind->lastnotifyhash, blockid))
			block_confirm(coind->id, blockid);
	} else {
		debuglog("*** REJECTED :( %s block %d %d txs\n", coind->name, templ->height, templ->txcount);
		rejectlog("REJECTED %s block %d\n", coind->symbol, templ->height);
	}
	return b;
}

////////////////////////////////////////////////////////////////////////////////////////

void protocol_share_accepted(YAAMP_CLIENT *client, YAAMP_JOB *job, char *nonce, double share_diff)
{
	client_send_result(client, "true");
	client_record_difficulty(client);
	client->submit_bad = 0;
	client->shares++;

	char extranonce2[2] = "";
	share_add(client, job, true, extranonce2, job->templ->ntime, nonce, share_diff, 0);
}

void protocol_share_rejected(YAAMP_CLIENT *client, YAAMP_JOB *job, int error, const char *message, char *nonce)
{
	if (job && job->deleted) {
		client_send_result(client, "true");
		return;
	}

	client_send_error(client, error, message);

	char extranonce2[2] = "";
	char ntime[16] = "00000000";
	share_add(client, job, false, extranonce2, job ? job->templ->ntime : ntime, nonce, 0, error);
	client->submit_bad++;

	if (g_debuglog_hash)
		debuglog("ERROR %s, %s job %x, nonce1 %s, nonce %s\n", message, client->sock->ip,
			job ? job->id : 0, client->extranonce1, nonce);
}
