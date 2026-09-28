// KawPoW family stratum (kawpow, evrprogpow, meowpow, firopow, sccpow, meraki)
//
// The de facto protocol of the KawPoW pools and miners (kawpowminer, T-Rex, NBMiner,
// TeamRedMiner, SRBMiner..., and the MiningCore Progpow pools):
//
//  mining.subscribe  -> [[["mining.set_target", id], ["mining.notify", id]], "nonce1"]
//                       nonce1 (2 bytes, 4 hex digits) is the prefix of the 64 bit nonces
//                       the miner may use, it makes the search space of every miner unique
//  mining.set_target <- ["target"]   the share target, 64 hex digits
//  mining.notify     <- [job id, header hash, seed hash, target, clean, height, "nbits"]
//  mining.submit     -> [worker, job id, "0x" nonce (16 hex), "0x" header hash, "0x" mix hash]
//
// The header hash is the sha256d of the 80 byte header ending with nHeight, where Bitcoin
// has the nonce (CKAWPOWInput/CProgPowHeader of the daemons). The block header is these
// 80 bytes followed by nNonce64 and mix_hash (120 bytes).
//
// The coinbase has no part rolled by the miners (the nonce prefix is enough), so the header
// hash is the same for all the miners of a job. Each template gets its own extranonce in the
// coinbase (a counter) so that two jobs never have the same header hash.
//
// Share difficulty: difficulty 1 is the target 0x00000000ff000000... (0xffff for firopow/
// sccpow, as MiningCore does), so a share of difficulty D is ~ D * 2^32 hashes, like a
// Bitcoin share of difficulty D: the difficulty stored in the shares table is the stratum
// difficulty (diff_multiplier 1 in g_algos) and the web hashrate needs no algo factor.

#include "stratum.h"
#include "algos/progpow/progpow.h"

static const progpow_variant *g_variant = NULL;
static unsigned char g_diff1[32];

#define KAWPOW_NONCE1_HEXLEN 4

static void kawpow_init()
{
	g_variant = progpow_find_variant(g_stratum_algo);
	if (!g_variant) yaamp_error("no progpow variant for this algo");
	progpow_diff1_target(g_variant, g_diff1);
}

////////////////////////////////////////////////////////////////////////////////////////

static void hex_target(double difficulty, char *hex)
{
	unsigned char target[32];
	protocol_diff_to_target(g_diff1, difficulty, target);
	hexlify(hex, target, 32);
}

static int kawpow_send_difficulty(YAAMP_CLIENT *client, double difficulty)
{
	char target[80];
	hex_target(difficulty, target);
	return client_call(client, "mining.set_target", "[\"%s\"]", target);
}

static bool nonce1_in_use(const char *nonce1)
{
	bool used = false;
	g_list_client.Enter();
	for (CLI li = g_list_client.first; li; li = li->next) {
		YAAMP_CLIENT *cli = (YAAMP_CLIENT *) li->data;
		if (cli->deleted) continue;
		if (!strcmp(cli->extranonce1_default, nonce1)) {
			used = true;
			break;
		}
	}
	g_list_client.Leave();
	return used;
}

static bool kawpow_subscribe(YAAMP_CLIENT *client, json_value *json_params)
{
	// 2 bytes nonce prefix, unique among the connected miners (after 65536 connections the
	// counter wraps)
	char nonce1[32];
	for (int tries = 0; tries < 64; tries++) {
		char en1[32];
		get_next_extraonce1(en1);
		strcpy(nonce1, en1 + 8 - KAWPOW_NONCE1_HEXLEN);
		if (!nonce1_in_use(nonce1)) break;
	}

	strcpy(client->extranonce1_default, nonce1);
	client->extranonce2size_default = 0;
	strcpy(client->extranonce1, nonce1);
	client->extranonce2size = 0;
	strcpy(client->extranonce1_last, nonce1);
	client->extranonce2size_last = 0;
	strcpy(client->extranonce1_reconnect, nonce1);
	client->extranonce2size_reconnect = 0;
	client->reconnectable = false; // no client.reconnect/set_extranonce with this protocol

	if (g_debuglog_client)
		debuglog("new %s client with nonce %s\n", g_stratum_algo, nonce1);

	return client_send_result(client, "[[[\"mining.set_target\",\"%s\"],[\"mining.notify\",\"%s\"]],\"%s\"]",
		client->notify_id, client->notify_id, nonce1) >= 0;
}

static void kawpow_job_notify(YAAMP_JOB *job, YAAMP_CLIENT *client, char *buffer, int size)
{
	YAAMP_JOB_TEMPLATE *templ = job->templ;
	char target[80];
	hex_target(client ? client->difficulty_actual : g_stratum_difficulty, target);

	snprintf(buffer, size, "{\"id\":null,\"method\":\"mining.notify\",\"params\":"
		"[\"%x\",\"%s\",\"%s\",\"%s\",true,%d,\"%s\"]}\n",
		job->id, templ->proto_hash, templ->proto_seed, target, templ->height, templ->nbits);
}

////////////////////////////////////////////////////////////////////////////////////////

static bool kawpow_template_prepare(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, json_value *gbt)
{
	static uint32_t counter = 0;
	char extranonce[32];

	// unique coinbase per template (the miners do not roll it)
	CommonLock(&g_job_create_mutex);
	uint32_t n = ++counter;
	CommonUnlock(&g_job_create_mutex);
	sprintf(extranonce, "%08x%08x", n, (uint32_t) time(NULL));

	if (!templ->coinb1[0] || !templ->coinb2[0]) return false; // coinbase_create() failed

	if (strlen(templ->coinb1) + strlen(templ->coinb2) + 16 >= sizeof(templ->proto_coinbase)) {
		stratumlog("ERROR %s coinbase too large\n", coind->symbol);
		return false;
	}
	snprintf(templ->proto_coinbase, sizeof(templ->proto_coinbase), "%s%s%s", templ->coinb1, extranonce, templ->coinb2);

	// merkle root
	int coinbase_len = strlen(templ->proto_coinbase) / 2;
	unsigned char *coinbase_bin = (unsigned char *) malloc(coinbase_len + 1);
	if (!coinbase_bin) return false;
	binlify(coinbase_bin, templ->proto_coinbase);
	char coinbase_hash[128] = { 0 };
	sha256_double_hash_hex((char *) coinbase_bin, coinbase_hash, coinbase_len);
	free(coinbase_bin);
	string merkleroot = merkle_with_first(templ->txsteps, coinbase_hash);

	// 80 bytes: version, prev block, merkle root, time, bits, height
	unsigned char header[80];
	uint32_t version = (uint32_t) strtoul(templ->version, NULL, 16);
	uint32_t ntime = (uint32_t) strtoul(templ->ntime, NULL, 16);
	uint32_t nbits = (uint32_t) strtoul(templ->nbits, NULL, 16);
	uint32_t height = (uint32_t) templ->height;
	unsigned char prev[32], merkle[32];
	binlify(prev, templ->prevhash_hex);
	binlify(merkle, merkleroot.c_str());

	memcpy(header, &version, 4);
	for (int i = 0; i < 32; i++) header[4 + i] = prev[31 - i]; // display order -> serialized
	memcpy(header + 36, merkle, 32);                           // already serialized order
	memcpy(header + 68, &ntime, 4);
	memcpy(header + 72, &nbits, 4);
	memcpy(header + 76, &height, 4);
	hexlify(templ->proto_header, header, 80);

	unsigned char hash[32], hash_be[32];
	sha256_double_hash((char *) header, (char *) hash, 80);
	for (int i = 0; i < 32; i++) hash_be[i] = hash[31 - i];
	hexlify(templ->proto_hash, hash_be, 32);

	unsigned char seed[32];
	progpow_seed_hash(g_variant, templ->height, seed);
	hexlify(templ->proto_seed, seed, 32);

	unsigned char target[32];
	protocol_nbits_to_target(templ->nbits, target);
	hexlify(templ->proto_target, target, 32);

	// light cache of the epoch (built once, a few seconds)
	if (!progpow_prepare(g_variant, templ->height)) {
		stratumlog("ERROR %s: unable to allocate the %s epoch cache (%lu bytes)\n", coind->symbol,
			g_stratum_algo, (unsigned long) progpow_light_cache_size(g_variant, templ->height));
		return false;
	}
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////

static bool valid_string_params(json_value *json_params, int n)
{
	if (json_params->u.array.length < (unsigned int) n) return false;
	for (int p = 0; p < n; p++)
		if (!json_is_string(json_params->u.array.values[p])) return false;
	return true;
}

static bool kawpow_submit(YAAMP_CLIENT *client, json_value *json_params)
{
	// [worker, job id, nonce, header hash, mix hash]
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

	char nonce[32] = { 0 }, header_hash[80] = { 0 }, mix_hex[80] = { 0 };
	bool params_ok = protocol_hex_param(json_params->u.array.values[2]->u.string.ptr, nonce, 16)
		&& protocol_hex_param(json_params->u.array.values[3]->u.string.ptr, header_hash, 64)
		&& protocol_hex_param(json_params->u.array.values[4]->u.string.ptr, mix_hex, 64);

	int jobid = htoi(jobid_str);
	YAAMP_JOB *job = (YAAMP_JOB *) object_find(&g_list_job, jobid, true);
	if (!job) {
		protocol_share_rejected(client, NULL, 21, "Invalid job id", nonce);
		return true;
	}
	if (job->deleted) {
		client_send_result(client, "true");
		object_unlock(job);
		return true;
	}
	YAAMP_JOB_TEMPLATE *templ = job->templ;

	if (!job->coind || !templ->proto_hash[0]) {
		protocol_share_rejected(client, job, 21, "Invalid job", nonce);
		object_unlock(job);
		return true;
	}
	if (!params_ok) {
		protocol_share_rejected(client, job, 20, "Invalid nonce, header or mix hash", nonce);
		object_unlock(job);
		return true;
	}
	if (strncmp(nonce, client->extranonce1, strlen(client->extranonce1))) {
		protocol_share_rejected(client, job, 20, "Nonce out of range", nonce);
		object_unlock(job);
		return true;
	}
	if (strcmp(header_hash, templ->proto_hash)) {
		protocol_share_rejected(client, job, 21, "Stale job (header hash)", nonce);
		object_unlock(job);
		return true;
	}
	char empty[2] = "";
	if (share_find(job->id, empty, templ->ntime, nonce, client->extranonce1)) {
		protocol_share_rejected(client, job, 22, "Duplicate share", nonce);
		object_unlock(job);
		return true;
	}

	unsigned char hh[32], mix[32], final[32], share_target[32], block_target[32];
	binlify(hh, header_hash);
	binlify(mix, mix_hex);
	uint64_t nonce64 = strtoull(nonce, NULL, 16);

	// cheap check of the final hash first (keccak only), then the mix (dataset items)
	progpow_hash_no_verify(g_variant, templ->height, hh, nonce64, mix, final);
	protocol_diff_to_target(g_diff1, client->difficulty_actual, share_target);
	binlify(block_target, templ->proto_target);

	bool is_block = protocol_hash_le_target(final, block_target);
	if (!is_block && !protocol_hash_le_target(final, share_target)) {
		protocol_share_rejected(client, job, 26, "Low difficulty share", nonce);
		object_unlock(job);
		return true;
	}

	unsigned char final2[32];
	if (!progpow_verify_mix(g_variant, templ->height, hh, nonce64, mix, final2)) {
		protocol_share_rejected(client, job, 20, "Invalid mix hash", nonce);
		object_unlock(job);
		return true;
	}

	double share_diff = protocol_target_to_diff(g_diff1, final);

	if (g_debuglog_hash) {
		char final_hex[80];
		hexlify(final_hex, final, 32);
		debuglog("submit %s (uid %d) job %x nonce %s hash %s diff %.4f/%.4f\n", client->sock->ip,
			client->userid, job->id, nonce, final_hex, share_diff, client->difficulty_actual);
	}

	if (is_block && !job->block_found) {
		// 120 byte header: the 80 bytes, nNonce64, mix_hash (serialized = reversed)
		char header_hex[256];
		char tail[128];
		unsigned char mix_ser[32];
		for (int i = 0; i < 32; i++) mix_ser[i] = mix[31 - i];
		unsigned char nonce_le[8];
		memcpy(nonce_le, &nonce64, 8);
		strcpy(header_hex, templ->proto_header);
		hexlify(tail, nonce_le, 8);
		strcat(header_hex, tail);
		hexlify(tail, mix_ser, 32);
		strcat(header_hex, tail);

		char powhash[80], blockid[80];
		hexlify(powhash, final, 32);
		if (progpow_variant_blockid(g_variant) == PROGPOW_BLOCKID_SHA256D) {
			unsigned char header_bin[120], id[32], id_be[32];
			binlify(header_bin, header_hex);
			sha256_double_hash((char *) header_bin, (char *) id, 120);
			for (int i = 0; i < 32; i++) id_be[i] = id[31 - i];
			hexlify(blockid, id_be, 32);
		} else {
			strcpy(blockid, powhash);
		}

		// block difficulty_user in Bitcoin units, like the network difficulty
		unsigned char btc_diff1[32] = { 0 };
		btc_diff1[4] = 0xff; btc_diff1[5] = 0xff;
		protocol_submit_block(client, job, header_hex, templ->proto_coinbase, blockid, powhash,
			protocol_target_to_diff(btc_diff1, final));
	}

	protocol_share_accepted(client, job, nonce, share_diff);
	object_unlock(job);

	if (client->shares <= 200 && (client->shares % 50) == 0) {
		if (!client_ask_stats(client)) client->stats = false;
	}
	return true;
}

static bool kawpow_method(YAAMP_CLIENT *client, const char *method, json_value *json_params, bool *keep)
{
	// some miners report their hashrate
	if (!strcmp(method, "eth_submitHashrate") || !strcmp(method, "mining.hashrate")) {
		*keep = client_send_result(client, "true") >= 0;
		return true;
	}
	return false;
}

extern const YAAMP_PROTOCOL g_protocol_kawpow;
const YAAMP_PROTOCOL g_protocol_kawpow = {
	"kawpow",
	YAAMP_PROTOCOL_KAWPOW,
	kawpow_subscribe,
	kawpow_send_difficulty,
	kawpow_template_prepare,
	kawpow_job_notify,
	true,
	kawpow_submit,
	kawpow_method,
	kawpow_init,
};
