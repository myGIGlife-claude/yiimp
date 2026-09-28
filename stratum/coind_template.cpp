
#include "stratum.h"

void coind_getauxblock(YAAMP_COIND *coind)
{
	if(!coind->isaux) return;

	json_value *json = rpc_call(&coind->rpc, "getauxblock", "[]");
	if(!json)
	{
		coind_error(coind, "coind_getauxblock");
		return;
	}

	json_value *json_result = json_get_object(json, "result");
	if(!json_result)
	{
		coind_error(coind, "coind_getauxblock");
		return;
	}

//	coind->aux.height = coind->height+1;
	coind->aux.chainid = json_get_int(json_result, "chainid");

	const char *p = json_get_string(json_result, "target");
	if(p) strcpy(coind->aux.target, p);

	p = json_get_string(json_result, "hash");
	if(p) strcpy(coind->aux.hash, p);

//	if(strcmp(coind->symbol, "UNO") == 0)
//	{
//		string_be1(coind->aux.target);
//		string_be1(coind->aux.hash);
//	}

	json_value_free(json);
}

// Multi-algo chains select the PoW with bits of the block version (g_algo_version_rules
// in stratum.cpp). The template of the daemon normally has them (getblocktemplate is
// called with "powalgo"); if not, set them so shares and blocks use the right algo.
static void template_apply_version_rule(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, uint32_t nVersion)
{
	if(!g_stratum_version_mask) return;
	if((nVersion & g_stratum_version_mask) == g_stratum_version_bits) return;

	static time_t last_warning = 0;
	if(time(NULL) - last_warning > 600) {
		stratumlog("%s: template version %08x has not the %s bits %08x (mask %08x), forcing them."
			" Check that the daemon makes %s templates (e.g. powalgo=%s in its conf)\n",
			coind->symbol, nVersion, g_stratum_algo, g_stratum_version_bits, g_stratum_version_mask,
			g_stratum_algo, g_stratum_gbt_powalgo[0] ? g_stratum_gbt_powalgo : g_stratum_algo);
		last_warning = time(NULL);
	}
	nVersion = (nVersion & ~g_stratum_version_mask) | g_stratum_version_bits;
	sprintf(templ->version, "%08x", nVersion);
}

YAAMP_JOB_TEMPLATE *coind_create_template_memorypool(YAAMP_COIND *coind)
{
	json_value *json = rpc_call(&coind->rpc, "getmemorypool");
	if(!json || json->type == json_null)
	{
		coind_error(coind, "getmemorypool");
		return NULL;
	}

	json_value *json_result = json_get_object(json, "result");
	if(!json_result || json_result->type == json_null)
	{
		coind_error(coind, "getmemorypool");
		json_value_free(json);

		return NULL;
	}

	YAAMP_JOB_TEMPLATE *templ = new YAAMP_JOB_TEMPLATE;
	memset(templ, 0, sizeof(YAAMP_JOB_TEMPLATE));

	templ->created = time(NULL);
	templ->value = json_get_int(json_result, "coinbasevalue");
//	templ->height = json_get_int(json_result, "height");
	sprintf(templ->version, "%08x", (unsigned int)json_get_int(json_result, "version"));
	sprintf(templ->ntime, "%08x", (unsigned int)json_get_int(json_result, "time"));
	strcpy(templ->nbits, json_get_string(json_result, "bits"));
	strcpy(templ->prevhash_hex, json_get_string(json_result, "previousblockhash"));

	json_value_free(json);

	json = rpc_call(&coind->rpc, "getmininginfo", "[]");
	if(!json || json->type == json_null)
	{
		coind_error(coind, "coind getmininginfo");
		return NULL;
	}

	json_result = json_get_object(json, "result");
	if(!json_result || json_result->type == json_null)
	{
		coind_error(coind, "coind getmininginfo");
		json_value_free(json);

		return NULL;
	}

	templ->height = json_get_int(json_result, "blocks")+1;
	json_value_free(json);

	coind_getauxblock(coind);

	coind->usememorypool = true;
	return templ;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Decred: dcrd has no getblocktemplate, the work comes from getwork: the
// serialized 180-byte block header followed by 12 bytes of padding (BLAKE3,
// DCP-0011), all fields little endian, no word swapping:
//
//   0 version   4 prevblock   36 merkleroot   68 stakeroot   100 votebits
//   102 finalstate   108 voters   110 freshstake   111 revocations
//   112 poolsize   116 bits   120 sbits   128 height   132 size
//   136 timestamp   140 nonce   144 extradata (32)   176 stakeversion
//
// The pool fills extradata[0..4] with extranonce1 and the miner extradata[4..8]
// with extranonce2 (dcrpool / gominer stratum), so no coinbase is built: the
// block reward goes to the dcrd --miningaddr.
static bool decred_parse_header(YAAMP_JOB_TEMPLATE *templ, const char *header_hex)
{
	if (strlen(header_hex) < DECRED_HEADER_SIZE*2 || !ishexa((char *) header_hex, DECRED_HEADER_SIZE*2))
		return false;

	unsigned char *hdr = (unsigned char *) templ->header;
	char hex[DECRED_HEADER_SIZE*2+1];
	memcpy(hex, header_hex, DECRED_HEADER_SIZE*2);
	hex[DECRED_HEADER_SIZE*2] = '\0';
	string_lower(hex);
	binlify(hdr, hex);

	// the extranonces are set by the pool and the miner
	memset(&hdr[DECRED_EXTRANONCE_OFFSET], 0, 32);

	uint32_t nbits, height;
	memcpy(&nbits, &hdr[116], 4);
	memcpy(&height, &hdr[128], 4);

	templ->height = height;
	sprintf(templ->nbits, "%08x", nbits);          // numeric, for decode_compact()
	hexlify(templ->version, &hdr[0], 4);           // as serialized (little endian)
	hexlify(templ->ntime, &hdr[136], 4);           // as serialized, like the miners submit it
	hexlify(templ->prevhash_be, &hdr[4], 32);      // as serialized, sent in mining.notify
	string_be(templ->prevhash_be, templ->prevhash_hex); // displayed block hash
	templ->prevhash_hex[64] = '\0';

	// mining.notify "coinb1": the header after the previous block hash
	hexlify(templ->coinb1, &hdr[36], DECRED_HEADER_SIZE - 36);
	templ->coinb2[0] = '\0';

	return true;
}

static YAAMP_JOB_TEMPLATE *decred_create_worktemplate(YAAMP_COIND *coind)
{
	char rpc_error[1024] = { 0 };
	#define GETWORK_RETRY_MAX 3
	int retry_cnt = GETWORK_RETRY_MAX;
retry:
	json_value *gw = rpc_call(&coind->rpc, "getwork", "[]");
	if(!gw || json_is_null(gw)) {
		usleep(500*YAAMP_MS); // too much connections ? no data received
		if (--retry_cnt > 0) {
			if (coind->rpc.curl)
				rpc_curl_get_lasterr(rpc_error, 1023);
			debuglog("%s getwork retry %d\n", coind->symbol, GETWORK_RETRY_MAX-retry_cnt);
			goto retry;
		}
		debuglog("%s error getwork %s\n", coind->symbol, rpc_error);
		return NULL;
	}
	json_value *gwr = json_get_object(gw, "result");
	if(!gwr) {
		debuglog("%s no getwork json result!\n", coind->symbol);
		json_value_free(gw);
		return NULL;
	}
	else if (json_is_null(gwr)) {
		json_value *jr = json_get_object(gw, "error");
		const char *err = (jr && !json_is_null(jr)) ? json_get_string(jr, "message") : NULL;
		if (err && (!strcmp(err, "internal error") || strstr(err, "no work is available"))) {
			usleep(500*YAAMP_MS); // not enough voters yet (testnet), reorg
			if (--retry_cnt > 0) {
				json_value_free(gw);
				goto retry;
			}
		}
		if (err) debuglog("%s getwork failed: %s\n", coind->symbol, err);
		json_value_free(gw);
		return NULL;
	}
	const char *header_hex = json_get_string(gwr, "data");
	if (!header_hex || !strlen(header_hex)) {
		debuglog("%s no getwork data!\n", coind->symbol);
		json_value_free(gw);
		return NULL;
	}

	YAAMP_JOB_TEMPLATE *templ = new YAAMP_JOB_TEMPLATE;
	memset(templ, 0, sizeof(YAAMP_JOB_TEMPLATE));

	templ->created = time(NULL);

	bool ok = decred_parse_header(templ, header_hex);
	json_value_free(gw);
	if (!ok) {
		stratumlog("%s invalid getwork data (%d chars)\n", coind->symbol, (int) strlen(header_hex));
		delete templ;
		return NULL;
	}

	// no coinbase/merkle for decred, the header is sent as is
	vector<string> txhashes;
	txhashes.push_back("");

	templ->txmerkles[0] = 0;
	templ->txcount = txhashes.size();
	templ->txsteps = merkle_steps(txhashes);
	txhashes.clear();

	return templ;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

YAAMP_JOB_TEMPLATE *coind_create_template(YAAMP_COIND *coind)
{
	if(coind->usememorypool)
		return coind_create_template_memorypool(coind);

	char params[512] = "[{}]";
	if(!strcmp(coind->symbol, "PPC")) strcpy(params, "[]");
	else if(coind->usemweb) strcpy(params, "[{\"rules\":[\"mweb\",\"segwit\"]}]");
	else if(g_stratum_segwit) strcpy(params, "[{\"rules\":[\"segwit\"]}]");

	// multi-algo chains (minotaurx): ask the template of our algo (bits, pow type in nVersion)
	if(g_stratum_gbt_powalgo[0] && strcmp(params, "[]")) {
		size_t l = strlen(params);
		snprintf(params + l - 2, sizeof(params) - l + 2, "%s\"powalgo\":\"%s\"}]",
			strcmp(params, "[{}]") ? "," : "", g_stratum_gbt_powalgo);
	}

	json_value *json = rpc_call(&coind->rpc, "getblocktemplate", params);

	// Litecoin Core (0.21.2+) refuses getblocktemplate without the mweb rule:
	// remember that and ask again.
	json_value *json_first_result = json ? json_get_object(json, "result") : NULL;
	if(json && !coind->usemweb && (!json_first_result || json_is_null(json_first_result))) {
		json_value *json_error = json_get_object(json, "error");
		const char *message = json_error ? json_get_string(json_error, "message") : NULL;
		if(message && strstr(message, "mweb")) {
			debuglog("%s requires the mweb rule, enabling MWEB\n", coind->symbol);
			coind->usemweb = true;
			json_value_free(json);
			strcpy(params, "[{\"rules\":[\"mweb\",\"segwit\"]}]");
			json = rpc_call(&coind->rpc, "getblocktemplate", params);
		}
	}
	if(!json || json_is_null(json))
	{
		// coind_error() reset auto_ready, and DCR gbt can fail
		if (strcmp(coind->rpcencoding, "DCR") == 0)
			debuglog("decred getblocktemplate failed\n");
		else
			coind_error(coind, "getblocktemplate");
		return NULL;
	}

	json_value *json_result = json_get_object(json, "result");
	if(!json_result || json_is_null(json_result))
	{
		coind_error(coind, "getblocktemplate result");
		json_value_free(json);
		return NULL;
	}

	// segwit rule
	json_value *json_rules = json_get_array(json_result, "rules");
	if(json_rules && !strlen(coind->witness_magic) && json_rules->u.array.length) {
		for (int i=0; i<json_rules->u.array.length; i++) {
			json_value *val = json_rules->u.array.values[i];
			if(!strcmp(val->u.string.ptr, "segwit")) {
				const char *commitment = json_get_string(json_result, "default_witness_commitment");
				strcpy(coind->witness_magic, "aa21a9ed");
				if (commitment && strlen(commitment) > 12) {
					strncpy(coind->witness_magic, &commitment[4], 8);
					coind->witness_magic[8] = '\0';
				}
				coind->usesegwit |= g_stratum_segwit;
				if (coind->usesegwit)
					debuglog("%s segwit enabled, magic %s\n", coind->symbol, coind->witness_magic);
				break;
			}
		}
	}

	json_value *json_tx = json_get_array(json_result, "transactions");
	if(!json_tx)
	{
		coind_error(coind, "getblocktemplate transactions");
		json_value_free(json);
		return NULL;
	}

	json_value *json_coinbaseaux = json_get_object(json_result, "coinbaseaux");
	if(!json_coinbaseaux && coind->isaux)
	{
		coind_error(coind, "getblocktemplate coinbaseaux");
		json_value_free(json);
		return NULL;
	}

	YAAMP_JOB_TEMPLATE *templ = new YAAMP_JOB_TEMPLATE;
	memset(templ, 0, sizeof(YAAMP_JOB_TEMPLATE));

	templ->created = time(NULL);
	templ->value = json_get_int(json_result, "coinbasevalue");
	templ->height = json_get_int(json_result, "height");
	sprintf(templ->version, "%08x", (unsigned int)json_get_int(json_result, "version"));
	template_apply_version_rule(coind, templ, (uint32_t) json_get_int(json_result, "version"));
	sprintf(templ->ntime, "%08x", (unsigned int)json_get_int(json_result, "curtime"));

	const char *bits = json_get_string(json_result, "bits");
	strcpy(templ->nbits, bits ? bits : "");
	const char *prev = json_get_string(json_result, "previousblockhash");
	strcpy(templ->prevhash_hex, prev ? prev : "");
	const char *flags = json_get_string(json_coinbaseaux, "flags");
	strcpy(templ->flags, flags ? flags : "");
	strcpy(templ->priceinfo, "");

	// Litecoin MWEB extension block, serialized after the transactions
	const char *mweb = json_get_string(json_result, "mweb");
	if (mweb && strlen(mweb)) {
		if (!ishexa((char *)mweb, strlen(mweb)) || strlen(mweb) % 2) {
			coind_error(coind, "getblocktemplate mweb");
			delete templ;
			json_value_free(json);
			return NULL;
		}
		templ->mweb.push_back(mweb);
	}

	// LBC Claim Tree (with wallet gbt patch)
	const char *claim = json_get_string(json_result, "claimtrie");
	if (claim) {
		strcpy(templ->claim_hex, claim);
		// debuglog("claimtrie: %s\n", templ->claim_hex);
	}
	else if (strcmp(coind->symbol, "LBC") == 0) {
		json_value *json_claim = rpc_call(&coind->rpc, "getclaimtrie");
		if (!json_claim || json_claim->type != json_object)
			return NULL;
		json_value *json_cls = json_get_array(json_claim, "result");
		if (!json_cls || !json_is_array(json_cls))
			return NULL;
		// get first claim "", seems the root
		// if empty need 0000000000000000000000000000000000000000000000000000000000000001
		json_value *json_obj = json_cls->u.array.values[0];
		if (!json_obj || json_claim->type != json_object)
			return NULL;
		claim = json_get_string(json_obj, "hash");
		if (claim) {
			strcpy(templ->claim_hex, claim);
			debuglog("claim_hex: %s\n", templ->claim_hex);
		}
	}
	else if (strcmp(coind->symbol, "BITC") == 0) {
		if (strlen(json_get_string(json_result, "priceinfo")) < 1000) {
			templ->needpriceinfo = json_get_bool(json_result, "needpriceinfo");
            if (templ->needpriceinfo)
				strcpy(templ->priceinfo, json_get_string(json_result, "priceinfo"));
		}
	}

	const char *sc_root = json_get_string(json_result, "stateroot");
	const char *sc_utxo = json_get_string(json_result, "utxoroot");
	if (sc_root && sc_utxo) {
		// LUX Smart Contracts, 144-bytes block headers
		strcpy(&templ->extradata_hex[ 0], sc_root); // 32-bytes hash (64 in hexa)
		strcpy(&templ->extradata_hex[64], sc_utxo); // 32-bytes hash too

		// same weird byte order as previousblockhash field
		ser_string_be2(sc_root, &templ->extradata_be[ 0], 8);
		ser_string_be2(sc_utxo, &templ->extradata_be[64], 8);
	}

	if (!templ->height || !templ->nbits || !strlen(templ->prevhash_hex)) {
		stratumlog("%s warning, gbt incorrect : version=%s height=%d value=%lld bits=%s time=%s prev=%s\n",
			coind->symbol, templ->version, templ->height, (long long) templ->value, templ->nbits, templ->ntime, templ->prevhash_hex);
	}

	// temporary hack, until wallet is fixed...
	if (!strcmp(coind->symbol, "MBL")) { // MBL: chainid in version
		unsigned int nVersion = (unsigned int)json_get_int(json_result, "version");
		if (nVersion & 0xFFFF0000UL == 0) {
			nVersion |= (0x16UL << 16);
			debuglog("%s version %s >> %08x\n", coind->symbol, templ->version, nVersion);
		}
		sprintf(templ->version, "%08x", nVersion);
	}

//	debuglog("%s ntime %s\n", coind->symbol, templ->ntime);
//	uint64_t target = decode_compact(json_get_string(json_result, "bits"));
//	coind->difficulty = target_to_diff(target);

//	string_lower(templ->ntime);
//	string_lower(templ->nbits);

//	char target[1024];
//	strcpy(target, json_get_string(json_result, "target"));
//	uint64_t coin_target = decode_compact(templ->nbits);
//	debuglog("nbits %s\n", templ->nbits);
//	debuglog("target %s\n", target);
//	debuglog("0000%016llx\n", coin_target);

	if(coind->isaux)
	{
		json_value_free(json);
		coind_getauxblock(coind);
		return templ;
	}

	//////////////////////////////////////////////////////////////////////////////////////////

	vector<string> txhashes;
	vector<string> txids;
	txhashes.push_back("");
	txids.push_back("");

	templ->has_segwit_txs = false;

	templ->has_filtered_txs = false;
	templ->filtered_txs_fee = 0;

	for(int i = 0; i < json_tx->u.array.length; i++)
	{
		const char *p = json_get_string(json_tx->u.array.values[i], "hash");
		char hash_be[256] = { 0 };

		if (templ->has_filtered_txs) {
			templ->filtered_txs_fee += json_get_int(json_tx->u.array.values[i], "fee");
			continue;
		}

		string_be(p, hash_be);
		txhashes.push_back(hash_be);

		const char *txid = json_get_string(json_tx->u.array.values[i], "txid");
		if(txid && strlen(txid)) {
			char txid_be[256] = { 0 };
			string_be(txid, txid_be);
			txids.push_back(txid_be);
			if (strcmp(hash_be, txid_be)) {
				templ->has_segwit_txs = true; // if not, its useless to generate a segwit block, bigger
			}
		} else {
			templ->has_segwit_txs = false; // force disable if not supported (no txid fields)
		}

		const char *d = json_get_string(json_tx->u.array.values[i], "data");
		templ->txdata.push_back(d);

		// if wanted, we can limit the count of txs to include
		if (g_limit_txs_per_block && i >= g_limit_txs_per_block-2) {
			debuglog("limiting block to %d first txs (of %d)\n", g_limit_txs_per_block, json_tx->u.array.length);
			templ->has_filtered_txs = true;
		}
	}

	if (templ->has_filtered_txs) {
		// coinbasevalue is a total with all tx fees, need to reduce it if some are skipped
		templ->value -= templ->filtered_txs_fee;
	}

	templ->txmerkles[0] = '\0';
	if(templ->has_segwit_txs) {
		templ->txcount = txids.size();
		templ->txsteps = merkle_steps(txids);
	} else {
		templ->txcount = txhashes.size();
		templ->txsteps = merkle_steps(txhashes);
	}

	if(templ->has_segwit_txs) {
		// * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
		//   coinbase (where 0x0000....0000 is used instead).
		// * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
		// * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
		// * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes (magic) of which are
		//   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are
		/*
		char bin[YAAMP_HASHLEN_BIN*2];
		char witness[128] = { 0 };
		vector<string> mt_verify = merkle_steps(txhashes);
		string witness_mt = merkle_with_first(mt_verify, "0000000000000000000000000000000000000000000000000000000000000000");
		mt_verify.clear();
		witness_mt = witness_mt + "0000000000000000000000000000000000000000000000000000000000000000";

		binlify((unsigned char *)bin, witness_mt.c_str());
		sha256_double_hash_hex(bin, witness, YAAMP_HASHLEN_BIN*2);

		int clen = (int) (strlen(coind->witness_magic) + strlen(witness)); // 4 + 32 = 36 = 0x24
		sprintf(coind->commitment, "6a%02x%s%s", clen/2, coind->witness_magic, witness);
		*/
		// default commitment is already computed correctly
		const char *commitment = json_get_string(json_result, "default_witness_commitment");
		if (commitment) {
			sprintf(coind->commitment, "%s", commitment);
		} else {
			templ->has_segwit_txs = false;
		}
	}

	txhashes.clear();
	txids.clear();

	vector<string>::const_iterator i;
	for(i = templ->txsteps.begin(); i != templ->txsteps.end(); ++i)
		sprintf(templ->txmerkles + strlen(templ->txmerkles), "\"%s\",", (*i).c_str());

	if(templ->txmerkles[0])
		templ->txmerkles[strlen(templ->txmerkles)-1] = 0;

//	debuglog("merkle transactions %d [%s]\n", templ->txcount, templ->txmerkles);
	ser_string_be2(templ->prevhash_hex, templ->prevhash_be, 8);

	if(!strcmp(coind->symbol, "LBC"))
		ser_string_be2(templ->claim_hex, templ->claim_be, 8);

	if(!coind->pos)
		coind_aux_build_auxs(templ);

	coinbase_create(coind, templ, json_result);

	// other stratum protocols (protocol.h): per job data (header hash...)
	if(g_protocol && g_protocol->template_prepare && !g_protocol->template_prepare(coind, templ, json_result))
	{
		json_value_free(json);
		templ->txsteps.clear();
		templ->txdata.clear();
		delete templ;
		return NULL;
	}

	json_value_free(json);
	return templ;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool coind_create_job(YAAMP_COIND *coind, bool force)
{
//	debuglog("create job %s\n", coind->symbol);

	bool b = rpc_connected(&coind->rpc);
	if(!b) return false;

	CommonLock(&coind->mutex);

	YAAMP_JOB_TEMPLATE *templ;

	// DCR: dcrd only provides getwork

	if (coind->usegetwork && strcmp(coind->rpcencoding, "DCR") == 0)
		templ = decred_create_worktemplate(coind);
	else
		templ = coind_create_template(coind);

	if(!templ)
	{
		CommonUnlock(&coind->mutex);
//		debuglog("%s: create job template failed!\n", coind->symbol);
		return false;
	}

	YAAMP_JOB *job_last = coind->job;

	if(	!force && job_last && job_last->templ && job_last->templ->created + 45 > time(NULL) &&
		templ->height == job_last->templ->height &&
		templ->txcount == job_last->templ->txcount &&
		strcmp(templ->coinb2, job_last->templ->coinb2) == 0)
	{
//		debuglog("coind_create_job %s %d same template %x \n", coind->name, coind->height, coind->job->id);
		if (templ->txcount) {
			templ->txsteps.clear();
			templ->txdata.clear();
		}
		delete templ;

		CommonUnlock(&coind->mutex);
		return true;
	}

	////////////////////////////////////////////////////////////////////////////////////////

	int height = coind->height;
	coind->height = templ->height-1;

	if(height > coind->height)
	{
		stratumlog("%s went from %d to %d\n", coind->name, height, coind->height);
	//	coind->auto_ready = false;
	}

	if(height < coind->height && !coind->newblock)
	{
		if(coind->auto_ready && coind->notreportingcounter++ > 5)
			stratumlog("%s %d not reporting\n", coind->name, coind->height);
	}

	uint64_t coin_target = decode_compact(templ->nbits);
	if (templ->nbits && !coin_target) coin_target = 0xFFFF000000000000ULL; // under decode_compact min diff
	coind->difficulty = target_to_diff(coin_target);

//	stratumlog("%s %d diff %g %llx %s\n", coind->name, height, coind->difficulty, coin_target, templ->nbits);

	coind->newblock = false;

	////////////////////////////////////////////////////////////////////////////////////////

	object_delete(coind->job);

	coind->job = new YAAMP_JOB;
	memset(coind->job, 0, sizeof(YAAMP_JOB));

	sprintf(coind->job->name, "%s", coind->symbol);

	coind->job->id = job_get_jobid();
	coind->job->templ = templ;

	coind->job->profit = coind_profitability(coind);
	coind->job->maxspeed = coind_nethash(coind) *
		(g_current_algo->profit? min(1.0, coind_profitability(coind)/g_current_algo->profit): 1);

	coind->job->coind = coind;
	coind->job->remote = NULL;

	g_list_job.AddTail(coind->job);
	CommonUnlock(&coind->mutex);

//	debuglog("coind_create_job %s %d new job %x\n", coind->name, coind->height, coind->job->id);

	return true;
}















