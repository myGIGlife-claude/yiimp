
// http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html

// https://en.bitcoin.it/wiki/Merged_mining_specification#Merged_mining_coinbase

#include "stratum.h"

#include <map>
#include <string>

#define TX_VALUE(v, s)	((unsigned int)(v>>s)&0xff)

static void encode_tx_value(char *encoded, json_int_t value)
{
	sprintf(encoded, "%02x%02x%02x%02x%02x%02x%02x%02x",
		TX_VALUE(value, 0), TX_VALUE(value, 8), TX_VALUE(value, 16), TX_VALUE(value, 24),
		TX_VALUE(value, 32), TX_VALUE(value, 40), TX_VALUE(value, 48), TX_VALUE(value, 56));
}

static void p2sh_pack_tx(YAAMP_COIND *coind, char *data, json_int_t amount, char *payee)
{
	char evalue[32];
	char coinb2_part[256];
	char coinb2_len[4];
	sprintf(coinb2_part, "a9%02x%s87", (unsigned int)(strlen(payee) >> 1) & 0xFF, payee);
	sprintf(coinb2_len, "%02x", (unsigned int)(strlen(coinb2_part) >> 1) & 0xFF);
	encode_tx_value(evalue, amount);
	strcat(data, evalue);
	strcat(data, coinb2_len);
	strcat(data, coinb2_part);
}

static void script_pack_tx(YAAMP_COIND *coind, char *data, json_int_t amount, const char *script)
{
	char evalue[32];
	char coinb2_part[256];
	char coinb2_len[4];
	encode_tx_value(evalue, amount);
	sprintf(coinb2_part, "%s", script);
	sprintf(coinb2_len, "%02x", (unsigned int)(strlen(coinb2_part) >> 1) & 0xFF);
	strcat(data, evalue);
	strcat(data, coinb2_len);
	strcat(data, coinb2_part);
}

static void job_pack_tx(YAAMP_COIND *coind, char *data, json_int_t amount, char *key)
{
	int ol = strlen(data);
	char evalue[32];

	if(coind->p2sh_address && !key) {
		p2sh_pack_tx(coind, data, amount, coind->script_pubkey);
		return;
	}

	encode_tx_value(evalue, amount);
	sprintf(data+strlen(data), "%s", evalue);

	if(coind->pos && !key)
		sprintf(data+strlen(data), "2321%sac", coind->pubkey);

	else
		sprintf(data+strlen(data), "1976a914%s88ac", key? key: coind->script_pubkey);

//	debuglog("pack tx %s\n", data+ol);
//	debuglog("pack tx %lld\n", amount);
}

// Append one required payment of a getblocktemplate entry ({"payee", "script", "amount"}),
// preferring the scriptPubKey given by the daemon (works for P2PKH, P2SH, P2WPKH...).
// Returns the amount packed (0 when the entry is empty or unusable).
static json_int_t pack_template_payment(YAAMP_COIND *coind, char *dests, size_t size, json_value *entry)
{
	if (!entry || entry->type != json_object) return 0;
	if (strlen(dests) + 2*(8+3+200) + 1 > size) {
		stratumlog("ERROR %s too many coinbase payments in the template\n", coind->symbol);
		return 0;
	}
	json_int_t amount = json_get_int(entry, "amount");
	const char *script = json_get_string(entry, "script");
	const char *payee = json_get_string(entry, "payee");
	if (amount <= 0) return 0;
	if (script && strlen(script) > 0 && strlen(script) < 200) {
		script_pack_tx(coind, dests, amount, script);
		return amount;
	}
	if (payee && strlen(payee) > 0) {
		char script_payee[1024] = { 0 };
		base58_decode(payee, script_payee);
		job_pack_tx(coind, dests, amount, script_payee);
		return amount;
	}
	return 0;
}


// scriptPubKey (hex) of an address, asked to the daemon (validateaddress) once
static bool coind_address_script(YAAMP_COIND *coind, const char *address, char *script, size_t size)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	static std::map<std::string, std::string> cache;

	if (!address || !strlen(address)) {
		// an empty address gives an empty script (e.g. FIRO regtest stage 2 fund)
		if (size) script[0] = '\0';
		return true;
	}

	std::string key = std::string(coind->symbol) + ":" + address;
	pthread_mutex_lock(&mutex);
	std::map<std::string, std::string>::iterator it = cache.find(key);
	if (it != cache.end()) {
		snprintf(script, size, "%s", it->second.c_str());
		pthread_mutex_unlock(&mutex);
		return true;
	}
	pthread_mutex_unlock(&mutex);

	char params[256];
	snprintf(params, sizeof(params), "[\"%s\"]", address);
	json_value *json = rpc_call(&coind->rpc, "validateaddress", params);
	json_value *result = json ? json_get_object(json, "result") : NULL;
	const char *spk = result ? json_get_string(result, "scriptPubKey") : NULL;
	bool ok = spk && strlen(spk) > 0 && strlen(spk) < size && ishexa((char *) spk, strlen(spk));
	if (ok) {
		snprintf(script, size, "%s", spk);
		pthread_mutex_lock(&mutex);
		cache[key] = spk;
		pthread_mutex_unlock(&mutex);
	} else {
		stratumlog("ERROR %s: unable to get the script of address %s (validateaddress)\n", coind->symbol, address);
	}
	if (json) json_value_free(json);
	return ok;
}

// chain name of the daemon (main, test, regtest), asked once
static const char *coind_chain(YAAMP_COIND *coind)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	static std::map<int, std::string> cache;

	pthread_mutex_lock(&mutex);
	std::map<int, std::string>::iterator it = cache.find(coind->id);
	if (it != cache.end()) {
		const char *c = it->second.c_str();
		pthread_mutex_unlock(&mutex);
		return c;
	}
	pthread_mutex_unlock(&mutex);

	json_value *json = rpc_call(&coind->rpc, "getblockchaininfo", "[]");
	json_value *result = json ? json_get_object(json, "result") : NULL;
	const char *chain = result ? json_get_string(result, "chain") : NULL;
	std::string c = chain ? chain : "";
	if (json) json_value_free(json);
	if (c.empty()) return "";

	pthread_mutex_lock(&mutex);
	cache[coind->id] = c;
	const char *r = cache[coind->id].c_str();
	pthread_mutex_unlock(&mutex);
	return r;
}

// Firo development and community fund outputs, not given by getblocktemplate: computed as
// ContextualCheckBlock (validation.cpp) checks them, with the consensus params of
// chainparams.cpp (firoorg/firo c03cd0a1, v0.14.18). Returns false if they are unknown.
struct firo_params {
	const char *chain;
	int halving_first, halving_second, halving_interval;
	uint32_t stage3_start_time;
	int stage4_start_block;
	int stage3_dev_share, stage3_community_share, stage4_dev_share, stage4_community_share;
	int stage2_dev_share;
	const char *stage2_dev_address, *stage3_dev_address, *stage3_community_address;
	const char *stage41_dev_address;
	int stage41_start_block;
	uint32_t mtp_switch_time;
	int mtp_reward_reduction;
	json_int_t tail_subsidy;
};

static const struct firo_params g_firo_params[] = {
	{ "main", 302438, 958655, 840000, 1655380800, 958655, 15, 10, 15, 10, 15,
	  "aFrAVZFr8pva5mG8XKaUH8EXcFVVNxLiuB", "aLgRaYSFk6iVw2FqY1oei8Tdn2aTsGPVmP", "aFA2TbqG9cnhhzX5Yny2pBJRK5EaEqLCH7",
	  "a7GJ9bYfbZqvXmEmxzxZyZYtUTQmzckpjG", 1205100, 1544443200, 2, 4*100000000LL },
	{ "test", 12000, 150000, 150000, 1653409800, 167500, 15, 10, 15, 10, 15,
	  "TUuKypsbbnHHmZ2auC2BBWfaP1oTEnxjK2", "TWDxLLKsFp6qcV1LL4U2uNmW4HwMcapmMU", "TCkC4uoErEyCB4MK3d6ouyJELoXnuyqe9L",
	  "TEQQi3AraGdo7VHVM7Z8xKYTiiNcy8rydF", 189800, 1539172800, 2, 4*100000000LL },
	{ "regtest", 1500, 2500, 1000, 0x7fffffff, 2500, 15, 10, 25, 15, 15,
	  "", "TGEGf26GwyUBE2P2o2beBAfE9Y438dCp5t", "TJmPzeJF4DECrBwUftc265U7rTPxKmpa4F",
	  "TEK8Kd2hd344LABNbMDTUTM3q4hH9WRn4q", 2600, 0x7fffffff, 2, 4*100000000LL },
	{ NULL }
};

static json_int_t firo_block_subsidy(const struct firo_params *p, int height, uint32_t ntime)
{
	if (height == 0) return 0;
	json_int_t subsidy;
	if (height < p->halving_first) subsidy = 50*100000000LL;
	else if (height < p->halving_second) subsidy = 25*100000000LL;
	else if (height < p->stage4_start_block) subsidy = 25*100000000LL / 2;
	else if (height < p->stage4_start_block + p->halving_interval) subsidy = 25*100000000LL;
	else subsidy = p->tail_subsidy;
	if (ntime >= p->mtp_switch_time) subsidy /= p->mtp_reward_reduction;
	if (ntime >= p->stage3_start_time) subsidy /= 2;
	return subsidy;
}

// appends the fund outputs to dests, returns the number of outputs or -1 on error
static int firo_fund_outputs(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, char *dests, size_t size)
{
	const char *chain = coind_chain(coind);
	const struct firo_params *p = NULL;
	for (int i = 0; g_firo_params[i].chain; i++)
		if (!strcmp(g_firo_params[i].chain, chain)) p = &g_firo_params[i];
	if (!p) {
		stratumlog("ERROR %s: unknown chain '%s' for the Firo funds\n", coind->symbol, chain);
		return -1;
	}

	int height = templ->height;
	uint32_t ntime = (uint32_t) strtoul(templ->ntime, NULL, 16);
	if (height < p->halving_first) {
		stratumlog("ERROR %s: Firo founders rewards (height < %d) are not supported\n", coind->symbol, p->halving_first);
		return -1;
	}

	json_int_t subsidy = firo_block_subsidy(p, height, ntime);
	char script[256];
	int n = 0;

	if (ntime >= p->stage3_start_time) {
		bool stage3 = height < p->halving_second;
		bool stage4 = height >= p->stage4_start_block;
		if (!stage3 && !stage4) return 0;
		json_int_t dev = subsidy * (stage3 ? p->stage3_dev_share : p->stage4_dev_share) / 100;
		json_int_t community = subsidy * (stage3 ? p->stage3_community_share : p->stage4_community_share) / 100;
		const char *dev_address = (p->stage41_start_block > 0 && height >= p->stage41_start_block) ?
			p->stage41_dev_address : p->stage3_dev_address;
		if (!coind_address_script(coind, dev_address, script, sizeof(script))) return -1;
		script_pack_tx(coind, dests, dev, script); n++;
		if (!coind_address_script(coind, p->stage3_community_address, script, sizeof(script))) return -1;
		script_pack_tx(coind, dests, community, script); n++;
	} else {
		json_int_t dev = subsidy * p->stage2_dev_share / 100;
		if (!coind_address_script(coind, p->stage2_dev_address, script, sizeof(script))) return -1;
		script_pack_tx(coind, dests, dev, script); n++;
	}
	return n;
}

void coinbase_aux(YAAMP_JOB_TEMPLATE *templ, char *aux_script)
{
	vector<string> hashlist = coind_aux_hashlist(templ->auxs, templ->auxs_size);
	while(hashlist.size() > 1)
	{
		vector<string> l;
		for(int i = 0; i < hashlist.size()/2; i++)
		{
			string s = hashlist[i*2] + hashlist[i*2+1];

			char bin[YAAMP_HASHLEN_BIN*2];
			char out[YAAMP_HASHLEN_STR];

			binlify((unsigned char *)bin, s.c_str());
			sha256_double_hash_hex(bin, out, YAAMP_HASHLEN_BIN*2);

			l.push_back(out);
		}

		hashlist = l;
	}

	char merkle_hash[4*1024];
	memset(merkle_hash, 0, 4*1024);
	string_be(hashlist[0].c_str(), merkle_hash);

	sprintf(aux_script+strlen(aux_script), "fabe6d6d%s%02x00000000000000", merkle_hash, templ->auxs_size);
//	debuglog("aux_script is %s\n", aux_script);
}

void coinbase_create(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, json_value *json_result)
{
	templ->isbitcash = false;
	if(strcmp(coind->symbol, "BITC") == 0) {
		char *params = (char *)malloc(4096);
		if (params) {
			unsigned char price_bin[1024];
			unsigned char pricehash_bin[1024];
			char pricehash_hex[1024];
			char pricehash_be[1024];

			if (templ->needpriceinfo && strlen(templ->priceinfo) > 0 && strlen(templ->priceinfo) < 1000) {
				binlify(price_bin, templ->priceinfo);

				int price_len = strlen(templ->priceinfo)/2;
				sha256_double_hash((char *)price_bin, (char *)pricehash_bin, price_len);

				hexlify(pricehash_hex, pricehash_bin, 32);
				string_be(pricehash_hex, pricehash_be);

				sprintf(params, "[\"%s\", %i, \"%s\"]", coind->wallet, templ->height, pricehash_be);
			} else {
				snprintf(params, 1024, "[\"%s\", %i]", coind->wallet, templ->height);
			}
			//std::cout << "Params:" << params << std::endl;
			json_value *json = rpc_call(&coind->rpc, "createcoinbaseforaddress", params);

			free(params);
			if (json) {
				json_value *json_result = json_get_object(json, "result");
				if (json_result) {
					sprintf(templ->coinb1, "%s", json_get_string(json_result, "coinbaseforhashpart1"));
					templ->coinb1[strlen(templ->coinb1) - 16] = '\0';
					sprintf(templ->coinb2, "%s", json_get_string(json_result, "coinbaseforhashpart2"));

					sprintf(templ->coinforsubmitb1, "%s", json_get_string(json_result, "coinbasepart1"));
					templ->coinforsubmitb1[strlen(templ->coinforsubmitb1) - 16] = '\0';
					sprintf(templ->coinforsubmitb2, "%s", json_get_string(json_result, "coinbasepart2"));
					templ->isbitcash = true;
				}
			}
		}
		return;
	}
	char eheight[32], etime[32];
	char entime[32] = { 0 };
	char commitment[128] = { 0 };

	ser_number(templ->height, eheight);
	ser_number(time(NULL), etime);
	if(coind->pos) ser_string_be(templ->ntime, entime, 1);

	char eversion1[32] = "01000000";
	if(coind->txmessage)
		strcpy(eversion1, "02000000");

	// Kylacoin/Lyncoin (flex) hash transactions with sha3d; Lyncoin only does so for
	// version 8 transactions (primitives/transaction.cpp), and its AuxPoW check hashes
	// the parent (KCN) coinbase that way, so the coinbase must be a version 8 tx.
	if(g_current_algo && g_current_algo->merkle_func == sha3d_hash_hex)
		strcpy(eversion1, "08000000");

	const char *coinbase_payload = json_get_string(json_result, "coinbase_payload");
	if(coinbase_payload && strlen(coinbase_payload) > 0)
		strcpy(eversion1, "03000500"); // DIP2 special tx: version 3, type 5 (CbTx)

	char script1[4*1024];
	sprintf(script1, "%s%s%s08", eheight, templ->flags, etime);

	char script2[32] = "746865706f6f6c2e6c6966655c30"; // "thepool.life\0" in hex ascii

	if(!coind->pos && !coind->isaux && templ->auxs_size)
		coinbase_aux(templ, script2);

	int script_len = strlen(script1)/2 + strlen(script2)/2 + 8;
	sprintf(templ->coinb1, "%s%s01"
		"0000000000000000000000000000000000000000000000000000000000000000"
		"ffffffff%02x%s", eversion1, entime, script_len, script1);

	sprintf(templ->coinb2, "%s00000000", script2);

	// segwit commitment, if needed
	if (templ->has_segwit_txs)
		snprintf(commitment, sizeof(commitment), "0000000000000000%02x%s", (int) (strlen(coind->commitment)/2), coind->commitment);

	json_int_t available = templ->value;

	// sample coins using mandatory dev/foundation fees
	if(strcmp(coind->symbol, "EGC") == 0) {
		if (coind->charity_percent <= 0)
			coind->charity_percent = 2;
		if (strlen(coind->charity_address) == 0)
			sprintf(coind->charity_address, "EdFwYw4Mo2Zq6CFM2yNJgXvE2DTJxgdBRX");
	}
	else if(strcmp(coind->symbol, "DYN") == 0)
	{
		char script_dests[2048] = { 0 };
		char script_payee[128] = { 0 };
		char payees[16];
		int npayees = (templ->has_segwit_txs) ? 2 : 1;
		bool dynode_enabled;
		dynode_enabled = json_get_bool(json_result, "dynode_payments_enforced");
		bool superblocks_enabled = json_get_bool(json_result, "superblocks_enabled");
		json_value* superblock = json_get_array(json_result, "superblock");
		json_value* dynode;
		dynode = json_get_object(json_result, "dynode");
		if(!dynode && json_get_bool(json_result, "dynode_payments")) {
			coind->oldmasternodes = true;
			debuglog("%s is using old dynodes rpc keys\n", coind->symbol);
			return;
		}

		if(superblocks_enabled && superblock) {
			for(int i = 0; i < superblock->u.array.length; i++) {
				const char *payee = json_get_string(superblock->u.array.values[i], "payee");
				json_int_t amount = json_get_int(superblock->u.array.values[i], "amount");
				if (payee && amount) {
					npayees++;
					available -= amount;
					base58_decode(payee, script_payee);
					job_pack_tx(coind, script_dests, amount, script_payee);
					//debuglog("%s superblock found %s %u\n", coind->symbol, payee, amount);
				}
			}
		}
		if (dynode_enabled && dynode) {
			bool started;
			started = json_get_bool(json_result, "dynode_payments_started");
			const char *payee = json_get_string(dynode, "payee");
			json_int_t amount = json_get_int(dynode, "amount");
			if (!payee)
				debuglog("coinbase_create failed to get Dynode payee\n");

			if (!amount)
				debuglog("coinbase_create failed to get Dynode amount\n");

			if (!started)
				debuglog("coinbase_create failed to get Dynode started\n");

			if (payee && amount && started) {
				npayees++;
				available -= amount;
				base58_decode(payee, script_payee);
				job_pack_tx(coind, script_dests, amount, script_payee);
				//debuglog("%s dynode found %s %u\n", coind->symbol, payee, amount);
			}
		}
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		strcat(templ->coinb2, script_dests);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime
		coind->reward = (double)available/100000000*coind->reward_mul;
		//debuglog("%s %d dests %s\n", coind->symbol, npayees, script_dests);
		return;
	}

	else if(strcmp(coind->symbol, "IDX") == 0)
	{
		char script_dests[2048] = { 0 };
		char script_payee[128] = { 0 };
		char payees[16];
		int npayees = (templ->has_segwit_txs) ? 2 : 1;
		json_value* indexnode;
		indexnode = json_get_object(json_result, "indexnode");
		if(!indexnode && json_get_bool(json_result, "indexnode_payments")) {
			coind->oldmasternodes = true;
			debuglog("%s is using old indexnodes rpc keys\n", coind->symbol);
			return;
		}
		if (indexnode) {
			bool started;
			started = json_get_bool(json_result, "indexnode_payments_started");
			const char *payee = json_get_string(indexnode, "payee");
			json_int_t amount = json_get_int(indexnode, "amount");
			if (!payee)
				debuglog("coinbase_create failed to get Indexnode payee\n");

			if (!amount)
				debuglog("coinbase_create failed to get Indexnode amount\n");

			if (!started)
				debuglog("coinbase_create failed to get Indexnode started\n");

			if (payee && amount && started) {
				npayees++;
				base58_decode(payee, script_payee);
				job_pack_tx(coind, script_dests, amount, script_payee);
				//debuglog("%s indexnode found %s %u\n", coind->symbol, payee, amount);
			}
		}
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		strcat(templ->coinb2, script_dests);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime
		coind->reward = (double)available/100000000*coind->reward_mul;
		//debuglog("%s %d dests %s\n", coind->symbol, npayees, script_dests);
		return;
	}


	else if(strcmp(coind->symbol, "GXX") == 0) {
	  char script_payee[1024];

	  bool znode_masternode_enabled = json_get_bool(json_result, "xnode_payments_started");
	  if (znode_masternode_enabled == true) {
	    json_value* znode_masternode = json_get_object(json_result, "xnode");
	    const char *payee = json_get_string(znode_masternode, "payee");
	    json_int_t amount = json_get_int(znode_masternode, "amount");
	    if (payee && amount) {
	      //debuglog("xnode payee: %s\n", payee);
	      strcat(templ->coinb2, "04");
	      job_pack_tx(coind, templ->coinb2, available, NULL);

	      base58_decode(payee, script_payee);
	      job_pack_tx(coind, templ->coinb2, amount, script_payee);
	    }
	  } else {
	    strcat(templ->coinb2, "03");
	    job_pack_tx(coind, templ->coinb2, available, NULL);
	  }

	  base58_decode("HU9t1QEp5J8udekCqFUEajD5TeigPqtfDZ", script_payee);
	  job_pack_tx(coind, templ->coinb2, 2 * 100000000, script_payee);

	  base58_decode("HLFmojjH6qLBTh5EXtbY9j9v4BCkNpmt95", script_payee);
	  job_pack_tx(coind, templ->coinb2, 1.5 * 100000000, script_payee);

	  strcat(templ->coinb2, "00000000"); // locktime
	  coind->reward = (double)available/100000000*coind->reward_mul;

	  return;
	}

	else if(strcmp(coind->symbol, "LTCR") == 0) {
		if (coind->charity_percent <= 0)
			coind->charity_percent = 10;
		if (strlen(coind->charity_address) == 0)
			sprintf(coind->charity_address, "BCDrF1hWdKTmrjXXVFTezPjKBmGigmaXg5");
	}

	else if(strcmp(coind->symbol, "GEEK") == 0) {
		if (coind->charity_percent <= 0)
			coind->charity_percent = 2.5;
		if (strlen(coind->charity_address) == 0)
			sprintf(coind->charity_address, "GRpdbSh3Z2FMjJH96CFPK5TzEb47Zg6FFR");
	}

	else if(strcmp(coind->symbol, "XZC") == 0) {
        char script_payee[1024];
         bool znode_masternode_enabled = json_get_bool(json_result, "znode_payments_started");
        if (znode_masternode_enabled == true) {
            json_value* znode_masternode = json_get_object(json_result, "znode");
            const char *payee = json_get_string(znode_masternode, "payee");
            json_int_t amount = json_get_int(znode_masternode, "amount");
            if (payee && amount) {
                //debuglog("znode payee: %s\n", payee);
                strcat(templ->coinb2, "06");
                job_pack_tx(coind, templ->coinb2, available, NULL);
                 base58_decode(payee, script_payee);
                job_pack_tx(coind, templ->coinb2, amount, script_payee);
            }
        } else {
            strcat(templ->coinb2, "06");
            job_pack_tx(coind, templ->coinb2, available, NULL);
        }
         base58_decode("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr", script_payee);
        job_pack_tx(coind, templ->coinb2, 1 * 100000000, script_payee);
         base58_decode("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD", script_payee);
        job_pack_tx(coind, templ->coinb2, 1 * 100000000, script_payee);
         base58_decode("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN", script_payee);
        job_pack_tx(coind, templ->coinb2, 1 * 100000000, script_payee);
         base58_decode("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3", script_payee);
        job_pack_tx(coind, templ->coinb2, 3 * 100000000, script_payee);
         base58_decode("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U", script_payee);
        job_pack_tx(coind, templ->coinb2, 1 * 100000000, script_payee);
         strcat(templ->coinb2, "00000000"); // locktime
        coind->reward = (double)available/100000000*coind->reward_mul;
         return;
    }

	else if(strcmp("DCR", coind->rpcencoding) == 0) {
		coind->reward_mul = 6;  // coinbase value is wrong, reward_mul should be 6
		coind->charity_percent = 0;
		coind->charity_amount = available;
		available *= coind->reward_mul;
		if (strlen(coind->charity_address) == 0 && !strcmp(coind->symbol, "DCR"))
			sprintf(coind->charity_address, "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx");
	}

	 else if(strcmp(coind->symbol, "HXX") == 0) {
        char script_payee[1024];
         bool znode_masternode_enabled = json_get_bool(json_result, "xnode_payments_started");
        if (znode_masternode_enabled == true) {
            json_value* znode_masternode = json_get_object(json_result, "xnode");
            const char *payee = json_get_string(znode_masternode, "payee");
            json_int_t amount = json_get_int(znode_masternode, "amount");
            if (payee && amount) {
                //debuglog("bznode payee: %s\n", payee);
                strcat(templ->coinb2, "06");
                job_pack_tx(coind, templ->coinb2, available, NULL);
                 base58_decode(payee, script_payee);
                job_pack_tx(coind, templ->coinb2, amount, script_payee);
            }
        } else {
            strcat(templ->coinb2, "05");
            job_pack_tx(coind, templ->coinb2, available, NULL);
        }
         base58_decode("HE7NSv3jevUAPjwsLGpoYSz9ftzV9S36Xq", script_payee);
        job_pack_tx(coind, templ->coinb2, 0.1 * 100000000, script_payee);
         base58_decode("HNdzbEtifr2nTd3VBvUWqJLc35ZFXr2EYo", script_payee);
        job_pack_tx(coind, templ->coinb2, 0.1 * 100000000, script_payee);
         base58_decode("HG1utYiVhkgBNz5ezrVpsjABxmMdVdcQe5", script_payee);
        job_pack_tx(coind, templ->coinb2, 0.1 * 100000000, script_payee);
         base58_decode("H94j1zMAbWwHWcEq8hUogAMALpVzj34M6Q", script_payee);
        job_pack_tx(coind, templ->coinb2, 0.3 * 100000000, script_payee);
         strcat(templ->coinb2, "00000000"); // locktime
        coind->reward = (double)available/100000000*coind->reward_mul;
         return;
    }

	    else if(strcmp(coind->symbol, "BZX") == 0) {
            char script_payee[1024];
             bool znode_masternode_enabled = json_get_bool(json_result, "bznode_payments_started");
            if (znode_masternode_enabled == true) {
                json_value* znode_masternode = json_get_object(json_result, "bznode");
                const char *payee = json_get_string(znode_masternode, "payee");
                json_int_t amount = json_get_int(znode_masternode, "amount");
                if (payee && amount) {
                    //debuglog("bznode payee: %s\n", payee);
                    strcat(templ->coinb2, "04");
                    job_pack_tx(coind, templ->coinb2, available, NULL);
                     base58_decode(payee, script_payee);
                    job_pack_tx(coind, templ->coinb2, amount, script_payee);
                }
            } else {
                strcat(templ->coinb2, "03");
                job_pack_tx(coind, templ->coinb2, available, NULL);
            }
             base58_decode("XWfdnGbXnBxeegrPJEvnYaNuwf6DXCruMX", script_payee);
            job_pack_tx(coind, templ->coinb2, 6.75 * 100000000, script_payee);
             base58_decode("XQ4WEZTFP83gVhhLBKavwopz7U84JucR8w", script_payee);
            job_pack_tx(coind, templ->coinb2, 2.25 * 100000000, script_payee);
             strcat(templ->coinb2, "00000000"); // locktime
            coind->reward = (double)available/100000000*coind->reward_mul;
             return;
        }

	else if(strcmp(coind->symbol, "STAK") == 0) {
		char script_payee[512] = { 0 };
		char payees[16];
		int npayees = (templ->has_segwit_txs) ? 2 : 1;
		bool masternode_payments = json_get_bool(json_result, "masternode_payments");
		bool masternodes_enabled = json_get_bool(json_result, "enforce_masternode_payments");

		if (masternodes_enabled && masternode_payments) {
			const char *payee = json_get_string(json_result, "payee");
			json_int_t amount = json_get_int(json_result, "payee_amount");
			if (payee && amount)
				++npayees;
		}

		//treasury 5% @ 10 STAK per block
		json_int_t charity_amount = 50000000;
		//testnet
		//sprintf(coind->charity_address, "93ASJtDuVYVdKXemH9BrtSMscznvsp9stD");
		switch (templ->height % 4) {
			case 0: sprintf(coind->charity_address, "3K3bPrW5h7DYEMp2RcXawTCXajcm4ZU9Zh");
			break;
			case 1: sprintf(coind->charity_address, "33Ssxmn3ehVMgyxgegXhpLGSBpubPjLZQ6");
			break;
			case 2: sprintf(coind->charity_address, "3HFPNAjesiBY5sSVUmuBFnMEGut69R49ca");
			break;
			case 3: sprintf(coind->charity_address, "37jLjjfUXQU4bdqVzvpUXyzAqPQSmxyByi");
			break;
		}
		++npayees;
		available -= charity_amount;
		base58_decode(coind->charity_address, script_payee);
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		char echarity_amount[32];
		encode_tx_value(echarity_amount, charity_amount);
		strcat(templ->coinb2, echarity_amount);
		char coinb2_part[1024] = { 0 };
		char coinb2_len[3] = { 0 };
		sprintf(coinb2_part, "a9%02x%s87", (unsigned int)(strlen(script_payee) >> 1) & 0xFF, script_payee);
		sprintf(coinb2_len, "%02x", (unsigned int)(strlen(coinb2_part) >> 1) & 0xFF);
		strcat(templ->coinb2, coinb2_len);
		strcat(templ->coinb2, coinb2_part);
		if (masternodes_enabled && masternode_payments) {
			//duplicated: revisit ++todo
			const char *payee = json_get_string(json_result, "payee");
			json_int_t amount = json_get_int(json_result, "payee_amount");
			if (payee && amount) {
				available -= amount;
				base58_decode(payee, script_payee);
				job_pack_tx(coind, templ->coinb2, amount, script_payee);
			}
		}
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime

		coind->reward = (double)available / 100000000 * coind->reward_mul;
		return;
	}
	else if(strcmp(coind->symbol, "TUX") == 0)  {
		char script_payee[1024];
		char charity_payee[256] = { 0 };
		const char *payee = json_get_string(json_result, "donation_payee");
		if(payee != NULL){
			sprintf(coind->charity_address, "%s", payee);
		} else {
			sprintf(coind->charity_address, "%s", "");
		}

		if(strlen(coind->charity_address) > 0){
			char script_payee[1024];
			char charity_payee[256] = { 0 };
			snprintf(charity_payee, sizeof(charity_payee), "%s", coind->charity_address);
			if (strlen(charity_payee) == 0)
				stratumlog("ERROR %s has no charity_address set!\n", coind->name);

			base58_decode(charity_payee, script_payee);

			json_int_t charity_amount = json_get_int(json_result, "donation_amount");
			coind->charity_amount = charity_amount;

			if (templ->has_segwit_txs) {
				strcat(templ->coinb2, "03"); // 3 outputs (nulldata + fees + miner)
				strcat(templ->coinb2, commitment);
			} else {
				strcat(templ->coinb2, "02");
			}
			job_pack_tx(coind, templ->coinb2, available, NULL);

			char echarity_amount[32];
			encode_tx_value(echarity_amount, charity_amount);
			strcat(templ->coinb2, echarity_amount);
			char coinb2_part[1024] = { 0 };
			char coinb2_len[3] = { 0 };
			sprintf(coinb2_part, "a9%02x%s87", (unsigned int)(strlen(script_payee) >> 1) & 0xFF, script_payee);
			sprintf(coinb2_len, "%02x", (unsigned int)(strlen(coinb2_part) >> 1) & 0xFF);
			strcat(templ->coinb2, coinb2_len);
			strcat(templ->coinb2, coinb2_part);
			debuglog("pack tx %s\n", coinb2_part);
			strcat(templ->coinb2, "00000000"); // locktime

			coind->reward = (double)available/100000000*coind->reward_mul;
			//debuglog("INFO %s block available %f, charity %f miner %f\n", coind->symbol,
			//	(double) available/1e8, (double) charity_amount/1e8, coind->reward);
			return;
		}
	}

	else if(strcmp(coind->symbol, "PGN") == 0)  {
	bool founder_enabled = json_get_bool(json_result, "founder_payments_started");
	json_value* founder = json_get_object(json_result, "founder");

	if (!coind->hasmasternodes && founder_enabled && founder) {
		char founder_payee[256] = { 0 };
		char founder_script[1024] = { 0};
		const char *payee = json_get_string(founder, "payee");
		bool founder_use_p2sh = (strcmp(coind->symbol, "PGN") == 0);
		json_int_t amount = json_get_int(founder, "amount");
		if(payee && amount) {
			if (payee) snprintf(founder_payee, 255, "%s", payee);
			if (strlen(founder_payee) == 0)
				stratumlog("ERROR %s has no charity_address set!\n", coind->name);
			base58_decode(founder_payee, founder_script);
			available -= amount;

			if (templ->has_segwit_txs) {
				strcat(templ->coinb2, "03"); // 3 outputs (nulldata + fees + miner)
				strcat(templ->coinb2, commitment);
			} else {
				strcat(templ->coinb2, "02");
			}
			job_pack_tx(coind, templ->coinb2, available, NULL);
			if(founder_use_p2sh) {
				p2sh_pack_tx(coind, templ->coinb2, amount, founder_script);
			} else {
				job_pack_tx(coind, templ->coinb2, amount, founder_script);
			}
			strcat(templ->coinb2, "00000000"); // locktime

			coind->reward = (double)available/100000000*coind->reward_mul;
			debuglog("%s founder address %s, amount %lld\n", coind->symbol,founder_payee, (long long) amount);
			debuglog("%s founder script %s\n", coind->symbol,founder_script);
			debuglog("%s scripts %s\n", coind->symbol, templ->coinb2);

		return;
		}
	}
}

	else if(strcmp(coind->symbol, "RITO") == 0)  {
	bool founder_enabled = json_get_bool(json_result, "founder_payments_started");
	json_value* founder = json_get_object(json_result, "founder");

	if (!coind->hasmasternodes && founder_enabled && founder) {
		char founder_payee[256] = { 0 };
		char founder_script[1024] = { 0};
		const char *payee = json_get_string(founder, "payee");
		bool founder_use_p2sh = (strcmp(coind->symbol, "RITO") == 0);
		json_int_t amount = json_get_int(founder, "amount");
		if(payee && amount) {
			if (payee) snprintf(founder_payee, 255, "%s", payee);
			if (strlen(founder_payee) == 0)
				stratumlog("ERROR %s has no charity_address set!\n", coind->name);
			base58_decode(founder_payee, founder_script);
			available -= amount;

			if (templ->has_segwit_txs) {
				strcat(templ->coinb2, "03"); // 3 outputs (nulldata + fees + miner)
				strcat(templ->coinb2, commitment);
			} else {
				strcat(templ->coinb2, "02");
			}
			job_pack_tx(coind, templ->coinb2, available, NULL);
			if(founder_use_p2sh) {
				p2sh_pack_tx(coind, templ->coinb2, amount, founder_script);
			} else {
				job_pack_tx(coind, templ->coinb2, amount, founder_script);
			}
			strcat(templ->coinb2, "00000000"); // locktime

			coind->reward = (double)available/100000000*coind->reward_mul;
			debuglog("%s founder address %s, amount %lld\n", coind->symbol,founder_payee, (long long) amount);
			debuglog("%s founder script %s\n", coind->symbol,founder_script);
			debuglog("%s scripts %s\n", coind->symbol, templ->coinb2);

		return;
		}
	}
}

	// Firo (FIRO): "znode": [{payee, script, amount}] (deterministic masternodes) and a DIP3
	// "coinbase_payload". "coinbasevalue" is only the miner output: the daemon already took
	// the masternode and development/community fund shares out of it. The fund outputs are
	// not in the template (see firo_fund_outputs).
	json_value *firo_znode = json_get_array(json_result, "znode");
	if(json_is_array(firo_znode))
	{
		char script_dests[4096] = { 0 };
		char payees[16];
		int npayees = (templ->has_segwit_txs) ? 2 : 1;

		for(int i = 0; i < firo_znode->u.array.length; i++) {
			json_value *entry = firo_znode->u.array.values[i];
			if(pack_template_payment(coind, script_dests, sizeof(script_dests), entry)) npayees++;
		}
		int nfunds = firo_fund_outputs(coind, templ, script_dests, sizeof(script_dests));
		if(nfunds < 0) {
			templ->coinb2[0] = '\0'; // no valid coinbase: drop the template
			return;
		}
		npayees += nfunds;

		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, script_dests);
		strcat(templ->coinb2, "00000000"); // locktime
		if(coinbase_payload && strlen(coinbase_payload) > 0) {
			char coinbase_payload_size[18];
			ser_compactsize((unsigned int)(strlen(coinbase_payload) >> 1), coinbase_payload_size);
			strcat(templ->coinb2, coinbase_payload_size);
			strcat(templ->coinb2, coinbase_payload);
		}
		coind->reward = (double)available/100000000*coind->reward_mul;
		return;
	}

	// Meowcoin (MEWC): "CommunityAutonomousAddress", "CommunityAutonomousValue". The community
	// fund must be vout[1] (validation.cpp), "coinbasevalue" is the miner output (vout[0]).
	const char *mewc_address = json_get_string(json_result, "CommunityAutonomousAddress");
	json_int_t mewc_value = json_get_int(json_result, "CommunityAutonomousValue");
	if(mewc_address && strlen(mewc_address) && mewc_value > 0)
	{
		char script[256];
		if(!coind_address_script(coind, mewc_address, script, sizeof(script))) {
			templ->coinb2[0] = '\0';
			return;
		}
		strcat(templ->coinb2, templ->has_segwit_txs ? "03" : "02");
		job_pack_tx(coind, templ->coinb2, available, NULL);
		script_pack_tx(coind, templ->coinb2, mewc_value, script);
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		strcat(templ->coinb2, "00000000"); // locktime
		coind->reward = (double)available/100000000*coind->reward_mul;
		return;
	}

	// Evrmore (EVR): "coinbasetxn": {"minerdevfund": {"addresses": [...], "minimumvalue": n}},
	// an output of at least minimumvalue to one of the addresses is required (validation.cpp
	// bad-cb-minerdevfund), "coinbasevalue" is the whole coinbase value.
	json_value *evr_coinbasetxn = json_get_object(json_result, "coinbasetxn");
	json_value *evr_fund = evr_coinbasetxn && evr_coinbasetxn->type == json_object ?
		json_get_object(evr_coinbasetxn, "minerdevfund") : NULL;
	json_value *evr_addresses = evr_fund && evr_fund->type == json_object ? json_get_array(evr_fund, "addresses") : NULL;
	if(json_is_array(evr_addresses) && evr_addresses->u.array.length > 0)
	{
		json_int_t fund_value = json_get_int(evr_fund, "minimumvalue");
		const char *fund_address = json_string_value(evr_addresses->u.array.values[0]);
		char script[256];
		if(fund_value <= 0 || !coind_address_script(coind, fund_address, script, sizeof(script))) {
			templ->coinb2[0] = '\0';
			return;
		}
		available -= fund_value;
		strcat(templ->coinb2, templ->has_segwit_txs ? "03" : "02");
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		script_pack_tx(coind, templ->coinb2, fund_value, script);
		strcat(templ->coinb2, "00000000"); // locktime
		coind->reward = (double)available/100000000*coind->reward_mul;
		return;
	}

	// Raptoreum (RTM) and its clones, Dash-derived. getblocktemplate (src/rpc/mining.cpp) gives
	//   "smartnode": [{payee, script, amount}], "smartnode_payments_started/_enforced",
	//   "superblock": [{payee, script, amount}], "superblocks_started/_enabled",
	//   "founder": {payee, script, amount}, "founder_payments_started",
	//   "coinbase_payload": the CbTx of the DIP3 special coinbase (version 3, type 5).
	// "coinbasevalue" is the whole coinbase value, the daemon takes the smartnode and
	// founder shares out of the miner output (FillBlockPayments, FillFounderPayment), and
	// validation requires every smartnode output exactly (CSmartnodePayments::IsTransactionValid)
	// and a founder output >= the founder share (FounderPayment::IsBlockPayeeValid).
	// Keyed on the template fields so that clones work whatever their symbol and without
	// the "hasmasternodes" coin flag; a clone that kept the Dash "masternode" name
	// (array or object) is handled the same way.
	json_value *rtm_smartnode = json_get_array(json_result, "smartnode");
	json_value *rtm_founder = json_get_object(json_result, "founder");
	// Also used for a Dash-style template with a CbTx payload when the coin is not flagged
	// "hasmasternodes" (VKAX and other Dash forks): a version 3 type 5 coinbase always
	// needs the payload after the locktime.
	if(json_is_array(rtm_smartnode) || json_get_object(json_result, "founder_payments_started")
		|| (!coind->hasmasternodes && coinbase_payload && strlen(coinbase_payload) > 0))
	{
		char script_dests[4096] = { 0 };
		char payees[16];
		int npayees = (templ->has_segwit_txs) ? 2 : 1;
		json_int_t amount;

		json_value *nodes = rtm_smartnode;
		if(!json_is_array(nodes)) nodes = json_get_array(json_result, "masternode");
		if(json_is_array(nodes)) {
			for(int i = 0; i < nodes->u.array.length; i++) {
				amount = pack_template_payment(coind, script_dests, sizeof(script_dests), nodes->u.array.values[i]);
				if(amount) { npayees++; available -= amount; }
			}
		} else if(nodes && nodes->type == json_object) {
			amount = pack_template_payment(coind, script_dests, sizeof(script_dests), nodes);
			if(amount) { npayees++; available -= amount; }
		}

		json_value *superblock = json_get_array(json_result, "superblock");
		if(json_is_array(superblock)) {
			for(int i = 0; i < superblock->u.array.length; i++) {
				amount = pack_template_payment(coind, script_dests, sizeof(script_dests), superblock->u.array.values[i]);
				if(amount) { npayees++; available -= amount; }
			}
		}

		// founder: an object, or an array of objects in some clones
		if(json_is_array(rtm_founder)) {
			for(int i = 0; i < rtm_founder->u.array.length; i++) {
				amount = pack_template_payment(coind, script_dests, sizeof(script_dests), rtm_founder->u.array.values[i]);
				if(amount) { npayees++; available -= amount; }
			}
		} else {
			amount = pack_template_payment(coind, script_dests, sizeof(script_dests), rtm_founder);
			if(amount) { npayees++; available -= amount; }
		}

		if(available < 0) {
			stratumlog("ERROR %s coinbase payments exceed the block value!\n", coind->symbol);
			available = 0;
		}

		size_t payload_len = coinbase_payload ? strlen(coinbase_payload) : 0;
		if(npayees > 252 || strlen(templ->coinb2) + strlen(script_dests) + payload_len + 256 > sizeof(templ->coinb2)) {
			stratumlog("ERROR %s coinbase too large (%d outputs)\n", coind->symbol, npayees);
			return;
		}
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		strcat(templ->coinb2, script_dests);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime
		if(payload_len > 0) {
			char coinbase_payload_size[18];
			ser_compactsize((unsigned int)(payload_len >> 1), coinbase_payload_size);
			strcat(templ->coinb2, coinbase_payload_size);
			strcat(templ->coinb2, coinbase_payload);
		}

		coind->reward = (double)available/100000000*coind->reward_mul;
		return;
	}

	// Kylacoin (KCN), Lyncoin (LCN): "coinbasedevreward": {value, scriptpubkey, address}.
	// Here "coinbasevalue" is only the miner output (vout[0] of the daemon's coinbase), the
	// developer output comes on top of it and is required by ConnectBlock (devreward-not-found).
	json_value *devreward = json_get_object(json_result, "coinbasedevreward");
	if(devreward && devreward->type == json_object && !coind->hasmasternodes
		&& json_get_int(devreward, "value") > 0 && json_get_string(devreward, "scriptpubkey"))
	{
		const char *dev_script = json_get_string(devreward, "scriptpubkey");
		json_int_t dev_value = json_get_int(devreward, "value");

		if (templ->has_segwit_txs) {
			strcat(templ->coinb2, "03"); // commitment + miner + dev
			strcat(templ->coinb2, commitment);
		} else {
			strcat(templ->coinb2, "02");
		}
		job_pack_tx(coind, templ->coinb2, available, NULL);
		script_pack_tx(coind, templ->coinb2, dev_value, dev_script);
		strcat(templ->coinb2, "00000000"); // locktime

		coind->reward = (double)available/100000000*coind->reward_mul;
		return;
	}

	// 2 txs are required on these coins, one for foundation (dev fees)
	if(coind->charity_percent && !coind->hasmasternodes)
	{
		char script_payee[1024];
		char charity_payee[256] = { 0 };
		const char *payee = json_get_string(json_result, "payee");
		if (payee) snprintf(charity_payee, 255, "%s", payee);
		else snprintf(charity_payee, sizeof(charity_payee), "%s", coind->charity_address);
		if (strlen(charity_payee) == 0)
			stratumlog("ERROR %s has no charity_address set!\n", coind->name);

		base58_decode(charity_payee, script_payee);

		json_int_t charity_amount = json_get_int(json_result, "payee_amount");
		if (charity_amount <= 0)
			charity_amount = (available * coind->charity_percent) / 100;

		available -= charity_amount;
		coind->charity_amount = charity_amount;

		if (templ->has_segwit_txs) {
			strcat(templ->coinb2, "03"); // 3 outputs (nulldata + fees + miner)
			strcat(templ->coinb2, commitment);
		} else {
			strcat(templ->coinb2, "02");
		}
		job_pack_tx(coind, templ->coinb2, available, NULL);
		job_pack_tx(coind, templ->coinb2, charity_amount, script_payee);
		strcat(templ->coinb2, "00000000"); // locktime

		coind->reward = (double)available/100000000*coind->reward_mul;
		//debuglog("INFO %s block available %f, charity %f miner %f\n", coind->symbol,
		//	(double) available/1e8, (double) charity_amount/1e8, coind->reward);
		return;
	}

	else if(coind->charity_amount && !strcmp("DCR", coind->rpcencoding))
	{
		stratumlog("ERROR %s should not use coinbase (getwork only)!\n", coind->symbol);
		coind->reward = (double)available/100000000;
		return;
	}

	//  add IFX
	if (strcmp(coind->symbol, "IFX") == 0)
{
	char payees[16];
	int npayees = 1;
	char script_dests[4096] = { 0 };
	//
	json_value* founderreward = json_get_array(json_result, "founderreward");
	if (founderreward)
	{
		const char *payee = json_get_string(founderreward, "founderpayee");
		json_int_t amount = json_get_int(founderreward, "amount");
		if (payee && amount)
		{
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	json_value* masternode = json_get_object(json_result, "masternode");
	bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
	if (masternode_enabled && masternode)
	{
		bool started = json_get_bool(json_result, "masternode_payments_started");
		const char *payee = json_get_string(masternode, "payee");
		json_int_t amount = json_get_int(masternode, "amount");
		if (started && payee && amount) {
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	sprintf(payees, "%02x", npayees);
	strcat(templ->coinb2, payees);
	strcat(templ->coinb2, script_dests);
	job_pack_tx(coind, templ->coinb2, available, NULL);
	strcat(templ->coinb2, "00000000"); // locktime
	coind->reward = (double)available / 100000000 * coind->reward_mul;
	return;
	}

	//  add GTM
	if (strcmp(coind->symbol, "GTM") == 0)
{
	char payees[16];
	int npayees = 1;
	char script_dests[4096] = { 0 };
	//
	json_value* founderreward = json_get_array(json_result, "founderreward");
	if (founderreward)
	{
		const char *payee = json_get_string(founderreward, "founderpayee");
		json_int_t amount = json_get_int(founderreward, "amount");
		if (payee && amount)
		{
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	json_value* masternode = json_get_object(json_result, "masternode");
	bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
	if (masternode_enabled && masternode)
	{
		bool started = json_get_bool(json_result, "masternode_payments_started");
		const char *payee = json_get_string(masternode, "payee");
		json_int_t amount = json_get_int(masternode, "amount");
		if (started && payee && amount) {
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	sprintf(payees, "%02x", npayees);
	strcat(templ->coinb2, payees);
	strcat(templ->coinb2, script_dests);
	job_pack_tx(coind, templ->coinb2, available, NULL);
	strcat(templ->coinb2, "00000000"); // locktime
	coind->reward = (double)available / 100000000 * coind->reward_mul;
	return;
	}

	//  add GWAY
	if (strcmp(coind->symbol, "GWAY") == 0)
{
	char payees[16];
	int npayees = 1;
	char script_dests[4096] = { 0 };
	//
	json_value* founderreward = json_get_array(json_result, "founderreward");
	if (founderreward)
	{
		const char *payee = json_get_string(founderreward, "founderpayee");
		json_int_t amount = json_get_int(founderreward, "amount");
		if (payee && amount)
		{
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	json_value* masternode = json_get_object(json_result, "masternode");
	bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
	if (masternode_enabled && masternode)
	{
		bool started = json_get_bool(json_result, "masternode_payments_started");
		const char *payee = json_get_string(masternode, "payee");
		json_int_t amount = json_get_int(masternode, "amount");
		if (started && payee && amount) {
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	sprintf(payees, "%02x", npayees);
	strcat(templ->coinb2, payees);
	strcat(templ->coinb2, script_dests);
	job_pack_tx(coind, templ->coinb2, available, NULL);
	strcat(templ->coinb2, "00000000"); // locktime
	coind->reward = (double)available / 100000000 * coind->reward_mul;
	return;
	}

	if (strcmp(coind->symbol, "AGM") == 0)
{
	char payees[16];
	int npayees = 1;
	char script_dests[4096] = { 0 };
	//
	json_value* founderreward = json_get_array(json_result, "founderreward");
	if (founderreward)
	{
		const char *payee = json_get_string(founderreward, "founderpayee");
		json_int_t amount = json_get_int(founderreward, "amount");
		if (payee && amount)
		{
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	json_value* masternode = json_get_object(json_result, "masternode");
	bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
	if (masternode_enabled && masternode)
	{
		bool started = json_get_bool(json_result, "masternode_payments_started");
		const char *payee = json_get_string(masternode, "payee");
		json_int_t amount = json_get_int(masternode, "amount");
		if (started && payee && amount) {
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	sprintf(payees, "%02x", npayees);
	strcat(templ->coinb2, payees);
	strcat(templ->coinb2, script_dests);
	job_pack_tx(coind, templ->coinb2, available, NULL);
	strcat(templ->coinb2, "00000000"); // locktime
	coind->reward = (double)available / 100000000 * coind->reward_mul;
	return;
	}

		//  add CRDS
	if (strcmp(coind->symbol, "CRDS") == 0)
{
	char payees[16];
	int npayees = 1;
	char script_dests[4096] = { 0 };
	//
	json_value* founderreward = json_get_array(json_result, "founderreward");
	if (founderreward)
	{
		const char *payee = json_get_string(founderreward, "founderpayee");
		json_int_t amount = json_get_int(founderreward, "amount");
		if (payee && amount)
		{
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	json_value* masternode = json_get_object(json_result, "masternode");
	bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
	if (masternode_enabled && masternode)
	{
		bool started = json_get_bool(json_result, "masternode_payments_started");
		const char *payee = json_get_string(masternode, "payee");
		json_int_t amount = json_get_int(masternode, "amount");
		if (started && payee && amount) {
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	sprintf(payees, "%02x", npayees);
	strcat(templ->coinb2, payees);
	strcat(templ->coinb2, script_dests);
	job_pack_tx(coind, templ->coinb2, available, NULL);
	strcat(templ->coinb2, "00000000"); // locktime
	coind->reward = (double)available / 100000000 * coind->reward_mul;
	return;
	}

	//  add BMN
	if (strcmp(coind->symbol, "BMN") == 0)
{
	char payees[16];
	int npayees = 1;
	char script_dests[4096] = { 0 };
	//
	json_value* founderreward = json_get_array(json_result, "founderreward");
	if (founderreward)
	{
		const char *payee = json_get_string(founderreward, "founderpayee");
		json_int_t amount = json_get_int(founderreward, "amount");
		if (payee && amount)
		{
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	json_value* masternode = json_get_object(json_result, "masternode");
	bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
	if (masternode_enabled && masternode)
	{
		bool started = json_get_bool(json_result, "masternode_payments_started");
		const char *payee = json_get_string(masternode, "payee");
		json_int_t amount = json_get_int(masternode, "amount");
		if (started && payee && amount) {
			char script_payee[128] = { 0 };
			npayees++;
			available -= amount;
			base58_decode(payee, script_payee);
			job_pack_tx(coind, script_dests, amount, script_payee);
		}
	}
 	sprintf(payees, "%02x", npayees);
	strcat(templ->coinb2, payees);
	strcat(templ->coinb2, script_dests);
	job_pack_tx(coind, templ->coinb2, available, NULL);
	strcat(templ->coinb2, "00000000"); // locktime
	coind->reward = (double)available / 100000000 * coind->reward_mul;
	return;
	}

 //add GLT
	else if(strcmp(coind->symbol, "GLT") == 0)
	{
		char script_dests[2048] = { 0 };
		char script_payee[128] = { 0 };
        char script_treasury[128] = { 0 };
		char payees[16];
		int npayees = 1;
		bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
		json_value* masternode = json_get_object(json_result, "masternode");
        json_value* treasury = json_get_object(json_result, "treasury");
        bool treasury_enabled = true;
		if(treasury_enabled && treasury) {
				const char *scriptPubKey = json_get_string(treasury, "scriptPubKey");
				json_int_t amount = json_get_int(treasury, "amount");
				if (scriptPubKey && amount) {
					npayees++;
					available -= amount;
                    base58_decode(scriptPubKey, script_treasury);
					job_pack_tx(coind, script_dests, amount, script_treasury);
					//debuglog("%s treasury %u\n", coind->symbol, amount);
				}
		}
		if (masternode_enabled && masternode) {
			const char *payee = json_get_string(masternode, "payee");
			json_int_t amount = json_get_int(masternode, "amount");
			if (payee && amount) {
				npayees++;
				available -= amount;
				base58_decode(payee, script_payee);
				job_pack_tx(coind, script_dests, amount, script_payee);
			}
		}
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		strcat(templ->coinb2, script_dests);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime
		coind->reward = (double)available/100000000*coind->reward_mul;
		//debuglog("%s %d dests %s\n", coind->symbol, npayees, script_dests);
		return;
	}

	// Add DigitalNote[XDN]
    if(strcmp(coind->symbol, "XDN") == 0) {

		// make sure we pay both mn and devops
		bool founder_enabled = json_get_bool(json_result, "founder_reward_enforced");
		bool masternode_enabled = json_get_bool(json_result, "enforce_masternode_payments");
		if (!founder_enabled || !masternode_enabled)
			return;

 			// founder/masternode vars
			char founder_script[1024] = { 0};
			char masternode_script[1024] = { 0};
			char founder_payee[256] = { 0};
			char masternode_payee[256] = { 0};
			json_int_t part_amount = (5000000000);
			json_int_t pool_amount = (5000000000*4);
			json_value* founder = json_get_object(json_result, "founderreward");
			const char *payee1 = json_get_string(json_result, "payee");
			const char *payee2 = json_get_string(founder, "payee");

 			// mn script
			snprintf(masternode_payee, 255, "%s", payee1);
			base58_decode(masternode_payee, masternode_script);
			available -= part_amount;

 			// payee script
			snprintf(founder_payee, 255, "%s", payee2);
			base58_decode(founder_payee, founder_script);
			available -= part_amount;

 			// total outputs
			strcat(templ->coinb2, "03");

 			// pack the tx
			job_pack_tx(coind, templ->coinb2, available, NULL);
			job_pack_tx(coind, templ->coinb2, part_amount, founder_script);
			job_pack_tx(coind, templ->coinb2, part_amount, masternode_script);
			strcat(templ->coinb2, "00000000");
			coind->reward = (double)available/100000000*coind->reward_mul;
			return;
    }

    if(strcmp(coind->symbol, "SIN") == 0)
    {
      int npayees = 1;
      char payees[16];
      char sinpayee[256] = {0};
      char sinscript[1024] = {0};
      char devpayee[256] = {0};
      char devscript[1024] = {0};
      const char *devpayaddr = json_get_string(json_result, "payee");
      json_int_t devfee_amount = json_get_int(json_result, "payee_amount");
      snprintf(devpayee, 255, "%s", devpayaddr);
      base58_decode(devpayee, devscript);
      npayees++;

      available -= devfee_amount;
      const char* mnpayaddrs[7] = {0};
      json_value* masternodes = json_get_array(json_result, "masternode");
      json_int_t mnamounts[7] = {0};
      int nmasternodes = json_is_array(masternodes) ? (int) masternodes->u.array.length : 0;
      if (nmasternodes > 7) nmasternodes = 7;
      for(int i = 0; i < nmasternodes; i++) {
      mnpayaddrs[i] = json_get_string(masternodes->u.array.values[i], "payee");
      mnamounts[i] = json_get_int(masternodes->u.array.values[i], "amount");
      available -= mnamounts[i];
      npayees++;
    }

      sprintf(payees, "%02x", npayees);
      strcat(templ->coinb2, payees);
      job_pack_tx(coind, templ->coinb2, available, NULL);
      job_pack_tx(coind, templ->coinb2, devfee_amount, devscript);
      for(int i = 0; i < nmasternodes; i++) {
          snprintf(sinpayee, 255, "%s", mnpayaddrs[i] ? mnpayaddrs[i] : "");
          base58_decode(sinpayee, sinscript);
          job_pack_tx(coind, templ->coinb2, mnamounts[i], sinscript);
      }

      strcat(templ->coinb2, "00000000");
      coind->reward = (double)available/100000000;
      return;
  }

	if(strcmp(coind->symbol, "BITC") == 0)
	{
		char *params = (char *)malloc(1024);
			if (params) {
			snprintf(params, 1024, "[\"%s\", %i]", coind->wallet, templ->height);
			//std::cout << "Params:" << params << std::endl;
			json_value *json = rpc_call(&coind->rpc, "createcoinbaseforaddress", params);
			free(params);
			if (json) {
				json_value *json_result = json_get_object(json, "result");
				const char *part1 = json_get_string(json_result, "coinbasepart1");
				const char *part2 = json_get_string(json_result, "coinbasepart2");
				if (part1 && part2 && strlen(part1) >= 16) {
					snprintf(templ->coinb1, sizeof(templ->coinb1), "%s", part1);
					templ->coinb1[strlen(templ->coinb1) - 16] = '\0';
					snprintf(templ->coinb2, sizeof(templ->coinb2), "%s", part2);
				}
			}
		}
		return;
	}

	if(strcmp(coind->symbol, "XVC") == 0)
	{
		char charity_payee[256];
		json_value* incentive = json_get_object(json_result, "incentive");
		if (incentive) {
			const char* payee = json_get_string(incentive, "address");
			if (payee) snprintf(charity_payee, 255, "%s", payee);
			else snprintf(charity_payee, sizeof(charity_payee), "%s", coind->charity_address);

			bool enforced = json_get_bool(incentive, "enforced");
			json_int_t charity_amount = json_get_int(incentive, "amount");
			if (enforced && charity_amount && strlen(charity_payee)) {
				char script_payee[1024];
				base58_decode(charity_payee, script_payee);

				strcat(templ->coinb2, "02");
				job_pack_tx(coind, templ->coinb2, available, NULL);
				job_pack_tx(coind, templ->coinb2, charity_amount, script_payee);
				strcat(templ->coinb2, "00000000"); // locktime

				coind->charity_amount = charity_amount;
				coind->reward = (double)available/100000000*coind->reward_mul;
				//debuglog("XVC coinbase %ld (+%ld incentive to %s)\n",
				//	(long) available, (long) charity_amount, charity_payee);
				return;
			}
		}
	}

	// most recent masternodes rpc (DASH, SIB, MUE, DSR, GBX...)
	if(coind->hasmasternodes && !coind->oldmasternodes)
	{
		char script_dests[2048] = { 0 };
		char script_payee[128] = { 0 };
		char payees[16]; // addresses count
		int npayees = (templ->has_segwit_txs) ? 2 : 1;
		bool masternode_enabled = json_get_bool(json_result, "masternode_payments_enforced");
		bool superblocks_enabled = json_get_bool(json_result, "superblocks_enabled");
		json_value* superblock = json_get_array(json_result, "superblock");
		json_value* masternode = json_get_object(json_result, "masternode");
		if(!masternode && json_get_bool(json_result, "masternode_payments")) {
			coind->oldmasternodes = true;
			debuglog("%s is using old masternodes rpc keys\n", coind->symbol);
			return;
		}
		if(coind->charity_percent) {
      char charity_payee[256] = { 0 };
    	const char *payee = json_get_string(json_result, "payee");
      if (payee) snprintf(charity_payee, 255, "%s", payee);
          else snprintf(charity_payee, sizeof(charity_payee), "%s", coind->charity_address);
      if (strlen(charity_payee) == 0)
          stratumlog("ERROR %s has no charity_address set!\n", coind->name);
          json_int_t charity_amount = (available * coind->charity_percent) / 100;
          npayees++;
          available -= charity_amount;
          coind->charity_amount = charity_amount;
          base58_decode(charity_payee, script_payee);
          job_pack_tx(coind, script_dests, charity_amount, script_payee);
      }
		// smart contracts balance refund, same format as DASH superblocks
		json_value* screfund = json_get_array(json_result, "screfund");
		if(screfund && screfund->u.array.length) {
			superblocks_enabled = true;
			superblock = screfund;
		}
		if(superblocks_enabled && superblock) {
			for(int i = 0; i < superblock->u.array.length; i++) {
				const char *payee = json_get_string(superblock->u.array.values[i], "payee");
				const char *script = json_get_string(superblock->u.array.values[i], "script");
				json_int_t amount = json_get_int(superblock->u.array.values[i], "amount");
				if (!amount) continue;
				if (script) {
					npayees++;
					available -= amount;
					script_pack_tx(coind, script_dests, amount, script);
				} else if (payee) {
					npayees++;
					available -= amount;
					base58_decode(payee, script_payee);
					bool superblock_use_p2sh = (strcmp(coind->symbol, "MAC") == 0);
					if(superblock_use_p2sh)
						p2sh_pack_tx(coind, script_dests, amount, script_payee);
					else
						job_pack_tx(coind, script_dests, amount, script_payee);
					//debuglog("%s superblock %s %u\n", coind->symbol, payee, amount);
				}
			}
		}

		bool started = json_get_bool(json_result, "masternode_payments_started");
		if (masternode_enabled && masternode && started) {
			if (json_is_array(masternode)) {
				for(int i = 0; i < masternode->u.array.length; i++) {
					const char *payee = json_get_string(masternode->u.array.values[i], "payee");
					const char *script = json_get_string(masternode->u.array.values[i], "script");
					json_int_t amount = json_get_int(masternode->u.array.values[i], "amount");
					if (!amount) continue;
					if (script) {
						npayees++;
						available -= amount;
						script_pack_tx(coind, script_dests, amount, script);
						} else if (payee) {
						npayees++;
						available -= amount;
						base58_decode(payee, script_payee);
						bool masternode_use_p2sh = (strcmp(coind->symbol, "MAC") == 0);
						if(masternode_use_p2sh)
							p2sh_pack_tx(coind, script_dests, amount, script_payee);
						else
							job_pack_tx(coind, script_dests, amount, script_payee);
						//debuglog("%s masternode %s %u\n", coind->symbol, payee, amount);
					}
				}
			} else {
				const char *payee = json_get_string(masternode, "payee");
				json_int_t amount = json_get_int(masternode, "amount");
				if (payee && amount) {
					npayees++;
					available -= amount;
					base58_decode(payee, script_payee);
					bool masternode_use_p2sh = (strcmp(coind->symbol, "MAC") == 0);
					if(masternode_use_p2sh)
						p2sh_pack_tx(coind, script_dests, amount, script_payee);
					else
						job_pack_tx(coind, script_dests, amount, script_payee);
				}
			}
		}
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		if (templ->has_segwit_txs) strcat(templ->coinb2, commitment);
		strcat(templ->coinb2, script_dests);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime
		if(coinbase_payload && strlen(coinbase_payload) > 0) {
			char coinbase_payload_size[18];
			ser_compactsize((unsigned int)(strlen(coinbase_payload) >> 1), coinbase_payload_size);
			strcat(templ->coinb2, coinbase_payload_size);
			strcat(templ->coinb2, coinbase_payload);
		}

		coind->reward = (double)available/100000000*coind->reward_mul;
		//debuglog("%s total %u available %u\n", coind->symbol, templ->value, available);
		//debuglog("%s %d dests %s\n", coind->symbol, npayees, script_dests);
		return;
	}

	else if(strcmp(coind->symbol, "ARC") == 0)
	{
		char script_dests[2048] = { 0 };
		char script_payee[128] = { 0 };
		char payees[16];
		int npayees = 1;
		bool masternode_enabled = json_get_bool(json_result, "goldminenode_payments_enforced");
		bool superblocks_enabled = json_get_bool(json_result, "superblocks_enabled");
		json_value* superblock = json_get_array(json_result, "superblock");
		json_value* masternode = json_get_object(json_result, "goldminenode");
		if(superblocks_enabled && superblock) {
			for(int i = 0; i < superblock->u.array.length; i++) {
				const char *payee = json_get_string(superblock->u.array.values[i], "payee");
				json_int_t amount = json_get_int(superblock->u.array.values[i], "amount");
				if (payee && amount) {
					npayees++;
					available -= amount;
					base58_decode(payee, script_payee);
					job_pack_tx(coind, script_dests, amount, script_payee);
					//debuglog("%s superblock %s %u\n", coind->symbol, payee, amount);
				}
			}
		}
		if (masternode_enabled && masternode) {
			const char *payee = json_get_string(masternode, "payee");
			json_int_t amount = json_get_int(masternode, "amount");
			if (payee && amount) {
				npayees++;
				available -= amount;
				base58_decode(payee, script_payee);
				job_pack_tx(coind, script_dests, amount, script_payee);
			}
		}
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		strcat(templ->coinb2, script_dests);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime
		coind->reward = (double)available/100000000*coind->reward_mul;
		//debuglog("%s %d dests %s\n", coind->symbol, npayees, script_dests);
		return;
	}

	else if(strcmp(coind->symbol, "ENT") == 0)
	{
		char script_dests[2048] = { 0 };
		char script_payee[128] = { 0 };
		char payees[16];
		int npayees = 1;
		bool masternode_enabled = json_get_bool(json_result, "eternitynode_payments_enforced");
		bool superblocks_enabled = json_get_bool(json_result, "superblocks_enabled");
		json_value* superblock = json_get_array(json_result, "superblock");
		json_value* masternode = json_get_object(json_result, "eternitynode");
		if(superblocks_enabled && superblock) {
			for(int i = 0; i < superblock->u.array.length; i++) {
				const char *payee = json_get_string(superblock->u.array.values[i], "payee");
				json_int_t amount = json_get_int(superblock->u.array.values[i], "amount");
				if (payee && amount) {
					npayees++;
					available -= amount;
					base58_decode(payee, script_payee);
					job_pack_tx(coind, script_dests, amount, script_payee);
					//debuglog("%s superblock %s %u\n", coind->symbol, payee, amount);
				}
			}
		}
		if (masternode_enabled && masternode) {
			const char *payee = json_get_string(masternode, "payee");
			json_int_t amount = json_get_int(masternode, "amount");
			if (payee && amount) {
				npayees++;
				available -= amount;
				base58_decode(payee, script_payee);
				job_pack_tx(coind, script_dests, amount, script_payee);
			}
		}
		sprintf(payees, "%02x", npayees);
		strcat(templ->coinb2, payees);
		strcat(templ->coinb2, script_dests);
		job_pack_tx(coind, templ->coinb2, available, NULL);
		strcat(templ->coinb2, "00000000"); // locktime
		coind->reward = (double)available/100000000*coind->reward_mul;
		//debuglog("%s %d dests %s\n", coind->symbol, npayees, script_dests);
		return;
	}


	else if(coind->hasmasternodes && coind->oldmasternodes) /* OLD DASH style */
	{
		char charity_payee[256] = { 0 };
		const char *payee = json_get_string(json_result, "payee");
		if (payee) snprintf(charity_payee, 255, "%s", payee);

		json_int_t charity_amount = json_get_int(json_result, "payee_amount");
		bool charity_payments = json_get_bool(json_result, "masternode_payments");
		bool charity_enforce = json_get_bool(json_result, "enforce_masternode_payments");

		if(strcmp(coind->symbol, "CRW") == 0)
		{
			char script_dests[2048] = { 0 };
			char script_payee[128] = { 0 };
			char payees[16];
			int npayees = 1;
			bool masternodes_enabled = json_get_bool(json_result, "enforce_masternode_payments");
			bool systemnodes_enabled = json_get_bool(json_result, "enforce_systemnode_payments");
			bool systemnodes = json_get_bool(json_result, "systemnodes");
			bool masternodes = json_get_bool(json_result, "masternodes");
			if(systemnodes_enabled && systemnodes) {
				const char *payeeSN = json_get_string(json_result, "payeeSN");
				json_int_t payeeSN_amount = json_get_int(json_result, "payeeSN_amount");
				if (payeeSN && payeeSN_amount) {
					npayees++;
					available -= payeeSN_amount;
					base58_decode(payeeSN, script_payee);
					job_pack_tx(coind, script_dests, payeeSN_amount, script_payee);
					//debuglog("%s systemnode %s %u\n", coind->symbol, payeeSN, payeeSN_amount);
				}
			}
			if (masternodes_enabled && masternodes) {
				const char *payee = json_get_string(json_result, "payee");
				json_int_t amount = json_get_int(json_result, "amount");
				if (payee && amount) {
					npayees++;
					available -= amount;
					base58_decode(payee, script_payee);
					job_pack_tx(coind, script_dests, amount, script_payee);
				}
			}
			sprintf(payees, "%02x", npayees);
			strcat(templ->coinb2, payees);
			strcat(templ->coinb2, script_dests);
			job_pack_tx(coind, templ->coinb2, available, NULL);
			strcat(templ->coinb2, "00000000"); // locktime
			coind->reward = (double)available/100000000*coind->reward_mul;
			//debuglog("%s %d dests %s\n", coind->symbol, npayees, script_dests);
			return;
		}

		if(charity_payments && charity_enforce)
		{
			char script_payee[256] = { 0 };
			base58_decode(charity_payee, script_payee);

			if (templ->has_segwit_txs) {
				strcat(templ->coinb2, "03"); // 3 outputs (nulldata + node + miner)
				strcat(templ->coinb2, commitment);
			} else {
				strcat(templ->coinb2, "02"); // 2 outputs
			}

			job_pack_tx(coind, templ->coinb2, charity_amount, script_payee);
			available -= charity_amount;

		} else {
			strcat(templ->coinb2, "01");
		}
	}

	else if (templ->has_segwit_txs) {
		strcat(templ->coinb2, "02");
		strcat(templ->coinb2, commitment);
	} else {
		strcat(templ->coinb2, "01");
	}

	job_pack_tx(coind, templ->coinb2, available, NULL);

	//if(coind->txmessage)
	//	strcat(templ->coinb2, "00");
	if(strcmp(coind->symbol, "DEM") == 0){if(coind->txmessage){strcat(templ->coinb2, "00");}} //fixes eMark.
  if(strcmp(coind->symbol, "FLO") == 0){if(coind->txmessage){strcat(templ->coinb2, "00");}} //fixes FlorinCoin
	if(strcmp(coind->symbol, "GIO") == 0){if(coind->txmessage){strcat(templ->coinb2, "00");}} //fixes GravioCoin
	strcat(templ->coinb2, "00000000"); // locktime

	coind->reward = (double)available/100000000*coind->reward_mul;
//	debuglog("coinbase %f\n", coind->reward);

//	debuglog("coinbase %s: version %s, nbits %s, time %s\n", coind->symbol, templ->version, templ->nbits, templ->ntime);
//	debuglog("coinb1 %s\n", templ->coinb1);
//	debuglog("coinb2 %s\n", templ->coinb2);
}
