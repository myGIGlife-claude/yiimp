// Stratum protocol families.
//
// The stratum was written for the Bitcoin stratum v1 job format (coinb1/coinb2, merkle
// branches, 80 byte header rolled by the miner with extranonce2/ntime/nonce). Other coin
// families use another job format with the same session and daemon (getblocktemplate/
// submitblock) logic. An algo selects its family in g_algo_protocols (protocol.cpp).
//
// The Bitcoin family has no YAAMP_PROTOCOL (g_protocol == NULL): all the existing code runs
// unchanged. A family is a table of hooks, called from the generic code at these points:
//
//   client.cpp       mining.subscribe       -> subscribe()          (after the common setup)
//                    mining.submit          -> submit()             (all the share handling)
//                    other methods          -> method()             (optional)
//   client_difficulty.cpp  client_send_difficulty -> send_difficulty()
//   coind_template.cpp     after coinbase_create  -> template_prepare() (per job data, with the
//                                                    getblocktemplate result)
//   stratum.cpp      conf file read         -> config()             (optional, own settings)
//   job_send.cpp     mining.notify          -> job_notify()         (per client if notify_per_client)
//
// The template (YAAMP_JOB_TEMPLATE) has a few proto_* fields the families can use for the
// per job data, and protocol.cpp has helpers shared by the families (targets, block
// assembly and submission, share accounting).
//
// Families:
//   KAWPOW    protocol_kawpow.cpp   kawpow, evrprogpow, meowpow, firopow, sccpow, meraki
//   EQUIHASH  protocol_equihash.cpp equihash (200,9), equihash144 (144,5), equihash192 (192,7):
//                                   Zcash style 140 byte headers + Equihash solutions, ZIP-301
//                                   stratum (mining.set_target, 32 byte nonce = nonce1 || nonce2)
//             (same file)           yespowerRES: Zcash style 140 byte header without solution,
//                                   Bitcoin stratum of its miner (only template/notify hooks)

#ifndef PROTOCOL_H
#define PROTOCOL_H

enum YAAMP_PROTOCOL_FAMILY
{
	YAAMP_PROTOCOL_BITCOIN = 0,
	YAAMP_PROTOCOL_KAWPOW,
	YAAMP_PROTOCOL_EQUIHASH,
};

struct YAAMP_PROTOCOL
{
	const char *name;
	int family;

	// answer mining.subscribe (client->extranonce1_default etc. are already set by the common code)
	bool (*subscribe)(YAAMP_CLIENT *client, json_value *json_params);

	// send the share difficulty (or target) to the miner
	int (*send_difficulty)(YAAMP_CLIENT *client, double difficulty);

	// called once per template, after coinbase_create(), gbt is the getblocktemplate result;
	// false drops the template
	bool (*template_prepare)(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, json_value *gbt);

	// mining.notify message; client is NULL when notify_per_client is false
	void (*job_notify)(YAAMP_JOB *job, YAAMP_CLIENT *client, char *buffer, int size);
	bool notify_per_client;

	// mining.submit: parse, validate, account the share, submit the block (returns false
	// to close the connection)
	bool (*submit)(YAAMP_CLIENT *client, json_value *json_params);

	// optional, other methods: return true if the method was handled, *keep = false closes
	// the connection
	bool (*method)(YAAMP_CLIENT *client, const char *method, json_value *json_params, bool *keep);

	// initialization at startup (conf read), optional
	void (*init)();

	// own settings of the conf file, optional (called before init)
	void (*config)(dictionary *ini);
};

// NULL for the Bitcoin family
extern const YAAMP_PROTOCOL *g_protocol;

const YAAMP_PROTOCOL *protocol_for_algo(const char *algo);
void protocol_config(dictionary *ini);
void protocol_init();

////////////////////////////////////////////////////////////////////////////////////////
// helpers for the families

// 256 bit targets as 32 bytes big endian (the order of the hexadecimal strings)
void protocol_nbits_to_target(const char *nbits, unsigned char target[32]);
void protocol_diff_to_target(const unsigned char diff1[32], double difficulty, unsigned char target[32]);
double protocol_target_to_diff(const unsigned char diff1[32], const unsigned char hash[32]);
bool protocol_hash_le_target(const unsigned char hash[32], const unsigned char target[32]);

// strip an optional 0x, check the length and the hexadecimal digits, copy in lower case
bool protocol_hex_param(const char *param, char *out, int hexlen);

// build the block (header_hex + transaction count + coinbase + transactions) and submit it
// to the daemon of the job; on success, record it for the blocks table (blockid is the
// hash the daemon gives to blocknotify, powhash the pow hash, both hexadecimal big endian)
bool protocol_submit_block(YAAMP_CLIENT *client, YAAMP_JOB *job, const char *header_hex,
	const char *coinbase_hex, const char *blockid, const char *powhash, double diff_user);

// share accounting and answer, as the Bitcoin path does
void protocol_share_accepted(YAAMP_CLIENT *client, YAAMP_JOB *job, char *nonce, double share_diff);
void protocol_share_rejected(YAAMP_CLIENT *client, YAAMP_JOB *job, int error, const char *message, char *nonce);

#endif
