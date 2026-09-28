/*
 * sha3-256t: SHA3-256(SHA3-256(SHA3-256(header))), BitcoinIII (BC3).
 *
 * FIPS 202 SHA3-256 (domain padding 0x06), not the Keccak-256 (0x01) of the
 * "keccak" algo.  Reference: BitcoinIII-Core src/hash.h HashWriterSHA3 and
 * src/crypto/sha3.cpp (MIT, commit 5b23c24e).  Post-fork BC3 blocks must
 * carry version bit 0x1000 (SHA3_VBIT), which the daemon sets in the
 * getblocktemplate version; the block hash (block id) is this hash too.
 */

#include <string.h>
#include <openssl/evp.h>

#include "sha3_256t.h"

void sha3_256t_hash(const char* input, char* output, uint32_t len)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hlen = 0;
	const EVP_MD *md = EVP_sha3_256();

	if (!EVP_Digest(input, len, hash, &hlen, md, NULL) ||
	    !EVP_Digest(hash, 32, hash, &hlen, md, NULL) ||
	    !EVP_Digest(hash, 32, hash, &hlen, md, NULL) || hlen != 32) {
		memset(output, 0xff, 32); /* never a valid share */
		return;
	}
	memcpy(output, hash, 32);
}
