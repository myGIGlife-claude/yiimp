/*
 * sha512256d: SHA-512/256(SHA-512/256(header)), Radiant (RXD).
 *
 * SHA-512/256 is the FIPS 180-4 function (own IV, not a truncated SHA-512).
 * Reference: radiant-node src/primitives/block.h
 * CalculateBlockHashFromHeader_sha512_256() (MIT, commit 3bfd3ed2):
 * the 32-byte digest is the block hash in internal byte order, as for sha256d.
 */

#include <string.h>
#include <openssl/evp.h>

#include "sha512256d.h"

void sha512256d_hash(const char* input, char* output, uint32_t len)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hlen = 0;
	const EVP_MD *md = EVP_sha512_256();

	if (!EVP_Digest(input, len, hash, &hlen, md, NULL) ||
	    !EVP_Digest(hash, 32, hash, &hlen, md, NULL) || hlen != 32) {
		memset(output, 0xff, 32); /* never a valid share */
		return;
	}
	memcpy(output, hash, 32);
}
