/*
 * Verthash (Vertcoin, VTC) for the yiimp stratum.
 *
 * Port of vertcoin-core src/crypto/verthash.cpp (MIT, Copyright (c) 2018 The
 * Vertcoin developers, https://github.com/vertcoin-project/vertcoin-core,
 * commit da447cd4), in-RAM path only.  The SHA3 calls (tiny_sha3 in
 * vertcoin-core, FIPS 202 padding) use OpenSSL here.
 *
 * The ~1.2 GB verthash.dat is mapped once at startup (verthash_load_datafile)
 * and shared read-only by all the stratum threads.  Like the reference code
 * this assumes a little-endian host.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "verthash.h"

#define HEADER_SIZE 80
#define HASH_OUT_SIZE 32
#define P0_SIZE 64
#define N_ITER 8
#define N_SUBSET (P0_SIZE * N_ITER)
#define N_ROT 32
#define N_INDEXES 4096
#define BYTE_ALIGNMENT 16

static const uint8_t *vh_data = NULL;
static size_t vh_size = 0;

static inline uint32_t fnv1a(const uint32_t a, const uint32_t b)
{
	return (a ^ b) * 0x1000193;
}

int verthash_datafile_loaded(void)
{
	return vh_data != NULL;
}

int verthash_load_datafile(const char *path, int verify, char *err, size_t errlen)
{
	struct stat st;
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) || (unsigned long long) st.st_size != VERTHASH_DATAFILE_SIZE) {
		snprintf(err, errlen, "%s: wrong size %lld (expected %llu)", path,
			(long long) st.st_size, VERTHASH_DATAFILE_SIZE);
		close(fd);
		return -1;
	}
	void *p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		snprintf(err, errlen, "cannot map %s: %s", path, strerror(errno));
		return -1;
	}

	if (verify) {
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int mdlen = 0;
		char hex[65];
		if (!EVP_Digest(p, st.st_size, md, &mdlen, EVP_sha256(), NULL) || mdlen != 32) {
			snprintf(err, errlen, "%s: sha256 failed", path);
			munmap(p, st.st_size);
			return -1;
		}
		for (int i = 0; i < 32; i++)
			sprintf(hex + 2*i, "%02x", md[i]);
		if (strcmp(hex, VERTHASH_DATAFILE_SHA256)) {
			snprintf(err, errlen, "%s: bad sha256 %s (expected %s)", path, hex,
				VERTHASH_DATAFILE_SHA256);
			munmap(p, st.st_size);
			return -1;
		}
	}

	vh_data = (const uint8_t *) p;
	vh_size = st.st_size;
	return 0;
}

static void sha3(const void *in, size_t inlen, void *md, int mdlen)
{
	unsigned int len = 0;
	EVP_Digest(in, inlen, (unsigned char *) md, &len,
		mdlen == 64 ? EVP_sha3_512() : EVP_sha3_256(), NULL);
}

void verthash_hash(const char* input, char* output, uint32_t len)
{
	unsigned char input_header[HEADER_SIZE];
	uint32_t p1_32[HASH_OUT_SIZE / sizeof(uint32_t)];
	uint32_t p0_32[N_SUBSET / sizeof(uint32_t)];
	uint32_t seek_indexes[N_INDEXES];

	if (!vh_data) {
		memset(output, 0xff, HASH_OUT_SIZE); /* never a valid share */
		return;
	}

	memcpy(input_header, input, HEADER_SIZE);
	sha3(input_header, HEADER_SIZE, p1_32, HASH_OUT_SIZE);

	unsigned char *p0 = (unsigned char *) p0_32;
	for (size_t i = 0; i < N_ITER; i++) {
		input_header[0] += 1;
		sha3(input_header, HEADER_SIZE, p0 + i * P0_SIZE, P0_SIZE);
	}

	for (size_t x = 0; x < N_ROT; x++) {
		memcpy(seek_indexes + x * (N_SUBSET / sizeof(uint32_t)), p0_32, N_SUBSET);
		for (size_t y = 0; y < N_SUBSET / sizeof(uint32_t); y++)
			p0_32[y] = (p0_32[y] << 1) | (1 & (p0_32[y] >> 31));
	}

	const uint32_t *blob_bytes_32 = (const uint32_t *) vh_data;
	uint32_t value_accumulator = 0x811c9dc5;
	const uint32_t mdiv = ((vh_size - HASH_OUT_SIZE) / BYTE_ALIGNMENT) + 1;

	for (size_t i = 0; i < N_INDEXES; i++) {
		const uint32_t offset = (fnv1a(seek_indexes[i], value_accumulator) % mdiv)
			* (BYTE_ALIGNMENT / sizeof(uint32_t));
		for (size_t i2 = 0; i2 < HASH_OUT_SIZE / sizeof(uint32_t); i2++) {
			const uint32_t value = blob_bytes_32[offset + i2];
			p1_32[i2] = fnv1a(p1_32[i2], value);
			value_accumulator = fnv1a(value_accumulator, value);
		}
	}

	memcpy(output, p1_32, HASH_OUT_SIZE);
}
