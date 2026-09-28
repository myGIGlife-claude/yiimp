/*
 * verthash_gen: create the Vertcoin verthash.dat (1283457024 bytes) needed by
 * the verthash stratum, without running a Vertcoin node.
 *
 *   make verthash_gen && ./verthash_gen /home/crypto-data/yiimp/site/stratum/verthash.dat
 *
 * Port of vertcoin-core src/crypto/verthash_datfile.cpp (MIT, Copyright (c)
 * 2018 The Vertcoin developers, https://github.com/vertcoin-project/vertcoin-core,
 * commit da447cd4).  The graph is built in RAM (needs ~1.3 GB of free memory)
 * instead of with a seek/read/write per node on disk, then written at once and
 * checked against the known SHA-256.  SHA3 (FIPS 202) comes from OpenSSL.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "algos/verthash.h"

#define NODE_SIZE 32

struct Graph {
	uint8_t *db;
	int64_t log2;
	int64_t pow2;
	uint8_t pk[NODE_SIZE];
	int64_t index;
};

static void sha3_256(const void *in, size_t inlen, uint8_t *out)
{
	unsigned int len = 0;
	if (!EVP_Digest(in, inlen, out, &len, EVP_sha3_256(), NULL) || len != 32) {
		fprintf(stderr, "sha3-256 failed\n");
		exit(1);
	}
}

static int64_t Log2(int64_t x)
{
	int64_t r = 0;
	for (; x > 1; x >>= 1)
		r++;
	return r;
}

static int64_t numXi(int64_t index)
{
	return (1 << ((uint64_t)index)) * (index + 1) * index;
}

static uint8_t *GetNode(struct Graph *g, const int64_t id)
{
	return g->db + (id & ~g->pow2) * NODE_SIZE;
}

static void WriteVarInt(uint8_t *buffer, int64_t val)
{
	memset(buffer, 0, NODE_SIZE);
	uint64_t uval = ((uint64_t)(val)) << 1;
	if (val < 0)
		uval = ~uval;
	uint32_t i = 0;
	while (uval >= 0x80) {
		buffer[i] = (uint8_t)uval | 0x80;
		uval >>= 7;
		i++;
	}
	buffer[i] = (uint8_t)uval;
}

/* node = sha3(pk || varint(id) || parents...) */
static void NewNode(struct Graph *g, int64_t id, const uint8_t *parent0, const uint8_t *parent1)
{
	uint8_t in[NODE_SIZE * 4];
	size_t n = 2;
	memcpy(in, g->pk, NODE_SIZE);
	WriteVarInt(in + NODE_SIZE, id);
	if (parent0) memcpy(in + NODE_SIZE * n++, parent0, NODE_SIZE);
	if (parent1) memcpy(in + NODE_SIZE * n++, parent1, NODE_SIZE);
	sha3_256(in, NODE_SIZE * n, GetNode(g, id));
}

static void ButterflyGraph(struct Graph *g, int64_t index, int64_t *count)
{
	if (index == 0)
		index = 1;

	int64_t numLevel = 2 * index;
	int64_t perLevel = (int64_t)(1 << (uint64_t)index);
	int64_t begin = *count - perLevel;

	for (int64_t level = 1; level < numLevel; level++) {
		for (int64_t i = 0; i < perLevel; i++) {
			int64_t prev;
			int64_t shift = index - level;
			if (level > numLevel / 2)
				shift = level - numLevel / 2;
			if (((i >> (uint64_t)shift) & 1) == 0)
				prev = i + (1 << (uint64_t)shift);
			else
				prev = i - (1 << (uint64_t)shift);

			uint8_t parent0[NODE_SIZE], parent1[NODE_SIZE];
			memcpy(parent0, GetNode(g, begin + (level - 1) * perLevel + prev), NODE_SIZE);
			memcpy(parent1, GetNode(g, *count - perLevel), NODE_SIZE);
			NewNode(g, *count, parent0, parent1);
			(*count)++;
		}
	}
}

static void XiGraphIter(struct Graph *g, int64_t index)
{
	int64_t count = g->pow2;

	/* explicit stacks, as in the reference (at most 5 + 5*depth entries) */
	int64_t stack[256];
	int32_t graphStack[256];
	int stackSize = 5, graphStackSize = 5;
	for (int i = 0; i < 5; i++) {
		stack[i] = index;
		graphStack[i] = graphStackSize - i - 1;
	}

	int64_t pow2index = 1 << ((uint64_t)index);
	for (int64_t i = 0; i < pow2index; i++) {
		NewNode(g, count, NULL, NULL);
		count++;
	}

	if (index == 1) {
		ButterflyGraph(g, index, &count);
		return;
	}

	while (stackSize != 0 && graphStackSize != 0) {
		index = stack[--stackSize];
		int32_t graph = graphStack[--graphStackSize];

		int64_t pow2indexInner = 1 << ((uint64_t)index);
		int64_t pow2indexInner_1 = 1 << ((uint64_t)index - 1);

		if (graph == 0) {
			uint64_t sources = count - pow2indexInner;
			for (int64_t i = 0; i < pow2indexInner_1; i++) {
				uint8_t parent0[NODE_SIZE], parent1[NODE_SIZE];
				memcpy(parent0, GetNode(g, sources + i), NODE_SIZE);
				memcpy(parent1, GetNode(g, sources + i + pow2indexInner_1), NODE_SIZE);
				NewNode(g, count, parent0, parent1);
				count++;
			}
		} else if (graph == 1 || graph == 2 || graph == 3) {
			/* firstXi, secondXi, secondButter: one parent each */
			uint64_t first = count;
			for (int64_t i = 0; i < pow2indexInner_1; i++) {
				uint8_t parent[NODE_SIZE];
				memcpy(parent, GetNode(g, first - pow2indexInner_1 + i), NODE_SIZE);
				NewNode(g, first + i, parent, NULL);
				count++;
			}
		} else {
			uint64_t sinks = count;
			uint64_t sources = sinks + pow2indexInner - numXi(index);
			for (int64_t i = 0; i < pow2indexInner_1; i++) {
				uint64_t nodeId0 = sinks + i;
				uint64_t nodeId1 = sinks + i + pow2indexInner_1;
				uint8_t parent0[NODE_SIZE], parent1_0[NODE_SIZE], parent1_1[NODE_SIZE];
				memcpy(parent0, GetNode(g, sinks - pow2indexInner_1 + i), NODE_SIZE);
				memcpy(parent1_0, GetNode(g, sources + i), NODE_SIZE);
				memcpy(parent1_1, GetNode(g, sources + i + pow2indexInner_1), NODE_SIZE);
				NewNode(g, nodeId0, parent0, parent1_0);
				NewNode(g, nodeId1, parent0, parent1_1);
				count += 2;
			}
		}

		if ((graph == 0 || graph == 3) || ((graph == 1 || graph == 2) && index == 2)) {
			ButterflyGraph(g, index - 1, &count);
		} else if (graph == 1 || graph == 2) {
			if (stackSize + 5 > 256) {
				fprintf(stderr, "stack overflow\n");
				exit(1);
			}
			for (int i = 0; i < 5; i++) {
				stack[stackSize++] = index - 1;
				graphStack[graphStackSize++] = 5 - i - 1;
			}
		}
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <path/to/verthash.dat>\n", argv[0]);
		return 1;
	}

	struct Graph g;
	const int64_t index = 17;
	const char *seed = "Verthash Proof-of-Space Datafile";
	sha3_256(seed, 32, g.pk);

	int64_t size = numXi(index);
	g.log2 = Log2(size) + 1;
	g.pow2 = 1 << ((uint64_t)g.log2);
	g.index = index;
	g.db = (uint8_t *) calloc(size, NODE_SIZE);
	if (!g.db) {
		fprintf(stderr, "cannot allocate %lld bytes\n", (long long) size * NODE_SIZE);
		return 1;
	}
	if ((unsigned long long) size * NODE_SIZE != VERTHASH_DATAFILE_SIZE) {
		fprintf(stderr, "unexpected size\n");
		return 1;
	}

	fprintf(stderr, "generating %lld bytes...\n", (long long) size * NODE_SIZE);
	XiGraphIter(&g, index);

	unsigned char md[32];
	unsigned int mdlen = 0;
	char hex[65];
	EVP_Digest(g.db, size * NODE_SIZE, md, &mdlen, EVP_sha256(), NULL);
	for (int i = 0; i < 32; i++)
		sprintf(hex + 2*i, "%02x", md[i]);
	if (strcmp(hex, VERTHASH_DATAFILE_SHA256)) {
		fprintf(stderr, "bad sha256 %s (expected %s), not written\n", hex, VERTHASH_DATAFILE_SHA256);
		return 1;
	}

	char tmp[4096];
	snprintf(tmp, sizeof(tmp), "%s.tmp", argv[1]);
	FILE *f = fopen(tmp, "wb");
	if (!f || fwrite(g.db, NODE_SIZE, size, f) != (size_t) size || fclose(f)) {
		perror(tmp);
		return 1;
	}
	if (rename(tmp, argv[1])) {
		perror(argv[1]);
		return 1;
	}
	fprintf(stderr, "%s written, sha256 %s OK\n", argv[1], hex);
	free(g.db);
	return 0;
}
