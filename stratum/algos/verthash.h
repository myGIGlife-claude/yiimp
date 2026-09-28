#ifndef VERTHASH_H
#define VERTHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* size of the Vertcoin verthash.dat (index 17 xi-graph, 40108032 nodes of 32 bytes) */
#define VERTHASH_DATAFILE_SIZE 1283457024ULL

/* sha256sum of a valid verthash.dat (vertcoin-core verthashDatFileHash, byte order of sha256sum) */
#define VERTHASH_DATAFILE_SHA256 "a55531e843cd56b010114aaf6325b0d529ecf88f8ad47639b6ededafd721aa48"

/*
 * Map the data file read-only and, if verify is set, check its SHA-256.
 * Returns 0 on success, or -1 and a message in err on failure.
 * Must be called once before verthash_hash() is used.
 */
int verthash_load_datafile(const char *path, int verify, char *err, size_t errlen);
int verthash_datafile_loaded(void);

/* Vertcoin verthash of the 80-byte block header; all 0xff if no data file */
void verthash_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
