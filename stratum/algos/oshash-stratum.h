/* YIIMP entry point for OSHash-Y (Old School Bitcoin). Kept out of the vendored oshash.h,
 * which stays a byte-for-byte copy of OSBTC/oshash/. */
#ifndef OSHASH_STRATUM_H
#define OSHASH_STRATUM_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void oshash_hash(const char *input, char *output, uint32_t len);
#ifdef __cplusplus
}
#endif
#endif
