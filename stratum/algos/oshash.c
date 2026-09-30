#include "oshash.h"
#include "oshash_prims.h"
#include "yespower.h"
#include <stdlib.h>
#include <string.h>

/* Hosts whose yespower_tls has a different signature (cpuminer-opt adds thr_id) override this. */
#ifndef OSHASH_YESPOWER_CALL
#define OSHASH_YESPOWER_CALL(src, len, params, dst) yespower_tls((src), (len), (params), (dst))
#endif

int oshash(const uint8_t header[80], uint8_t out[32])
{
    static const yespower_params_t params = {
        YESPOWER_1_0, 2048, 8, (const uint8_t *)OSHASH_PERS, sizeof(OSHASH_PERS) - 1
    };
    uint8_t buf[112];
    uint8_t fin[64];
    yespower_binary_t y;

#ifdef OSHASH_TEST_FAIL
    if (getenv("OSHASH_TEST_FAIL")) return -1;
#endif
    oshash_sha256d(header, 80, buf);          /* h1 = SHA-256d(header) */
    memcpy(buf + 32, header, 80);             /* yespower input: h1 || header */
    if (OSHASH_YESPOWER_CALL(buf, sizeof buf, &params, &y))
        return -1;
    memcpy(fin, &y, 32);                      /* finalizer input: y || h1 */
    memcpy(fin + 32, buf, 32);
    oshash_sha3_256(fin, sizeof fin, out);
    return 0;
}
