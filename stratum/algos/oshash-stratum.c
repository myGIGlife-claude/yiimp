#include "oshash.h"
#include "oshash-stratum.h"
#include <stdint.h>
/* YIIMP algo entry: input is the 80-byte header as stratum builds it (same layout yespower uses). */
void oshash_hash(const char *input, char *output, uint32_t len)
{
    (void)len;
    if (oshash((const uint8_t *)input, (uint8_t *)output) != 0) {
        for (int i = 0; i < 32; i++) output[i] = (char)0xff;   /* never a valid share */
    }
}
