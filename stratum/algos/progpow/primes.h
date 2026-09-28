/* Imported from Ravencoin src/crypto/ethash (commit 6d48ae0175b10283248146ae3080e2ba70966739),
 * a copy of chfast/ethash, Apache License 2.0. Only the include paths were changed. */
/* ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
 * Copyright 2018-2019 Pawel Bylica.
 * Licensed under the Apache License, Version 2.0.
 */

#pragma once

#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Finds the largest prime number not greater than the provided upper bound.
 *
 * @param upper_bound  The upper bound. SHOULD be greater than 1.
 * @return  The largest prime number `p` such `p <= upper_bound`.
 *          In case `upper_bound <= 1`, returns 0.
 */
int ethash_find_largest_prime(int upper_bound) NOEXCEPT;

#ifdef __cplusplus
}
#endif
