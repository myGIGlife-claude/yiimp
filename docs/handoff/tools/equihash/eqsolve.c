/* Small generic Equihash solver (Wagner's algorithm), for regtest parameters (48,5 / 96,5)
 * and slow tests of larger ones. Test tool, not part of yiimp.
 * int eq_solve(n, k, pers, input, inlen, out, max): writes up to max solutions (minimal
 * encoding, no compact size) to out, returns their count. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "blake2.h"

typedef struct { uint32_t ch[16]; uint32_t *idx; } row_t;
static int cur_r;
static int cmp_row(const void *a, const void *b) {
	uint32_t x = ((const row_t *) a)->ch[cur_r], y = ((const row_t *) b)->ch[cur_r];
	return x < y ? -1 : x > y;
}
static uint32_t get_bits(const unsigned char *p, size_t pos, unsigned len) {
	uint64_t v = 0; size_t byte = pos / 8; unsigned skip = pos % 8, need = (skip + len + 7) / 8;
	for (unsigned i = 0; i < need; i++) v = (v << 8) | p[byte + i];
	v >>= need * 8 - skip - len;
	return (uint32_t) (v & ((1ULL << len) - 1));
}
static int distinct(const uint32_t *a, const uint32_t *b, int n) {
	for (int i = 0; i < n; i++) for (int j = 0; j < n; j++) if (a[i] == b[j]) return 0;
	return 1;
}

int eq_solve(unsigned n, unsigned k, const char *pers, const unsigned char *input, size_t inlen,
	unsigned char *out, int max)
{
	unsigned c = n / (k + 1), words = k + 1, per_hash = 512 / n, out_len = per_hash * n / 8;
	size_t nleaves = (size_t) 1 << (c + 1);
	blake2b_state base; blake2b_param P; memset(&P, 0, sizeof(P));
	P.digest_length = out_len; P.fanout = 1; P.depth = 1; memcpy(P.personal, pers, 8);
	memcpy(P.personal + 8, &n, 4); memcpy(P.personal + 12, &k, 4);
	blake2b_init_param(&base, &P); blake2b_update(&base, input, inlen);

	size_t cap = nleaves * 2, nrows = nleaves;
	row_t *rows = calloc(cap, sizeof(row_t));
	uint32_t *pool = malloc(sizeof(uint32_t) * nleaves);
	for (size_t g = 0; g < (nleaves + per_hash - 1) / per_hash; g++) {
		unsigned char h[64]; blake2b_state s = base; uint32_t le = (uint32_t) g;
		blake2b_update(&s, &le, 4); blake2b_final(&s, h, out_len);
		for (unsigned j = 0; j < per_hash && g * per_hash + j < nleaves; j++) {
			size_t i = g * per_hash + j;
			for (unsigned w = 0; w < words; w++) rows[i].ch[w] = get_bits(h + j * n / 8, (size_t) w * c, c);
			pool[i] = (uint32_t) i; rows[i].idx = &pool[i];
		}
	}
	int found = 0;
	size_t sol_size = ((size_t) 1 << k) * (c + 1) / 8;
	for (unsigned r = 0; r < k; r++) {
		int sz = 1 << r;
		cur_r = r; qsort(rows, nrows, sizeof(row_t), cmp_row);
		row_t *next = calloc(cap, sizeof(row_t)); size_t nn = 0;
		uint32_t *npool = malloc(sizeof(uint32_t) * cap * 2 * sz); size_t np = 0;
		for (size_t i = 0; i < nrows; ) {
			size_t j = i; while (j < nrows && rows[j].ch[r] == rows[i].ch[r]) j++;
			for (size_t a = i; a < j && a < i + 16; a++) for (size_t b = a + 1; b < j && b < i + 16; b++) {
				row_t *A = &rows[a], *B = &rows[b];
				if (r == k - 1 && A->ch[k] != B->ch[k]) continue;
				if (!distinct(A->idx, B->idx, sz)) continue;
				if (A->idx[0] > B->idx[0]) { row_t *t = A; A = B; B = t; }
				if (r == k - 1) {
					if (found >= max) continue;
					unsigned char *o = out + found * sol_size; memset(o, 0, sol_size);
					for (int q = 0; q < 2 * sz; q++) {
						uint32_t v = q < sz ? A->idx[q] : B->idx[q - sz];
						for (unsigned bit = 0; bit < c + 1; bit++)
							if (v & (1u << (c - bit))) { size_t pos = (size_t) q * (c + 1) + bit; o[pos / 8] |= 0x80 >> (pos % 8); }
					}
					found++;
					continue;
				}
				if (nn >= cap || np + 2 * sz > cap * 2 * (size_t) sz) continue;
				row_t *N = &next[nn++];
				for (unsigned w = r + 1; w < words; w++) N->ch[w] = A->ch[w] ^ B->ch[w];
				N->idx = &npool[np]; memcpy(N->idx, A->idx, 4 * sz); memcpy(N->idx + sz, B->idx, 4 * sz); np += 2 * sz;
			}
			i = j;
		}
		free(rows); free(pool); pool = npool; rows = next; nrows = nn;
		if (r == k - 1) break;
	}
	free(rows); free(pool);
	return found;
}
void clear_internal_memory(void *v, size_t n) { memset(v, 0, n); }
