/* Compact reference SHA-256 (FIPS 180-4) and SHA3-256 (FIPS 202). Not performance critical:
 * yespower dominates OSHash-Y cost by >1000x. */
#include "oshash_prims.h"
#include <string.h>

static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t s[8], const uint8_t b[64])
{
    uint32_t w[64], a, bb, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4*i] << 24 | (uint32_t)b[4*i+1] << 16 | (uint32_t)b[4*i+2] << 8 | b[4*i+3];
    for (i = 16; i < 64; i++)
        w[i] = (ROR32(w[i-2],17) ^ ROR32(w[i-2],19) ^ (w[i-2] >> 10)) + w[i-7] +
               (ROR32(w[i-15],7) ^ ROR32(w[i-15],18) ^ (w[i-15] >> 3)) + w[i-16];
    a = s[0]; bb = s[1]; c = s[2]; d = s[3]; e = s[4]; f = s[5]; g = s[6]; h = s[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22)) + ((a & bb) ^ (a & c) ^ (bb & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    s[0] += a; s[1] += bb; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

void oshash_sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint32_t s[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t buf[128];
    size_t rem = len, i, pad;
    uint64_t bits = (uint64_t)len * 8;
    while (rem >= 64) { sha256_block(s, in); in += 64; rem -= 64; }
    memcpy(buf, in, rem);
    buf[rem] = 0x80;
    pad = (rem < 56) ? 64 : 128;
    memset(buf + rem + 1, 0, pad - rem - 1);
    for (i = 0; i < 8; i++) buf[pad - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha256_block(s, buf);
    if (pad == 128) sha256_block(s, buf + 64);
    for (i = 0; i < 8; i++) {
        out[4*i] = (uint8_t)(s[i] >> 24); out[4*i+1] = (uint8_t)(s[i] >> 16);
        out[4*i+2] = (uint8_t)(s[i] >> 8); out[4*i+3] = (uint8_t)s[i];
    }
}

void oshash_sha256d(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint8_t t[32];
    oshash_sha256(in, len, t);
    oshash_sha256(t, 32, out);
}

static const uint64_t RC[24] = {
0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int ROTC[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int PILN[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
#define ROL64(x,n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccakf(uint64_t st[25])
{
    uint64_t t, bc[5];
    int i, j, r;
    for (r = 0; r < 24; r++) {
        for (i = 0; i < 5; i++) bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (i = 0; i < 5; i++) {
            t = bc[(i+4) % 5] ^ ROL64(bc[(i+1) % 5], 1);
            for (j = 0; j < 25; j += 5) st[j+i] ^= t;
        }
        t = st[1];
        for (i = 0; i < 24; i++) { j = PILN[i]; bc[0] = st[j]; st[j] = ROL64(t, ROTC[i]); t = bc[0]; }
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) bc[i] = st[j+i];
            for (i = 0; i < 5; i++) st[j+i] ^= (~bc[(i+1) % 5]) & bc[(i+2) % 5];
        }
        st[0] ^= RC[r];
    }
}

static void absorb(uint64_t st[25], const uint8_t blk[136])
{
    for (int i = 0; i < 17; i++) {
        uint64_t v = 0;
        for (int k = 7; k >= 0; k--) v = (v << 8) | blk[8*i + k];
        st[i] ^= v;
    }
    keccakf(st);
}

void oshash_sha3_256(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint64_t st[25];
    uint8_t blk[136];
    memset(st, 0, sizeof st);
    while (len >= 136) { absorb(st, in); in += 136; len -= 136; }
    memset(blk, 0, sizeof blk);
    memcpy(blk, in, len);
    blk[len] ^= 0x06;
    blk[135] ^= 0x80;
    absorb(st, blk);
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(st[i / 8] >> (8 * (i % 8)));
}

#ifdef OSHASH_PRIMS_SELFTEST
#include <stdio.h>
static int eq(const uint8_t *h, const char *hex)
{
    char s[65];
    for (int i = 0; i < 32; i++) sprintf(s + 2*i, "%02x", h[i]);
    if (strcmp(s, hex)) { printf("FAIL %s != %s\n", s, hex); return 1; }
    return 0;
}
int main(void)
{
    uint8_t h[32], a[200];
    int bad = 0;
    memset(a, 'a', sizeof a);
    oshash_sha3_256(a, 0, h);   bad |= eq(h, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    oshash_sha3_256((const uint8_t *)"abc", 3, h); bad |= eq(h, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    oshash_sha3_256(a, 136, h); bad |= eq(h, "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1");
    oshash_sha3_256(a, 200, h); bad |= eq(h, "cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387");
    oshash_sha256((const uint8_t *)"abc", 3, h);   bad |= eq(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    oshash_sha256(a, 64, h);    bad |= eq(h, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    oshash_sha256(a, 120, h);   bad |= eq(h, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c");
    oshash_sha256d((const uint8_t *)"abc", 3, h);  bad |= eq(h, "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358");
    puts(bad ? "PRIMS-FAIL" : "PRIMS-OK");
    return bad;
}
#endif
