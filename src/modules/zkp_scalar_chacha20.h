/***********************************************************************
 * Chacha20 scalar generation for ZKP modules (from litecoin secp256k1-zkp).
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ZKP_SCALAR_CHACHA20_H
#define SECP256K1_MODULE_ZKP_SCALAR_CHACHA20_H

#include "../scalar.h"
#include "../util.h"

#define ZKP_ROTL32(x,n) ((x) << (n) | (x) >> (32-(n)))
#define ZKP_QUARTERROUND(a,b,c,d) \
  a += b; d = ZKP_ROTL32(d ^ a, 16); \
  c += d; b = ZKP_ROTL32(b ^ c, 12); \
  a += b; d = ZKP_ROTL32(d ^ a, 8); \
  c += d; b = ZKP_ROTL32(b ^ c, 7);

/* Read a 32-bit unsigned integer from 4 bytes in little-endian order. */
static SECP256K1_INLINE uint32_t secp256k1_zkp_read_le32(const unsigned char *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Convert a 32-bit ChaCha20 state word (whose 4 keystream bytes are serialized
 * in little-endian order: [x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, x >> 24])
 * into the corresponding 32-bit big-endian integer value for scalar limbs.
 * Because secp256k1_scalar limbs store mathematical values in host-native integers,
 * this byte-swap is unconditional on both little-endian and big-endian hosts. */
#define ZKP_BSWAP32(p) ((((p) & 0xFFU) << 24) | (((p) & 0xFF00U) << 8) | (((p) & 0xFF0000U) >> 8) | (((p) & 0xFF000000U) >> 24))

#if defined(EXHAUSTIVE_TEST_ORDER)
static void secp256k1_scalar_chacha20(secp256k1_scalar *r1, secp256k1_scalar *r2, const unsigned char *seed, uint64_t idx) {
    (void)seed;
    secp256k1_scalar_set_int(r1, (int)(idx % EXHAUSTIVE_TEST_ORDER));
    secp256k1_scalar_set_int(r2, (int)((idx + 1) % EXHAUSTIVE_TEST_ORDER));
}
#elif defined(SECP256K1_WIDEMUL_INT128)

static void secp256k1_scalar_chacha20(secp256k1_scalar *r1, secp256k1_scalar *r2, const unsigned char *seed, uint64_t idx) {
    size_t n;
    size_t over_count = 0;
    uint32_t seed32[8];
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    int over1, over2;

    for (n = 0; n < 8; n++) {
        seed32[n] = secp256k1_zkp_read_le32(seed + 4 * n);
    }
    do {
        x0 = 0x61707865;
        x1 = 0x3320646e;
        x2 = 0x79622d32;
        x3 = 0x6b206574;
        x4 = seed32[0];
        x5 = seed32[1];
        x6 = seed32[2];
        x7 = seed32[3];
        x8 = seed32[4];
        x9 = seed32[5];
        x10 = seed32[6];
        x11 = seed32[7];
        x12 = (uint32_t)idx;
        x13 = (uint32_t)(idx >> 32);
        x14 = 0;
        x15 = (uint32_t)over_count;

        n = 10;
        while (n--) {
            ZKP_QUARTERROUND(x0, x4, x8,x12)
            ZKP_QUARTERROUND(x1, x5, x9,x13)
            ZKP_QUARTERROUND(x2, x6,x10,x14)
            ZKP_QUARTERROUND(x3, x7,x11,x15)
            ZKP_QUARTERROUND(x0, x5,x10,x15)
            ZKP_QUARTERROUND(x1, x6,x11,x12)
            ZKP_QUARTERROUND(x2, x7, x8,x13)
            ZKP_QUARTERROUND(x3, x4, x9,x14)
        }

        x0 += 0x61707865;
        x1 += 0x3320646e;
        x2 += 0x79622d32;
        x3 += 0x6b206574;
        x4 += seed32[0];
        x5 += seed32[1];
        x6 += seed32[2];
        x7 += seed32[3];
        x8 += seed32[4];
        x9 += seed32[5];
        x10 += seed32[6];
        x11 += seed32[7];
        x12 += (uint32_t)idx;
        x13 += (uint32_t)(idx >> 32);
        x14 += 0;
        x15 += (uint32_t)over_count;

        r1->d[3] = ((uint64_t)ZKP_BSWAP32(x0) << 32) | (uint64_t)ZKP_BSWAP32(x1);
        r1->d[2] = ((uint64_t)ZKP_BSWAP32(x2) << 32) | (uint64_t)ZKP_BSWAP32(x3);
        r1->d[1] = ((uint64_t)ZKP_BSWAP32(x4) << 32) | (uint64_t)ZKP_BSWAP32(x5);
        r1->d[0] = ((uint64_t)ZKP_BSWAP32(x6) << 32) | (uint64_t)ZKP_BSWAP32(x7);
        r2->d[3] = ((uint64_t)ZKP_BSWAP32(x8) << 32) | (uint64_t)ZKP_BSWAP32(x9);
        r2->d[2] = ((uint64_t)ZKP_BSWAP32(x10) << 32) | (uint64_t)ZKP_BSWAP32(x11);
        r2->d[1] = ((uint64_t)ZKP_BSWAP32(x12) << 32) | (uint64_t)ZKP_BSWAP32(x13);
        r2->d[0] = ((uint64_t)ZKP_BSWAP32(x14) << 32) | (uint64_t)ZKP_BSWAP32(x15);

        over1 = secp256k1_scalar_check_overflow(r1);
        over2 = secp256k1_scalar_check_overflow(r2);
        over_count++;
   } while (over1 | over2);
}

#elif defined(SECP256K1_WIDEMUL_INT64)

static void secp256k1_scalar_chacha20(secp256k1_scalar *r1, secp256k1_scalar *r2, const unsigned char *seed, uint64_t idx) {
    size_t n;
    size_t over_count = 0;
    uint32_t seed32[8];
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    int over1, over2;

    for (n = 0; n < 8; n++) {
        seed32[n] = secp256k1_zkp_read_le32(seed + 4 * n);
    }
    do {
        x0 = 0x61707865;
        x1 = 0x3320646e;
        x2 = 0x79622d32;
        x3 = 0x6b206574;
        x4 = seed32[0];
        x5 = seed32[1];
        x6 = seed32[2];
        x7 = seed32[3];
        x8 = seed32[4];
        x9 = seed32[5];
        x10 = seed32[6];
        x11 = seed32[7];
        x12 = (uint32_t)idx;
        x13 = (uint32_t)(idx >> 32);
        x14 = 0;
        x15 = (uint32_t)over_count;

        n = 10;
        while (n--) {
            ZKP_QUARTERROUND(x0, x4, x8,x12)
            ZKP_QUARTERROUND(x1, x5, x9,x13)
            ZKP_QUARTERROUND(x2, x6,x10,x14)
            ZKP_QUARTERROUND(x3, x7,x11,x15)
            ZKP_QUARTERROUND(x0, x5,x10,x15)
            ZKP_QUARTERROUND(x1, x6,x11,x12)
            ZKP_QUARTERROUND(x2, x7, x8,x13)
            ZKP_QUARTERROUND(x3, x4, x9,x14)
        }

        x0 += 0x61707865;
        x1 += 0x3320646e;
        x2 += 0x79622d32;
        x3 += 0x6b206574;
        x4 += seed32[0];
        x5 += seed32[1];
        x6 += seed32[2];
        x7 += seed32[3];
        x8 += seed32[4];
        x9 += seed32[5];
        x10 += seed32[6];
        x11 += seed32[7];
        x12 += (uint32_t)idx;
        x13 += (uint32_t)(idx >> 32);
        x14 += 0;
        x15 += (uint32_t)over_count;

        r1->d[7] = ZKP_BSWAP32(x0);
        r1->d[6] = ZKP_BSWAP32(x1);
        r1->d[5] = ZKP_BSWAP32(x2);
        r1->d[4] = ZKP_BSWAP32(x3);
        r1->d[3] = ZKP_BSWAP32(x4);
        r1->d[2] = ZKP_BSWAP32(x5);
        r1->d[1] = ZKP_BSWAP32(x6);
        r1->d[0] = ZKP_BSWAP32(x7);
        r2->d[7] = ZKP_BSWAP32(x8);
        r2->d[6] = ZKP_BSWAP32(x9);
        r2->d[5] = ZKP_BSWAP32(x10);
        r2->d[4] = ZKP_BSWAP32(x11);
        r2->d[3] = ZKP_BSWAP32(x12);
        r2->d[2] = ZKP_BSWAP32(x13);
        r2->d[1] = ZKP_BSWAP32(x14);
        r2->d[0] = ZKP_BSWAP32(x15);

        over1 = secp256k1_scalar_check_overflow(r1);
        over2 = secp256k1_scalar_check_overflow(r2);
        over_count++;
   } while (over1 | over2);
}

#endif

#endif /* SECP256K1_MODULE_ZKP_SCALAR_CHACHA20_H */
