#include <crypto/kheavyhash.h>
#include <crypto/sha3.h>
#include <crypto/xoshiro256pp.h>

#include <span.h>

#include <stdint.h>
#include <math.h>
#include <string.h>

static bool IsFullRank(const uint16_t matrix[64][64]);

KHeavyHash::KHeavyHash(uint256 matrix_seed) {
    // kHeavyHash setup -> Get the cSHAKE ready
    // cSHAKE256( "HeavyHash" || whatever is later written )
    uint8_t tmpBuffer[136] = {0};
    tmpBuffer[0] = 1;
    tmpBuffer[1] = 136;
    tmpBuffer[2] = 1;
    tmpBuffer[3] = 0;
    tmpBuffer[4] = 1;
    tmpBuffer[5] = 120;
    strncpy((char*)tmpBuffer+6, powHashStr, 15);
    hasher.Write(tmpBuffer);

    // kHeavyHash setup -> Get the matrix ready
    // these two setup steps could be done in parallel
    // in fact all of the cSHAKE writes could be done in parallel with below
    XoShiRo256PlusPlus generator(matrix_seed);
    do {
        for (int i = 0; i < 64; ++i) {
            for (int j = 0; j < 64; j += 16) {
                uint64_t value = generator();
                for (int shift = 0; shift < 16; ++shift) {
                    matrix[i][j + shift] =  (value >> (4 * shift)) & 0xF;
                }
            }
        }
    } while (!IsFullRank(matrix));
}

KHeavyHash& KHeavyHash::Write(Span<const unsigned char> data) {
    hasher.Write(data);
    return *this;
}

KHeavyHash& KHeavyHash::Finalize(Span<unsigned char> output) {
    uint8_t hash_first[32];
    uint8_t hash_second[32];
    uint8_t hash_xored[32];

    uint16_t vector[64];
    uint16_t product[64];

    hasher.Finalize(hash_first, 0x04);

    for (int i = 0; i < 32; ++i) {
        vector[2*i] = (hash_first[i] >> 4);
        vector[2*i+1] = hash_first[i] & 0xF;
    }

    for (int i = 0; i < 64; ++i) {
        uint16_t sum = 0;
        for (int j = 0; j < 64; ++j) {
            sum += matrix[i][j] * vector[j];
        }
        product[i] = (sum >> 10);
    }

    for (int i = 0; i < 32; ++i) {
        hash_second[i] = (product[2*i] << 4) | (product[2*i+1]);
    }

    for (int i = 0; i < 32; ++i) {
        hash_xored[i] = hash_first[i] ^ hash_second[i];
    }

    // kHeavyHash Result = CSHAKE256( "HeavyHash" || hash_xored )
    hasher.Reset();
    uint8_t tmpBuffer[136] = {0};
    tmpBuffer[0] = 1;
    tmpBuffer[1] = 136;
    tmpBuffer[2] = 1;
    tmpBuffer[3] = 0;
    tmpBuffer[4] = 1;
    tmpBuffer[5] = 72;
    strncpy((char*)tmpBuffer+6, hashStr, 15);
    hasher.Write(tmpBuffer);
    hasher.Write(hash_xored);
    hasher.Finalize(output, 0x04);
    return *this;
}

KHeavyHash& KHeavyHash::Reset(uint256 matrix_seed) {
    *this = KHeavyHash(matrix_seed);
    return *this;
}

#define EPS 1e-9

static bool IsFullRank(const uint16_t A[64][64]) {
    double B[64][64];
    for (int i = 0; i < 64; ++i){
        for(int j = 0; j < 64; ++j){
            B[i][j] = A[i][j];
        }
    }

    int rank = 0;
    bool row_selected[64] = {};

    for (int i = 0; i < 64; ++i) {
        int j;
        for (j = 0; j < 64; ++j) {
            if (!row_selected[j] && fabs(B[j][i]) > EPS)
                break;
        }
        if (j != 64) {
            ++rank;
            row_selected[j] = true;
            for (int p = i + 1; p < 64; ++p)
                B[j][p] /= B[j][i];
            for (int k = 0; k < 64; ++k) {
                if (k != j && fabs(B[k][i]) > EPS) {
                    for (int p = i + 1; p < 64; ++p)
                        B[k][p] -= B[j][p] * B[k][i];
                }
            }
        }
    }
    return rank == 64;
}
