
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_PEDERSEN_H
#define BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_PEDERSEN_H
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/commitment.h>

#include <cstdint>
#include <vector>

class Pedersen
{
public:
    //
    // Creates a pedersen commitment from a value with a zero blinding factor.
    //
    static Commitment CommitTransparent(uint64_t value);

    //
    // Creates a pedersen commitment from a value with the supplied blinding factor.
    //
    static Commitment Commit(
        uint64_t value,
        const BlindingFactor& blindingFactor
    );

    //
    // Adds the homomorphic pedersen commitments together.
    //
    static Commitment AddCommitments(
        const std::vector<Commitment>& positive,
        const std::vector<Commitment>& negative = {}
    );

    //
    // Adds blinding factors together (first negating those in the "negative" vector)
    //
    static BlindingFactor AddBlindingFactors(
        const std::vector<BlindingFactor>& positive,
        const std::vector<BlindingFactor>& negative = { }
    );

    //
    // Calculates the blinding factor x' = x + SHA256(xG+vH | xJ), used in the switch commitment x'G+vH.
    //
    static BlindingFactor BlindSwitch(
        const BlindingFactor& secretKey,
        uint64_t amount
    );

private:
    static Commitment PedersenCommitSum(
        const std::vector<Commitment>& positive,
        const std::vector<Commitment>& negative);

    static BlindingFactor PedersenBlindSum(
        const std::vector<BlindingFactor>& positive,
        const std::vector<BlindingFactor>& negative);
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_PEDERSEN_H
