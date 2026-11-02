
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_PROOF_DATA_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_PROOF_DATA_H
#include <mw/models/crypto/commitment.h>
#include <mw/models/crypto/range_proof.h>
#include <cassert>

struct ProofData
{
    Commitment commitment;
    RangeProof::CPtr pRangeProof;
    std::vector<uint8_t> extraData;

    inline bool operator==(const ProofData& rhs) const noexcept
    {
        assert(rhs.pRangeProof != nullptr);

        return commitment == rhs.commitment
            && *pRangeProof == *rhs.pRangeProof
            && extraData == rhs.extraData;
    }

    inline bool operator!=(const ProofData& rhs) const noexcept { return !(rhs == *this); }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_PROOF_DATA_H
