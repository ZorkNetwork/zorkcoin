
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CONSENSUS_STEALTH_SUM_VALIDATOR_H
#define BITCOIN_LIBMW_INCLUDE_MW_CONSENSUS_STEALTH_SUM_VALIDATOR_H
#include <mw/crypto/public_keys.h>
#include <mw/exceptions/validation_exception.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/public_key.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/tx_body.h>

#include <algorithm>
#include <iterator>
#include <optional>
#include <vector>

class StealthSumValidator
{
public:
    struct SumState
    {
        std::optional<PublicKey> lhs;
        std::optional<PublicKey> rhs;
    };

    //
    // Verifies that stealth excesses balance:
    //
    // sum(K_s) + sum(K_i) - sum(K_o) = sum(E') + x'*G
    //
    static void Validate(const BlindingFactor& stealth_offset, const TxBody& body)
    {
        ValidateAndAdd(stealth_offset, body, SumState{});
    }

    // Extends the sums of an already-valid transaction aggregate without
    // rebuilding the full aggregate body.
    static SumState ValidateAndAdd(
        const BlindingFactor& stealth_offset,
        const TxBody& body,
        const SumState& previous)
    {
        std::vector<PublicKey> lhs_keys;

        if (previous.lhs) {
            lhs_keys.push_back(*previous.lhs);
        }

        //
        // sum(K_s) + sum(K_i)
        //
        std::transform(
            body.GetOutputs().cbegin(), body.GetOutputs().cend(), std::back_inserter(lhs_keys),
            [](const Output& output) { return output.GetSenderPubKey(); }
        );

        for (const Input& input : body.GetInputs()) {
            if (!!input.GetInputPubKey()) {
                lhs_keys.push_back(*input.GetInputPubKey());
            }
        }

        const std::optional<PublicKey> lhs_total = AddKeys(lhs_keys);

        //
        // sum(E') + x'*G + sum(K_o)
        //
        std::vector<PublicKey> rhs_keys = body.GetStealthExcesses();

        if (previous.rhs) {
            rhs_keys.push_back(*previous.rhs);
        }

        std::transform(
            body.GetInputs().cbegin(), body.GetInputs().cend(), std::back_inserter(rhs_keys),
            [](const Input& input) { return input.GetOutputPubKey(); }
        );


        if (!stealth_offset.IsZero()) {
            rhs_keys.push_back(PublicKeys::Calculate(stealth_offset.GetBigInt()));
        }

        const std::optional<PublicKey> rhs_total = AddKeys(rhs_keys);

        // sum(K_s) + sum(K_i) = sum(E') + x'*G + sum(K_o)
        if (lhs_total != rhs_total) {
            ThrowValidation(EConsensusError::STEALTH_SUMS);
        }

        return SumState{lhs_total, rhs_total};
    }

private:
    static std::optional<PublicKey> AddKeys(const std::vector<PublicKey>& keys)
    {
        if (keys.empty()) {
            return std::nullopt;
        }

        return PublicKeys::Add(keys);
    }
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_CONSENSUS_STEALTH_SUM_VALIDATOR_H
