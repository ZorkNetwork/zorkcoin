#include <mw/models/crypto/commitment.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/crypto/pedersen.h>
#include <consensus/amount.h>
#include <random.h>

Commitment Commitment::Random()
{
    return Commitment::Blinded(BlindingFactor::Random(), FastRandomContext{}.randrange<CAmount>(MAX_MONEY));
}

Commitment Commitment::Switch(const BlindingFactor& blind, const uint64_t value)
{
    return Pedersen::Commit(value, Pedersen::BlindSwitch(blind, value));
}

Commitment Commitment::Blinded(const BlindingFactor& blind, const uint64_t value)
{
    return Pedersen::Commit(value, blind);
}

Commitment Commitment::Transparent(const uint64_t value)
{
    return Pedersen::CommitTransparent(value);
}
