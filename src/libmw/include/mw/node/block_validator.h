
#ifndef BITCOIN_LIBMW_INCLUDE_MW_NODE_BLOCK_VALIDATOR_H
#define BITCOIN_LIBMW_INCLUDE_MW_NODE_BLOCK_VALIDATOR_H
#include <mw/models/block/block.h>

class BlockValidator
{
public:
    BlockValidator() = default;

    static bool ValidateBlock(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegInCoin>& pegInCoins,
        const std::vector<PegOutCoin>& pegOutCoins,
        int32_t kernel_lock_height_grandfather = 0
    ) noexcept;

private:
    static void ValidatePegInCoins(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegInCoin>& pegInCoins
    );

    static void ValidatePegOutCoins(
        const mw::Block::CPtr& pBlock,
        const std::vector<PegOutCoin>& pegOutCoins
    );
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_NODE_BLOCK_VALIDATOR_H
