
#ifndef BITCOIN_LIBMW_INCLUDE_MW_WALLET_TX_BUILDER_H
#define BITCOIN_LIBMW_INCLUDE_MW_WALLET_TX_BUILDER_H
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/transaction.h>
#include <mw/models/tx/peg_in_coin.h>
#include <mw/models/tx/peg_out_coin.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/recipient.h>

class TxBuilder
{
    struct Inputs
    {
        BlindingFactor total_blind;
        SecretKey total_key;
        std::vector<Input> inputs;
    };

    struct Outputs
    {
        BlindingFactor total_blind;
        SecretKey total_key;
        std::vector<Output> outputs;
        std::vector<mw::Coin> coins;
    };

public:
    static mw::Transaction::CPtr BuildTx(
        const std::vector<mw::Coin>& input_coins,
        const std::vector<mw::Recipient>& recipients,
        const std::vector<PegOutCoin>& pegouts,
        const std::optional<CAmount>& pegin_amount,
        CAmount fee,
        std::vector<mw::Coin>& output_coins
    );

private:
    static Inputs CreateInputs(const std::vector<mw::Coin>& input_coins);
    static Outputs CreateOutputs(const std::vector<mw::Recipient>& recipients);
    static CAmount TotalAmount(const std::vector<mw::Coin>& coins);
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_WALLET_TX_BUILDER_H
