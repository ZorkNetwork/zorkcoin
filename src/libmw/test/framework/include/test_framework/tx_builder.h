
#ifndef BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_TX_BUILDER_H
#define BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_TX_BUILDER_H
#include <test_framework/models/tx.h>

#include <mw/crypto/blinds.h>
#include <mw/crypto/bulletproofs.h>
#include <mw/models/wallet/stealth_address.h>

TEST_NAMESPACE

//
// Builds transactions for use with automated tests using random blinding factors.
// To make the transaction valid, TxBuilder keeps track of all blinding factors used,
// and adjusts the tx offset to make a valid transaction.
//
class TxBuilder
{
public:
    TxBuilder();

    TxBuilder& AddInput(const TxOutput& input);
    TxBuilder& AddInput(CAmount amount);
    TxBuilder& AddInput(
        CAmount amount,
        const SecretKey& privkey,
        const BlindingFactor& blind,
        const mw::Hash& output_id
    );

    TxBuilder& AddOutput(CAmount amount);
    TxBuilder& AddOutput(
        CAmount amount,
        const SecretKey& sender_privkey,
        const StealthAddress& receiver_addr
    );
    TxBuilder& AddOutput(
        CAmount amount,
        const SecretKey& sender_privkey,
        const SecretKey& receiver_scan_key,
        const SecretKey& receiver_spend_key
    );

    TxBuilder& AddPlainKernel(CAmount fee, bool add_stealth_excess = false, const std::optional<int32_t>& lock_height = std::nullopt);
    TxBuilder& AddPeginKernel(CAmount amount, const std::optional<CAmount>& fee = std::nullopt, bool add_stealth_excess = false, const std::optional<int32_t>& lock_height = std::nullopt);
    TxBuilder& AddPegoutKernel(CAmount amount, CAmount fee, bool add_stealth_excess = false);
    TxBuilder& AddPegoutKernel(const std::vector<PegOutCoin>& pegouts, CAmount fee, bool add_stealth_excess = false);

    Tx Build();

private:
    CAmount m_amount{ 0 };
    Blinds m_kernelOffset;
    Blinds m_stealthOffset;

    std::vector<Input> m_inputs;
    std::vector<TxOutput> m_outputs;
    std::vector<Kernel> m_kernels;
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_TX_BUILDER_H
