// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <interfaces/wallet.h>
#include <mweb/mweb_spend.h>
#include <mweb/mweb_transact.h>
#include <mweb/mweb_wallet.h>
#include <mw/consensus/params.h>
#include <mw/consensus/weight.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/crypto/hash.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/tx/tx_body.h>
#include <mw/models/wallet/coin.h>
#include <mw/wallet/keychain.h>
#include <mw/wallet/sign.h>
#include <net.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <test/util/mweb_setup.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <uint256.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/mweb_util.h>
#include <wallet/test/util.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

namespace {

wallet::CRecipient MakeMWEBRecipient(CAmount amount)
{
    // StealthAddress default-constructed is enough for IsMWEB() / weight formulas.
    wallet::CRecipient recipient;
    recipient.dest = StealthAddress{};
    recipient.nAmount = amount;
    recipient.fSubtractFeeFromAmount = false;
    return recipient;
}

util::Result<SecretKey> RandomSenderKey()
{
    return SecretKey::Random();
}

mw::MutableInput OwnedMWEBInput(CAmount amount)
{
    const SecretKey scan = SecretKey::Random();
    const SecretKey spend = SecretKey::Random();
    const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(spend), scan, 0);
    BlindingFactor blind;
    const Output output = Output::Create(&blind, SecretKey::Random(), address, amount);
    const SecretKey shared_secret = mw::RecoverSharedSecret(output.GetKeyExchangePubKey(), scan);
    mw::MutableInput input = mw::MutableInput::FromOutput(output);
    input.amount = amount;
    input.shared_secret = shared_secret;
    input.spend_key = mw::DeriveOutputSpendKey(mw::DeriveSubaddressSpendKey(spend, scan, 0), shared_secret);
    return input;
}

mw::MutableOutput MWEBRecipientOutput(CAmount amount)
{
    mw::MutableOutput output;
    output.amount = amount;
    output.address = StealthAddress::Random();
    return output;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_spend_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mweb_to_mweb_fee_matches_litecoin_formulas)
{
    const CFeeRate feerate{CAmount(1000)}; // 1000 sat/kvB
    const std::vector<wallet::CRecipient> recipients{MakeMWEBRecipient(COIN)};
    const uint64_t mweb_weight = MWEB::CalcMWEBWeight(
        MWEB::TxType::MWEB_TO_MWEB, /*change_on_mweb=*/true, recipients);

    // Litecoin: MWEB_TO_MWEB L1 bytes = 0, so fee_needed == mweb_fee == GetMWEBFee.
    const int32_t l1_vsize = MWEB::EstimateMWEBTxSize(
        MWEB::TxType::MWEB_TO_MWEB, /*signed_l1_vsize=*/60, /*selected_coins=*/{}, recipients);
    BOOST_CHECK_EQUAL(l1_vsize, 0);

    const CAmount fee_needed = MWEB::ComputeFeeNeeded(feerate, l1_vsize, mweb_weight);
    const CAmount mweb_fee = MWEB::ComputeKernelFee(
        feerate, MWEB::TxType::MWEB_TO_MWEB, mweb_weight, recipients);

    BOOST_CHECK_EQUAL(fee_needed, CFeeRate::GetMWEBFee(mweb_weight));
    BOOST_CHECK_EQUAL(mweb_fee, CFeeRate::GetMWEBFee(mweb_weight));
    BOOST_CHECK_EQUAL(fee_needed, mweb_fee);

    // Selection target with change is recipients + kernel fee.
    const MWEB::SelectionTargets targets = MWEB::ComputeSelectionTargets(
        feerate, MWEB::TxType::MWEB_TO_MWEB, COIN, recipients);
    BOOST_CHECK_EQUAL(targets.with_change, COIN + mweb_fee);
}

BOOST_AUTO_TEST_CASE(selection_targets_bound_adjacent_changeless_window)
{
    // doc/mweb/descriptors.md "Selection algorithm": the changeless window
    // [no_change, with_change] and the with-change region are adjacent —
    // separated by exactly one standard output's weight fee.
    const CFeeRate feerate{CAmount(1000)};
    const CAmount change_output_fee = CFeeRate::GetMWEBFee(mw::STANDARD_OUTPUT_WEIGHT);
    BOOST_CHECK_EQUAL(change_output_fee, 1800);

    const std::vector<wallet::CRecipient> mweb_recipients{MakeMWEBRecipient(COIN)};
    const MWEB::SelectionTargets mweb_targets = MWEB::ComputeSelectionTargets(
        feerate, MWEB::TxType::MWEB_TO_MWEB, COIN, mweb_recipients);
    BOOST_CHECK_EQUAL(mweb_targets.with_change - mweb_targets.no_change, change_output_fee);
    BOOST_CHECK_EQUAL(mweb_targets.no_change,
        COIN + CFeeRate::GetMWEBFee(MWEB::CalcMWEBWeight(
            MWEB::TxType::MWEB_TO_MWEB, /*change_on_mweb=*/false, mweb_recipients)));

    // Peg-out targets include the peg-out byte fee on both bounds; the window
    // width is still exactly the change output's weight fee.
    wallet::CRecipient pegout;
    pegout.dest = CTxDestination{PKHash{}};
    pegout.nAmount = COIN;
    pegout.fSubtractFeeFromAmount = false;
    const std::vector<wallet::CRecipient> pegout_recipients{pegout};
    const MWEB::SelectionTargets pegout_targets = MWEB::ComputeSelectionTargets(
        feerate, MWEB::TxType::PEGOUT, COIN, pegout_recipients);
    BOOST_CHECK_EQUAL(pegout_targets.with_change - pegout_targets.no_change, change_output_fee);
    const int64_t pegout_bytes = MWEB::CalcPegOutBytes(MWEB::TxType::PEGOUT, pegout_recipients);
    BOOST_CHECK_EQUAL(pegout_targets.no_change,
        COIN + feerate.GetTotalFee(static_cast<int32_t>(pegout_bytes),
            MWEB::CalcMWEBWeight(MWEB::TxType::PEGOUT, /*change_on_mweb=*/false, pegout_recipients)));
}

BOOST_AUTO_TEST_CASE(pegin_selection_fee_includes_hogex_and_mweb_weight)
{
    const CFeeRate feerate{CAmount(1000)};
    const std::vector<wallet::CRecipient> recipients{MakeMWEBRecipient(COIN)};
    const uint64_t mweb_weight = MWEB::CalcMWEBWeight(
        MWEB::TxType::PEGIN, /*change_on_mweb=*/true, recipients);

    const CAmount selection_fee = MWEB::PegInSelectionFee(feerate, recipients);
    const int32_t hogex_vsize = static_cast<int32_t>(::GetSerializeSize(CTxIn()));
    BOOST_CHECK_EQUAL(selection_fee, feerate.GetTotalFee(hogex_vsize, mweb_weight));
    BOOST_CHECK(selection_fee > CFeeRate::GetMWEBFee(mweb_weight));
}

BOOST_AUTO_TEST_CASE(pegin_estimate_size_adds_hogex_input)
{
    const std::vector<wallet::CRecipient> recipients{MakeMWEBRecipient(COIN)};
    // Simulate one L1 input already reflected in signed_l1_vsize.
    // ContainsPegIn(PEGIN, *) is always true, so HogEx input bytes are added.
    const int32_t signed_l1_vsize = 150;
    const std::set<wallet::CInputCoin> selected;

    const int32_t est = MWEB::EstimateMWEBTxSize(
        MWEB::TxType::PEGIN, signed_l1_vsize, selected, recipients);
    const int32_t hogex_vsize = static_cast<int32_t>(::GetSerializeSize(CTxIn()));
    BOOST_CHECK_EQUAL(est, signed_l1_vsize + hogex_vsize);
}

BOOST_AUTO_TEST_CASE(kernel_fee_pegout_includes_pegout_bytes)
{
    const CFeeRate feerate{CAmount(1000)};
    wallet::CRecipient pegout;
    pegout.dest = CTxDestination{PKHash{}};
    pegout.nAmount = COIN;
    pegout.fSubtractFeeFromAmount = false;
    const std::vector<wallet::CRecipient> recipients{pegout};

    const uint64_t mweb_weight = MWEB::CalcMWEBWeight(
        MWEB::TxType::PEGOUT, /*change_on_mweb=*/true, recipients);
    const int64_t pegout_bytes = MWEB::CalcPegOutBytes(MWEB::TxType::PEGOUT, recipients);
    BOOST_CHECK(pegout_bytes > 0);

    const CAmount mweb_fee = MWEB::ComputeKernelFee(
        feerate, MWEB::TxType::PEGOUT, mweb_weight, recipients);
    BOOST_CHECK_EQUAL(mweb_fee, feerate.GetTotalFee(static_cast<int32_t>(pegout_bytes), mweb_weight));
    BOOST_CHECK(mweb_fee > CFeeRate::GetMWEBFee(mweb_weight));
}

BOOST_AUTO_TEST_CASE(max_num_inputs_fit_p2p_message_budget)
{
    // Wallet selection may use the full consensus input cap (50,000). A
    // max-input *transaction body* must still fit in a v1 p2p message (32 MB).
    // Consensus *blocks* are capped at the Litecoin MWEB envelope
    // (25,800,195); a full L1 + max MWEB combination can exceed the BIP324
    // mine/assembly cap even when the body alone would fit — that is
    // intentional (see doc/mweb/weight.md).
    BOOST_CHECK_EQUAL(MAX_PROTOCOL_MESSAGE_LENGTH, 32 * 1000 * 1000);
    BOOST_CHECK_EQUAL(mw::MAX_NUM_INPUTS, 50'000);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_BIP324, 16'777'214);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB, MAX_BLOCK_SERIALIZED_SIZE + mw::MAX_BLOCK_BYTES);
    BOOST_CHECK(MAX_PROTOCOL_MESSAGE_LENGTH > MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB);

    // Canonical stealth input (no extra_data) serializes to INPUT_BYTES.
    const Input sample(
        /*features=*/0x01, // STEALTH_KEY_FEATURE_BIT
        mw::Hash{},
        Commitment{},
        PublicKey{},
        PublicKey{},
        Signature{});
    BOOST_CHECK_EQUAL(sample.Serialized().size(), mw::INPUT_BYTES);

    // Serialize a TxBody with the full protocol-max input count.
    std::vector<Input> inputs(mw::MAX_NUM_INPUTS, sample);
    BOOST_CHECK_EQUAL(inputs.size(), mw::MAX_NUM_INPUTS);
    const TxBody body(std::move(inputs), {}, {});
    BOOST_CHECK(!Weight::ExceedsMaximum(body));

    const size_t body_bytes = body.Serialized().size();
    // Inputs dominate: ~9.8 MB at the cap — under both the 32 MB message limit
    // and the BIP324 block envelope when L1 is small; still useful coverage of
    // 50k-input selection remaining relay-safe as a transaction body.
    BOOST_CHECK(body_bytes <= mw::MAX_BLOCK_BYTES);
    BOOST_CHECK(body_bytes < MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB);
    BOOST_CHECK(MAX_BLOCK_SERIALIZED_SIZE + body_bytes < MAX_PROTOCOL_MESSAGE_LENGTH);
    BOOST_CHECK(body_bytes >= mw::MAX_NUM_INPUTS * mw::INPUT_BYTES);
}

BOOST_AUTO_TEST_CASE(coin_control_fee_params_include_mweb_weight)
{
    const CFeeRate feerate{CAmount(1000)};
    const std::vector<wallet::CRecipient> recipients{MakeMWEBRecipient(COIN)};
    const uint64_t expected_weight = MWEB::CalcMWEBWeight(
        MWEB::TxType::MWEB_TO_MWEB, /*change_on_mweb=*/true, recipients);

    // MWEB inputs + MWEB payee: L1 vsize 0, positive MWEB weight (with change).
    const MWEB::CoinControlFeeParams mweb_params = MWEB::EstimateCoinControlFeeParams(
        /*has_l1_inputs=*/false,
        /*has_mweb_inputs=*/true,
        recipients,
        CNoDestination{},
        /*signed_l1_vsize=*/250);
    BOOST_CHECK(mweb_params.uses_mweb);
    BOOST_CHECK_EQUAL(mweb_params.l1_vsize, 0);
    BOOST_CHECK_EQUAL(mweb_params.mweb_weight, expected_weight);
    BOOST_CHECK(mweb_params.mweb_weight > 0);

    const CAmount mweb_fee = feerate.GetTotalFee(mweb_params.l1_vsize, mweb_params.mweb_weight);
    BOOST_CHECK_EQUAL(mweb_fee, CFeeRate::GetMWEBFee(expected_weight));

    // Same L1 byte skeleton with mweb_weight=0 underestimates vs real MWEB fee.
    const CAmount naive_l1_only = feerate.GetTotalFee(/*virtual_bytes=*/250, /*mweb_weight=*/0);
    BOOST_CHECK(mweb_fee > naive_l1_only);

    // L1-only selection stays at zero MWEB weight and keeps the L1 vsize.
    wallet::CRecipient l1_rcp;
    l1_rcp.dest = CTxDestination{PKHash{}};
    l1_rcp.nAmount = COIN;
    l1_rcp.fSubtractFeeFromAmount = false;
    const MWEB::CoinControlFeeParams l1_params = MWEB::EstimateCoinControlFeeParams(
        /*has_l1_inputs=*/true,
        /*has_mweb_inputs=*/false,
        {l1_rcp},
        CNoDestination{},
        /*signed_l1_vsize=*/250);
    BOOST_CHECK(!l1_params.uses_mweb);
    BOOST_CHECK_EQUAL(l1_params.mweb_weight, 0);
    BOOST_CHECK_EQUAL(l1_params.l1_vsize, 250);

    // MWEB inputs with no payees yet still budget MWEB_TO_MWEB + change weight.
    const MWEB::CoinControlFeeParams browse_params = MWEB::EstimateCoinControlFeeParams(
        /*has_l1_inputs=*/false,
        /*has_mweb_inputs=*/true,
        /*recipients=*/{},
        CNoDestination{},
        /*signed_l1_vsize=*/100);
    BOOST_CHECK(browse_params.uses_mweb);
    BOOST_CHECK_EQUAL(browse_params.mweb_weight, expected_weight);
    BOOST_CHECK_EQUAL(browse_params.l1_vsize, 0);
}

BOOST_AUTO_TEST_CASE(calc_mweb_weight_counts_all_stealth_recipients)
{
    const std::vector<wallet::CRecipient> two_mweb{
        MakeMWEBRecipient(COIN),
        MakeMWEBRecipient(COIN),
    };
    const uint64_t weight_nc = MWEB::CalcMWEBWeight(
        MWEB::TxType::MWEB_TO_MWEB, /*change_on_mweb=*/false, two_mweb);
    BOOST_CHECK_EQUAL(weight_nc,
        2 * mw::STANDARD_OUTPUT_WEIGHT + mw::KERNEL_WITH_STEALTH_WEIGHT);

    const uint64_t weight_c = MWEB::CalcMWEBWeight(
        MWEB::TxType::MWEB_TO_MWEB, /*change_on_mweb=*/true, two_mweb);
    BOOST_CHECK_EQUAL(weight_c,
        3 * mw::STANDARD_OUTPUT_WEIGHT + mw::KERNEL_WITH_STEALTH_WEIGHT);

    // Single-recipient with-change still matches the historical 3900 sat fee base.
    const std::vector<wallet::CRecipient> one_mweb{MakeMWEBRecipient(COIN)};
    const uint64_t one_c = MWEB::CalcMWEBWeight(
        MWEB::TxType::MWEB_TO_MWEB, /*change_on_mweb=*/true, one_mweb);
    BOOST_CHECK_EQUAL(one_c,
        2 * mw::STANDARD_OUTPUT_WEIGHT + mw::KERNEL_WITH_STEALTH_WEIGHT);
    BOOST_CHECK_EQUAL(CFeeRate::GetMWEBFee(one_c), 3900);
}

BOOST_AUTO_TEST_CASE(pegout_change_costs_kernel_weight_and_hogex_output)
{
    const CFeeRate feerate{CAmount(10000)};
    const std::vector<wallet::CRecipient> recipients{MakeMWEBRecipient(COIN)};
    const CScript change_script = GetScriptForDestination(WitnessV0KeyHash{});
    BOOST_CHECK(MWEB::GetPegoutChangeScript(CNoDestination{}).empty());
    BOOST_CHECK(MWEB::GetPegoutChangeScript(StealthAddress{}).empty());
    BOOST_CHECK(MWEB::GetPegoutChangeScript(WitnessV0KeyHash{}) == change_script);

    // The change peg-out replaces the change output with the weight of its script in the kernel.
    const std::vector<PegOutCoin> change_pegout{PegOutCoin(0, change_script)};
    for (const MWEB::TxType type : {MWEB::TxType::MWEB_TO_MWEB, MWEB::TxType::PEGIN}) {
        BOOST_CHECK_EQUAL(MWEB::CalcMWEBWeight(type, /*change_on_mweb=*/true, recipients, change_script),
            mw::STANDARD_OUTPUT_WEIGHT + Weight::CalcKernelWeight(/*has_stealth_excess=*/true, change_pegout));
        BOOST_CHECK_EQUAL(MWEB::CalcMWEBWeight(type, /*change_on_mweb=*/false, recipients, change_script),
            MWEB::CalcMWEBWeight(type, /*change_on_mweb=*/false, recipients));
    }

    // Its HogEx output is paid by the kernel fee on every path with an MWEB part.
    const int64_t change_vsize = GetVirtualTransactionSize(
        static_cast<int64_t>(::GetSerializeSize(CTxOut(0, change_script))) * WITNESS_SCALE_FACTOR, 0, 0);
    BOOST_CHECK_EQUAL(MWEB::CalcPegOutBytes(MWEB::TxType::MWEB_TO_MWEB, recipients, change_script), change_vsize);
    BOOST_CHECK_EQUAL(MWEB::CalcPegOutBytes(MWEB::TxType::PEGIN, recipients, change_script), change_vsize);
    BOOST_CHECK_EQUAL(MWEB::CalcPegOutBytes(MWEB::TxType::BTC_TO_BTC, recipients, change_script), 0);
    wallet::CRecipient pegout;
    pegout.dest = CTxDestination{PKHash{}};
    pegout.nAmount = COIN;
    const std::vector<wallet::CRecipient> pegout_recipients{pegout};
    BOOST_CHECK_EQUAL(MWEB::CalcPegOutBytes(MWEB::TxType::PEGOUT, pegout_recipients, change_script),
        MWEB::CalcPegOutBytes(MWEB::TxType::PEGOUT, pegout_recipients) + change_vsize);

    const uint64_t weight = MWEB::CalcMWEBWeight(MWEB::TxType::MWEB_TO_MWEB, /*change_on_mweb=*/true, recipients, change_script);
    BOOST_CHECK_EQUAL(MWEB::ComputeKernelFee(feerate, MWEB::TxType::MWEB_TO_MWEB, weight, recipients, change_script),
        feerate.GetTotalFee(static_cast<int32_t>(change_vsize), weight));
    BOOST_CHECK_EQUAL(MWEB::EstimateMWEBTxSize(MWEB::TxType::MWEB_TO_MWEB, /*signed_l1_vsize=*/60, {}, recipients, change_script),
        change_vsize);

    const MWEB::SelectionTargets targets = MWEB::ComputeSelectionTargets(feerate, MWEB::TxType::MWEB_TO_MWEB, COIN, recipients, change_script);
    BOOST_CHECK_EQUAL(targets.no_change, MWEB::ComputeSelectionTargets(feerate, MWEB::TxType::MWEB_TO_MWEB, COIN, recipients).no_change);
    BOOST_CHECK_EQUAL(targets.with_change, COIN + feerate.GetTotalFee(static_cast<int32_t>(change_vsize), weight));

    const int32_t hogex_vsize = static_cast<int32_t>(::GetSerializeSize(CTxIn()));
    BOOST_CHECK_EQUAL(MWEB::PegInSelectionFee(feerate, recipients, change_script),
        feerate.GetTotalFee(hogex_vsize + static_cast<int32_t>(change_vsize),
            MWEB::CalcMWEBWeight(MWEB::TxType::PEGIN, /*change_on_mweb=*/true, recipients, change_script)));

    // Coin control budgets the change peg-out once a transparent change address is set.
    const MWEB::CoinControlFeeParams params = MWEB::EstimateCoinControlFeeParams(
        /*has_l1_inputs=*/true, /*has_mweb_inputs=*/false, recipients, WitnessV0KeyHash{}, /*signed_l1_vsize=*/150);
    BOOST_CHECK_EQUAL(params.mweb_weight, MWEB::CalcMWEBWeight(MWEB::TxType::PEGIN, /*change_on_mweb=*/true, recipients, change_script));
    BOOST_CHECK_EQUAL(params.l1_vsize, 150 + hogex_vsize + change_vsize);
}

BOOST_AUTO_TEST_CASE(built_tx_weight_matches_signed_consensus_weight)
{
    const auto check = [](CMutableTransaction tx) {
        const int32_t estimate = MWEB::EstimateBuiltTxWeight(tx);
        BOOST_REQUIRE(!tx.mweb_tx.IsFinal());
        const auto signed_tx = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
        BOOST_REQUIRE_MESSAGE(signed_tx, util::ErrorString(signed_tx).original);
        const CTransaction final_tx{tx};
        BOOST_REQUIRE(final_tx.HasMWEBTx());
        BOOST_CHECK_EQUAL(estimate, GetTransactionWeight(final_tx));
    };

    CMutableTransaction mweb_to_mweb;
    mweb_to_mweb.mweb_tx.inputs.push_back(OwnedMWEBInput(2'000'000));
    mweb_to_mweb.mweb_tx.outputs.push_back(MWEBRecipientOutput(1'990'000));
    mweb_to_mweb.mweb_tx.SetFee(10'000);
    check(mweb_to_mweb);

    CMutableTransaction pegout;
    pegout.mweb_tx.inputs.push_back(OwnedMWEBInput(2'000'000));
    pegout.mweb_tx.AddPegout(CScript() << OP_1 << std::vector<unsigned char>(32, 0x01), 1'500'000, false);
    pegout.mweb_tx.outputs.push_back(MWEBRecipientOutput(480'000));
    pegout.mweb_tx.SetFee(20'000);
    check(pegout);

    CMutableTransaction l1_output_only{mweb_to_mweb};
    l1_output_only.vout.emplace_back(0, CScript() << OP_RETURN);
    check(l1_output_only);

    CMutableTransaction pegin;
    pegin.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    pegin.vout.emplace_back(1'000'000, GetScriptForPegin(mw::Hash{}));
    pegin.vout.emplace_back(500'000, CScript() << OP_0 << std::vector<unsigned char>(20, 0x02));
    pegin.mweb_tx.outputs.push_back(MWEBRecipientOutput(990'000));
    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    kernel.pegin = 1'000'000;
    pegin.mweb_tx.kernels.push_back(std::move(kernel));
    check(pegin);
}

BOOST_AUTO_TEST_CASE(frozen_output_detection_matches_consensus_list)
{
    const auto regtest = CChainParams::RegTest();
    const auto& frozen_ids = regtest->GetConsensus().frozen_mweb_output_ids;
    BOOST_REQUIRE_EQUAL(frozen_ids.size(), 1U);
    const mw::Hash frozen_id{std::vector<uint8_t>(frozen_ids[0].begin(), frozen_ids[0].end())};
    BOOST_CHECK(frozen_ids[0] == uint256{"2f3a08d9f5ef5f388386c11efe935394b14b524220cff4ec5c81942b82e694f7"});

    BOOST_CHECK(MWEB::IsFrozenOutput(regtest->GetConsensus(), frozen_id));
    BOOST_CHECK(!MWEB::IsFrozenOutput(regtest->GetConsensus(), mw::Hash{}));
    BOOST_CHECK(!MWEB::IsFrozenOutput(CChainParams::Main()->GetConsensus(), frozen_id));
}

BOOST_FIXTURE_TEST_CASE(mixed_mweb_l1_recipients_multi_recipient_gate, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    wallet::CRecipient l1_recipient{PKHash{}, 1 * COIN, /*subtract_fee=*/false};
    wallet::CRecipient mweb_recipient;
    mweb_recipient.dest = StealthAddress{};
    mweb_recipient.nAmount = 1 * COIN;
    mweb_recipient.fSubtractFeeFromAmount = false;
    const std::vector<wallet::CRecipient> recipients{l1_recipient, mweb_recipient};

    auto res = wallet::CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, wallet::CCoinControl{});
#if ENABLE_MWEB_UNCOMMON_SENDS
    // Gate lifted: must not fail with the Litecoin single-recipient string.
    // This fixture has no MWEB coins, so funding still fails for other reasons.
    if (!res) {
        BOOST_CHECK(util::ErrorString(res).original != "Only one MWEB recipient supported at this time");
    }
#else
    BOOST_CHECK(!res);
    BOOST_CHECK_EQUAL(util::ErrorString(res).original, "Only one MWEB recipient supported at this time");
#endif
}

BOOST_FIXTURE_TEST_CASE(mixed_l1_mweb_input_presets_gate, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    wallet::CRecipient mweb_recipient;
    mweb_recipient.dest = StealthAddress{};
    mweb_recipient.nAmount = 1 * COIN;
    mweb_recipient.fSubtractFeeFromAmount = false;

    wallet::CCoinControl cc;
    cc.Select(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    cc.SelectMWEB(mw::Hash{});

    auto res = wallet::CreateTransaction(*wallet, {mweb_recipient}, /*change_pos=*/std::nullopt, cc);
    BOOST_CHECK(!res);
#if ENABLE_MWEB_UNCOMMON_SENDS
    // Dual presets allowed through the gate; funding fails without real coins.
    BOOST_CHECK(util::ErrorString(res).original != "Mixed L1 and MWEB inputs toward an MWEB destination are not enabled");
#else
    BOOST_CHECK_EQUAL(util::ErrorString(res).original,
                      "Mixed L1 and MWEB inputs toward an MWEB destination are not enabled");
#endif
}

BOOST_FIXTURE_TEST_CASE(no_auto_pegin_refuses_silent_l1_funding, TestChain100Setup)
{
    // send RPC sets m_no_auto_pegin: MWEB dest without L1 presets and without
    // enough MWEB must not fall through to a silent L1 peg-in.
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    wallet::CRecipient mweb_recipient;
    mweb_recipient.dest = StealthAddress{};
    mweb_recipient.nAmount = 1 * COIN;
    mweb_recipient.fSubtractFeeFromAmount = false;

    wallet::CCoinControl cc;
    cc.m_no_auto_pegin = true;
    cc.m_allow_other_inputs = true;

    auto res = wallet::CreateTransaction(*wallet, {mweb_recipient}, /*change_pos=*/std::nullopt, cc);
    BOOST_CHECK(!res);
    BOOST_CHECK(util::ErrorString(res).original.find("Insufficient MWEB funds for a confidential send") != std::string::npos);

    // Without the flag, L1-only wallets may still attempt peg-in funding (sendtoaddress path).
    wallet::CCoinControl cc_legacy;
    cc_legacy.m_allow_other_inputs = true;
    auto res_legacy = wallet::CreateTransaction(*wallet, {mweb_recipient}, /*change_pos=*/std::nullopt, cc_legacy);
    if (!res_legacy) {
        BOOST_CHECK(util::ErrorString(res_legacy).original.find("Insufficient MWEB funds for a confidential send") == std::string::npos);
    }
}

BOOST_FIXTURE_TEST_CASE(unknown_mweb_preset_fails_closed, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    wallet::CRecipient mweb_recipient;
    mweb_recipient.dest = StealthAddress{};
    mweb_recipient.nAmount = 1 * COIN;
    mweb_recipient.fSubtractFeeFromAmount = false;

    wallet::CCoinControl cc;
    cc.m_no_auto_pegin = true;
    cc.m_allow_other_inputs = false;
    cc.SelectMWEB(mw::Hash{});

    auto res = wallet::CreateTransaction(*wallet, {mweb_recipient}, /*change_pos=*/std::nullopt, cc);
    BOOST_CHECK(!res);
    BOOST_CHECK(util::ErrorString(res).original.find("Unable to find MWEB output") != std::string::npos);
    BOOST_CHECK(util::ErrorString(res).original.find("Insufficient MWEB funds for a confidential send") == std::string::npos);

    wallet::CRecipient l1_recipient{PKHash{}, 1 * COIN, /*subtract_fee=*/false};
    wallet::CCoinControl cc_pegout;
    cc_pegout.m_allow_other_inputs = false;
    cc_pegout.SelectMWEB(mw::Hash{});
    auto res_pegout = wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, cc_pegout);
    BOOST_CHECK(!res_pegout);
    BOOST_CHECK(util::ErrorString(res_pegout).original.find("Unable to find MWEB output") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(pegin_refuses_mweb_inputs, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    wallet::CRecipient mweb_recipient;
    mweb_recipient.dest = StealthAddress{};
    mweb_recipient.nAmount = 1 * COIN;
    mweb_recipient.fSubtractFeeFromAmount = false;

    wallet::CCoinControl cc;
    cc.m_mweb_peg_in = true;
    cc.SelectMWEB(mw::Hash{});

    auto res = wallet::CreateTransaction(*wallet, {mweb_recipient}, /*change_pos=*/std::nullopt, cc);
    BOOST_CHECK(!res);
    BOOST_CHECK_EQUAL(util::ErrorString(res).original, "A peg-in cannot spend MWEB inputs");
}

BOOST_FIXTURE_TEST_CASE(pegin_funds_from_l1_coins, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);
    BOOST_REQUIRE(!wallet::PegInAndMine(*this, *wallet, 10 * COIN).empty());

    const wallet::CRecipient own_mweb{wallet::getNewDestination(*wallet, OutputType::MWEB), 1 * COIN, /*subtract_fee=*/false};

    // The wallet holds L1 and MWEB coins, and a plain send to its MWEB address spends MWEB coins.
    const auto plain = wallet::CreateTransaction(*wallet, {own_mweb}, /*change_pos=*/std::nullopt, wallet::CCoinControl{});
    BOOST_REQUIRE_MESSAGE(plain, util::ErrorString(plain).original);
    BOOST_CHECK(plain->tx->vin.empty());
    BOOST_CHECK(!plain->tx->mweb_tx.GetSpentIDs().empty());
    BOOST_CHECK(plain->tx->mweb_tx.GetPegIns().empty());

    // A peg-in of the same payment spends L1 coins only.
    wallet::CCoinControl peg_in;
    peg_in.m_mweb_peg_in = true;
    const auto res = wallet::CreateTransaction(*wallet, {own_mweb}, /*change_pos=*/std::nullopt, peg_in);
    BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
    BOOST_CHECK(!res->tx->vin.empty());
    BOOST_CHECK(res->tx->mweb_tx.GetSpentIDs().empty());
    BOOST_CHECK(!res->tx->mweb_tx.GetPegIns().empty());
}

BOOST_FIXTURE_TEST_CASE(pegout_refuses_l1_funding, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    const wallet::CRecipient l1_recipient{PKHash{}, 1 * COIN, /*subtract_fee=*/false};

    // The wallet holds only L1 coins, which a plain send spends.
    BOOST_CHECK(wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, wallet::CCoinControl{}));

    wallet::CCoinControl cc;
    cc.m_mweb_peg_out = true;
    auto res = wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, cc);
    BOOST_CHECK(!res);
    BOOST_CHECK_EQUAL(util::ErrorString(res).original, "Insufficient MWEB funds for a peg-out");

    COutPoint l1_coin;
    {
        LOCK(wallet->cs_wallet);
        l1_coin = wallet::AvailableCoins(*wallet).All().at(0).outpoint;
    }
    cc.Select(l1_coin);
    auto res_l1_input = wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, cc);
    BOOST_CHECK(!res_l1_input);
    BOOST_CHECK_EQUAL(util::ErrorString(res_l1_input).original, "A peg-out cannot spend L1 inputs");
}

BOOST_FIXTURE_TEST_CASE(pegout_funds_from_mweb_coins, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);

    // The wallet's first MWEB coins come from a peg-in of its L1 coins.
    std::set<mw::Hash> mweb_coins;
    CAmount mweb_balance{0};
    for (const auto& [output_id, amount] : wallet::PegInAndMine(*this, *wallet, 10 * COIN)) {
        mweb_coins.insert(output_id);
        mweb_balance += amount;
    }
    BOOST_REQUIRE(!mweb_coins.empty());
    BOOST_REQUIRE_GE(mweb_balance, 10 * COIN);

    const CTxDestination l1_dest = wallet::getNewDestination(*wallet, OutputType::BECH32);
    const wallet::CRecipient l1_recipient{l1_dest, 1 * COIN, /*subtract_fee=*/false};

    // A plain send to an L1 address spends L1 coins.
    const auto plain = wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, wallet::CCoinControl{});
    BOOST_REQUIRE_MESSAGE(plain, util::ErrorString(plain).original);
    BOOST_CHECK(!plain->tx->vin.empty());
    BOOST_CHECK(!plain->tx->HasMWEBTx());

    // A peg-out of the same payment spends MWEB coins only and pays the address from a kernel.
    wallet::CCoinControl peg_out;
    peg_out.m_mweb_peg_out = true;
    peg_out.m_feerate = CFeeRate{10'000};
    for (const bool subtract_fee : {false, true}) {
        wallet::CRecipient recipient{l1_recipient};
        recipient.fSubtractFeeFromAmount = subtract_fee;
        const auto res = wallet::CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, peg_out);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        const CTransaction& tx = *res->tx;
        BOOST_CHECK(tx.IsMWEBOnly());
        const std::set<mw::Hash> spent = tx.mweb_tx.GetSpentIDs();
        BOOST_CHECK(!spent.empty());
        BOOST_CHECK(std::includes(mweb_coins.begin(), mweb_coins.end(), spent.begin(), spent.end()));
        const std::vector<PegOutCoin> pegouts = tx.mweb_tx.GetPegOuts();
        BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);
        BOOST_CHECK(pegouts[0].GetScriptPubKey() == GetScriptForDestination(l1_dest));
        BOOST_CHECK_EQUAL(pegouts[0].GetAmount(), subtract_fee ? 1 * COIN - res->fee : 1 * COIN);
        BOOST_CHECK_EQUAL(*tx.mweb_tx.GetFee(), res->fee);
        BOOST_CHECK_GE(res->fee, MWEB::ComputeKernelFee(*peg_out.m_feerate, MWEB::TxType::PEGOUT, tx.mweb_tx.GetMWEBWeight(), {recipient}));
    }

    // The peg-out available balance is the MWEB coins the wallet may spend.
    wallet::WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;
    const auto interface_wallet = interfaces::MakeWallet(context, shared_wallet);
    BOOST_CHECK_EQUAL(interface_wallet->getAvailableBalance(peg_out), mweb_balance);
    {
        LOCK(wallet->cs_wallet);
        for (const mw::Hash& output_id : mweb_coins) {
            wallet->LockCoin(output_id, /*persist=*/false);
        }
    }
    BOOST_CHECK_EQUAL(interface_wallet->getAvailableBalance(peg_out), 0);
    const auto res_locked = wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, peg_out);
    BOOST_CHECK(!res_locked);
    BOOST_CHECK_EQUAL(util::ErrorString(res_locked).original, "Insufficient MWEB funds for a peg-out");
}

BOOST_FIXTURE_TEST_CASE(mweb_change_metadata_distinguishes_same_address_recipient, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain,
        WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);
    constexpr CAmount input_amount{5 * COIN}, payment{2 * COIN};
    const auto funding = wallet::PegInAndMine(*this, *wallet, input_amount);
    const auto selected = std::find_if(funding.begin(), funding.end(), [&](const auto& coin) { return coin.second == input_amount; });
    BOOST_REQUIRE(selected != funding.end());
    const mw::Hash input_id{selected->first};
    const StealthAddress shared_address = std::get<StealthAddress>(wallet::getNewDestination(*wallet, OutputType::MWEB));

    wallet::CCoinControl coin_control;
    coin_control.SelectMWEB(input_id);
    coin_control.m_allow_other_inputs = false;
    coin_control.m_feerate = CFeeRate{10'000};
    coin_control.fOverrideFeeRate = true;
    coin_control.destChange = shared_address;
    for (const bool sign : {false, true}) {
        const auto created = wallet::CreateTransaction(*wallet, {{shared_address, payment, /*subtract_fee=*/false}},
            /*change_pos=*/std::nullopt, coin_control, sign);
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        BOOST_CHECK(created->tx->vin.empty());
        BOOST_CHECK(created->tx->vout.empty());
        BOOST_CHECK(!created->change_pos);
        BOOST_REQUIRE_EQUAL(created->mweb_tx.inputs.size(), 1U);
        BOOST_CHECK(created->mweb_tx.inputs.front().output_id == input_id);
        BOOST_REQUIRE_EQUAL(created->mweb_tx.outputs.size(), 2U);
        BOOST_REQUIRE(created->mweb_change_index);
        const size_t change_index{*created->mweb_change_index};
        BOOST_REQUIRE_LT(change_index, created->mweb_tx.outputs.size());
        const auto& change = created->mweb_tx.outputs[change_index];
        const auto& recipient = created->mweb_tx.outputs[1 - change_index];
        BOOST_CHECK(change.address == shared_address);
        BOOST_CHECK(recipient.address == shared_address);
        BOOST_REQUIRE(change.amount);
        BOOST_REQUIRE(recipient.amount);
        BOOST_CHECK_EQUAL(*recipient.amount, payment);
        BOOST_REQUIRE_GT(created->fee, 0);
        const CAmount expected_change{input_amount - payment - created->fee};
        BOOST_REQUIRE_GT(expected_change, payment);
        BOOST_CHECK_EQUAL(*change.amount, expected_change);
        BOOST_CHECK_EQUAL(*change.amount + *recipient.amount + created->fee, input_amount);

        if (!sign) {
            BOOST_CHECK(created->tx->mweb_tx.IsNull());
            BOOST_CHECK(!change.CalcOutputID());
            BOOST_CHECK(!recipient.CalcOutputID());
            continue;
        }

        BOOST_REQUIRE(created->tx->HasMWEBTx());
        BOOST_CHECK(created->tx->mweb_tx.GetSpentIDs() == std::set<mw::Hash>{input_id});
        const auto change_id = change.CalcOutputID();
        const auto recipient_id = recipient.CalcOutputID();
        BOOST_REQUIRE(change_id);
        BOOST_REQUIRE(recipient_id);
        BOOST_CHECK(*change_id != *recipient_id);
        const std::set<mw::Hash> expected_ids{*change_id, *recipient_id};
        BOOST_CHECK(created->tx->mweb_tx.GetOutputIDs() == expected_ids);
        // The change index addresses retained mutable metadata. The final body
        // is sorted, so locate that exact output by ID rather than by this index.
        const auto& outputs = created->tx->mweb_tx.m_transaction->GetOutputs();
        const auto finalized_change = std::find_if(outputs.begin(), outputs.end(),
            [&](const Output& output) { return output.GetOutputID() == *change_id; });
        BOOST_REQUIRE(finalized_change != outputs.end());
        BOOST_CHECK(*finalized_change == *change.Finalized());
    }
}

BOOST_FIXTURE_TEST_CASE(mweb_builder_outputs_use_scan_derived_sender_sequence, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain,
        WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    wallet->SetMWEBDeterministicSenders(true);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);
    constexpr CAmount input_amount{10 * COIN};
    const auto funding = wallet::PegInAndMine(*this, *wallet, input_amount);
    const auto selected = std::find_if(funding.begin(), funding.end(), [&](const auto& coin) { return coin.second == input_amount; });
    BOOST_REQUIRE(selected != funding.end());
    const mw::Hash input_id{selected->first};
    const auto keychain = WITH_LOCK(wallet->cs_wallet, return wallet->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    const auto read_sender_index = [&] {
        uint64_t next_index{0};
        BOOST_REQUIRE(wallet->GetDatabase().MakeBatch()->Read(
            std::make_pair(wallet::DBKeys::MWEB_SENDER_KEY_INDEX, keychain->GetMasterScanKeyID()), next_index));
        return next_index;
    };
    const uint64_t first_sender_index{read_sender_index()};
    BOOST_REQUIRE_GT(first_sender_index, 0U); // The real funding transaction already consumed sender keys.

    std::vector<wallet::CRecipient> recipients{{StealthAddress::Random(), COIN, /*subtract_fee=*/false}};
#if ENABLE_MWEB_UNCOMMON_SENDS
    recipients.push_back({StealthAddress::Random(), 2 * COIN, /*subtract_fee=*/false});
#endif
    std::map<StealthAddress, CAmount> expected_payments;
    CAmount payment_total{0};
    for (const auto& recipient : recipients) {
        expected_payments.emplace(std::get<StealthAddress>(recipient.dest), recipient.nAmount);
        payment_total += recipient.nAmount;
    }
    const size_t output_count{recipients.size() + 1};
    wallet::CCoinControl coin_control;
    coin_control.SelectMWEB(input_id);
    coin_control.m_allow_other_inputs = false;
    // Request one APS candidate; the default wrapper may sign and discard another.
    coin_control.m_avoid_partial_spends = true;
    coin_control.m_feerate = CFeeRate{10'000};
    coin_control.fOverrideFeeRate = true;

    const auto unsigned_tx = wallet::CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/false);
    BOOST_REQUIRE_MESSAGE(unsigned_tx, util::ErrorString(unsigned_tx).original);
    BOOST_REQUIRE_EQUAL(unsigned_tx->mweb_tx.outputs.size(), output_count);
    BOOST_CHECK(unsigned_tx->tx->mweb_tx.IsNull());
    for (const auto& output : unsigned_tx->mweb_tx.outputs) {
        BOOST_CHECK(!output.sender_pubkey);
        BOOST_CHECK(!output.CalcOutputID());
    }
    BOOST_CHECK_EQUAL(read_sender_index(), first_sender_index);

    const auto created = wallet::CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE(created->tx->IsMWEBOnly());
    BOOST_CHECK(created->tx->mweb_tx.GetPegIns().empty());
    BOOST_CHECK(created->tx->mweb_tx.GetPegOuts().empty());
    BOOST_REQUIRE_EQUAL(created->tx->mweb_tx.m_transaction->GetKernels().size(), 1U);
    BOOST_REQUIRE(created->tx->mweb_tx.GetFee());
    BOOST_CHECK_EQUAL(*created->tx->mweb_tx.GetFee(), created->fee);
    BOOST_CHECK(created->tx->mweb_tx.GetSpentIDs() == std::set<mw::Hash>{input_id});
    BOOST_REQUIRE_EQUAL(created->mweb_tx.outputs.size(), output_count);
    BOOST_REQUIRE(created->mweb_change_index);
    BOOST_REQUIRE_LT(*created->mweb_change_index, output_count);
    BOOST_CHECK_EQUAL(read_sender_index(), first_sender_index + output_count);
    std::set<PublicKey> expected_sender_pubkeys;
    for (uint64_t i = 0; i < output_count; ++i) {
        BOOST_REQUIRE(expected_sender_pubkeys.insert(PublicKey::From(
            mw::DeriveSenderSigningKey(keychain->GetScanSecret(), first_sender_index + i))).second);
    }

    const auto& final_outputs = created->tx->mweb_tx.m_transaction->GetOutputs();
    BOOST_REQUIRE_EQUAL(final_outputs.size(), output_count);
    std::set<mw::Hash> output_ids;
    for (size_t i = 0; i < output_count; ++i) {
        const auto& output = created->mweb_tx.outputs[i];
        BOOST_REQUIRE(output.sender_pubkey);
        BOOST_CHECK_EQUAL(expected_sender_pubkeys.erase(*output.sender_pubkey), 1U);
        BOOST_REQUIRE(output.address);
        BOOST_REQUIRE(output.amount);
        const bool is_change{i == *created->mweb_change_index};
        if (is_change) {
            BOOST_CHECK_EQUAL(*output.amount, input_amount - payment_total - created->fee);
        } else {
            const auto payment = expected_payments.find(*output.address);
            BOOST_REQUIRE(payment != expected_payments.end());
            BOOST_CHECK_EQUAL(*output.amount, payment->second);
            expected_payments.erase(payment);
        }
        const auto output_id = output.CalcOutputID();
        BOOST_REQUIRE(output_id);
        BOOST_REQUIRE(output_ids.insert(*output_id).second);
        // Mutable metadata keeps its own order; locate the sorted wire output by ID.
        const auto finalized = std::find_if(final_outputs.begin(), final_outputs.end(),
            [&](const Output& candidate) { return candidate.GetOutputID() == *output_id; });
        BOOST_REQUIRE(finalized != final_outputs.end());
        BOOST_CHECK(*finalized == *output.Finalized());
        LOCK(wallet->cs_wallet);
        mw::Coin coin;
        BOOST_REQUIRE(wallet->GetCoin(*output_id, coin));
        BOOST_CHECK(coin.output_id == *output_id);
        BOOST_CHECK(coin.address == output.address);
        BOOST_CHECK_EQUAL(coin.amount, *output.amount);
        BOOST_REQUIRE(coin.sender_key);
        BOOST_CHECK(PublicKey::From(*coin.sender_key) == *output.sender_pubkey);
        BOOST_CHECK(coin.master_scan_key_id == keychain->GetMasterScanKeyID());
        BOOST_CHECK_EQUAL(coin.IsMine(), is_change);
        BOOST_CHECK_EQUAL(coin.IsChange(), is_change);
        mw::Coin persisted;
        BOOST_REQUIRE(wallet->GetDatabase().MakeBatch()->Read(std::make_pair(wallet::DBKeys::MWEB_COIN, *output_id), persisted));
        BOOST_CHECK(persisted.Serialized() == coin.SanitizeForDisk().Serialized());
    }
    BOOST_CHECK(expected_sender_pubkeys.empty());
    BOOST_CHECK(expected_payments.empty());
    BOOST_CHECK(created->tx->mweb_tx.GetOutputIDs() == output_ids);

    const auto& change = created->mweb_tx.outputs[*created->mweb_change_index];
    const auto change_id = change.CalcOutputID();
    BOOST_REQUIRE(change_id);
    wallet->CommitTransaction(created->tx);
    {
        LOCK(::cs_main);
        const auto admitted = Assert(m_node.chainman)->ProcessTransaction(created->tx);
        BOOST_REQUIRE_MESSAGE(admitted.m_result_type == MempoolAcceptResult::ResultType::VALID, admitted.m_state.ToString());
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    MineMWEBEraBlock();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    LOCK(wallet->cs_wallet);
    const auto* confirmed = wallet->GetWalletTx(created->tx->GetHash());
    BOOST_REQUIRE(confirmed);
    BOOST_CHECK(!confirmed->IsMWEBPlaceholder());
    BOOST_CHECK(confirmed->GetTx()->GetHash() == created->tx->GetHash());
    BOOST_CHECK(confirmed->GetTx()->mweb_tx.GetOutputIDs() == output_ids);
    BOOST_CHECK_EQUAL(wallet->GetTxDepthInMainChain(*confirmed), 1);
    mw::Coin mined_change;
    BOOST_REQUIRE(wallet->GetCoin(*change_id, mined_change));
    BOOST_CHECK(mined_change.output_id == *change_id);
    BOOST_CHECK(mined_change.IsMine());
    BOOST_CHECK(mined_change.IsChange());
    BOOST_CHECK_EQUAL(mined_change.address_index, mw::CHANGE_INDEX);
    BOOST_CHECK(mined_change.address == change.address);
    BOOST_CHECK_EQUAL(mined_change.amount, *change.amount);
    std::map<mw::Hash, CAmount> inventory;
    for (const auto& entry : wallet->ListMWEBUnspent(1, 9999999, false, nullptr, 0, MAX_MONEY)) {
        inventory.emplace(entry.output_id, entry.amount);
        if (entry.output_id == *change_id) {
            BOOST_CHECK(entry.txid == created->tx->GetHash());
            BOOST_CHECK_EQUAL(entry.depth, 1);
            BOOST_CHECK(entry.safe);
        }
    }
    auto expected_inventory = funding;
    BOOST_REQUIRE_EQUAL(expected_inventory.erase(input_id), 1U);
    BOOST_REQUIRE(expected_inventory.emplace(*change_id, *change.amount).second);
    BOOST_CHECK(inventory == expected_inventory);
}

BOOST_FIXTURE_TEST_CASE(mweb_builder_outputs_use_random_sender_keys_by_default, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain,
        WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(!wallet->GetMWWallet()->UseDeterministicSenderKeys());
    }
    constexpr CAmount input_amount{10 * COIN};
    const auto funding = wallet::PegInAndMine(*this, *wallet, input_amount);
    const auto selected = std::find_if(funding.begin(), funding.end(), [&](const auto& coin) { return coin.second == input_amount; });
    BOOST_REQUIRE(selected != funding.end());
    const auto keychain = WITH_LOCK(wallet->cs_wallet, return wallet->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);
    BOOST_CHECK(!wallet->GetDatabase().MakeBatch()->Exists(
        std::make_pair(wallet::DBKeys::MWEB_SENDER_KEY_INDEX, keychain->GetMasterScanKeyID())));

    wallet::CCoinControl coin_control;
    coin_control.SelectMWEB(selected->first);
    coin_control.m_allow_other_inputs = false;
    coin_control.m_avoid_partial_spends = true;
    coin_control.m_feerate = CFeeRate{10'000};
    coin_control.fOverrideFeeRate = true;
    const std::vector<wallet::CRecipient> recipients{{StealthAddress::Random(), COIN, /*subtract_fee=*/false}};
    const auto created = wallet::CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_CHECK(!wallet->GetDatabase().MakeBatch()->Exists(
        std::make_pair(wallet::DBKeys::MWEB_SENDER_KEY_INDEX, keychain->GetMasterScanKeyID())));
    for (size_t i = 0; i < created->mweb_tx.outputs.size(); ++i) {
        BOOST_REQUIRE(created->mweb_tx.outputs[i].sender_pubkey);
        for (uint64_t idx = 0; idx < 4; ++idx) {
            BOOST_CHECK(*created->mweb_tx.outputs[i].sender_pubkey !=
                        PublicKey::From(mw::DeriveSenderSigningKey(keychain->GetScanSecret(), idx)));
        }
    }
}

BOOST_FIXTURE_TEST_CASE(default_mweb_change_identity_survives_commit_and_mining, MWEBRegtest100Setup)
{
    struct Phase {
        const char* source_case;
        bool l1_input;
        bool mweb_input;
        OutputType recipient_type;
        std::vector<CAmount> amounts;
    };
    const std::vector<Phase> phases{
        {"SingleMWEBRecipientFromLTCBuildsPegin", true, false, OutputType::MWEB, {5 * COIN}},
#if ENABLE_MWEB_UNCOMMON_SENDS
        {"MultipleMWEBRecipientsFromLTCBuildPegin", true, false, OutputType::MWEB, {2 * COIN, 3 * COIN}},
#endif
        {"SingleLTCRecipientFromMWEBBuildsPegout", false, true, OutputType::BECH32, {COIN}},
        {"MultipleLTCRecipientsFromMWEBBuildPegout", false, true, OutputType::BECH32, {COIN, 2 * COIN}},
        {"SingleLTCRecipientFromLTCAndMWEBBuildsPeginPegout", true, true, OutputType::BECH32, {COIN}},
        {"MultipleLTCRecipientsFromLTCAndMWEBBuildPeginPegout", true, true, OutputType::BECH32, {COIN, 2 * COIN}},
    };
    MineToMWEBActivation();
    for (const Phase& phase : phases) {
        BOOST_TEST_CONTEXT(phase.source_case) {
            auto wallet = wallet::CreateSyncedWallet(*m_node.chain,
                WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
            const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
            const auto notifications = m_node.chain->handleNotifications(shared_wallet);
            constexpr CAmount mweb_input_amount{10 * COIN};
            const auto funding = wallet::PegInAndMine(*this, *wallet, mweb_input_amount);
            const auto selected = std::find_if(funding.begin(), funding.end(), [&](const auto& coin) { return coin.second == mweb_input_amount; });
            BOOST_REQUIRE(selected != funding.end());
            wallet::CCoinControl coin_control;
            coin_control.m_allow_other_inputs = false;
            coin_control.m_avoid_partial_spends = true;
            coin_control.m_feerate = CFeeRate{10'000};
            coin_control.fOverrideFeeRate = true;
            CAmount input_total{0};
            std::set<mw::Hash> expected_spent;
            if (phase.mweb_input) {
                coin_control.SelectMWEB(selected->first);
                expected_spent.insert(selected->first);
                input_total += mweb_input_amount;
            }
            std::optional<COutPoint> l1_input;
            if (phase.l1_input) {
                LOCK(wallet->cs_wallet);
                const auto l1_coins = wallet::AvailableCoins(*wallet).All();
                BOOST_REQUIRE(!l1_coins.empty());
                const auto& coin = l1_coins.front();
                l1_input = coin.outpoint;
                coin_control.Select(*l1_input);
                input_total += coin.txout.nValue;
            }
            std::vector<wallet::CRecipient> recipients;
            std::map<StealthAddress, CAmount> expected_mweb_payments;
            std::vector<PegOutCoin> expected_pegouts;
            CAmount payment_total{0};
            for (const CAmount amount : phase.amounts) {
                const CTxDestination destination = wallet::getNewDestination(*wallet, phase.recipient_type);
                recipients.push_back({destination, amount, /*subtract_fee=*/false});
                if (phase.recipient_type == OutputType::MWEB) {
                    BOOST_REQUIRE(expected_mweb_payments.emplace(std::get<StealthAddress>(destination), amount).second);
                } else {
                    expected_pegouts.emplace_back(amount, GetScriptForDestination(destination));
                }
                payment_total += amount;
            }
            const auto created = wallet::CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
            BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
            const CTransaction& tx = *created->tx;
            BOOST_REQUIRE(tx.HasMWEBTx());
            BOOST_REQUIRE_EQUAL(tx.vin.size(), phase.l1_input ? 1U : 0U);
            if (l1_input) BOOST_CHECK(tx.vin.front().prevout == *l1_input);
            BOOST_CHECK(tx.mweb_tx.GetSpentIDs() == expected_spent);
            BOOST_REQUIRE_EQUAL(tx.mweb_tx.m_transaction->GetInputs().size(), phase.mweb_input ? 1U : 0U);
            BOOST_REQUIRE_EQUAL(tx.mweb_tx.m_transaction->GetKernels().size(), 1U);
            BOOST_CHECK(tx.mweb_tx.GetPegOuts() == expected_pegouts);
            const auto pegins = tx.mweb_tx.GetPegIns();
            BOOST_REQUIRE_EQUAL(pegins.size(), phase.l1_input ? 1U : 0U);
            BOOST_REQUIRE_EQUAL(tx.vout.size(), phase.l1_input ? 1U : 0U);
            if (phase.l1_input) {
                BOOST_CHECK_EQUAL(tx.vout.front().nValue, pegins.front().GetAmount());
                BOOST_CHECK(tx.vout.front().scriptPubKey == GetScriptForPegin(pegins.front().GetKernelID()));
            }
            BOOST_CHECK(!created->change_pos);
            BOOST_REQUIRE(created->mweb_change_index);
            const size_t change_index{*created->mweb_change_index};
            const size_t output_count{expected_mweb_payments.size() + 1};
            BOOST_REQUIRE_EQUAL(created->mweb_tx.outputs.size(), output_count);
            BOOST_REQUIRE_EQUAL(tx.mweb_tx.m_transaction->GetOutputs().size(), output_count);
            BOOST_REQUIRE_LT(change_index, output_count);
            BOOST_REQUIRE_GT(created->fee, 0);
            const CAmount change_amount{input_total - payment_total - created->fee};
            BOOST_REQUIRE_GT(change_amount, 0);
            std::map<mw::Hash, CAmount> new_owned_outputs;
            CAmount mweb_output_total{0};
            for (size_t i = 0; i < output_count; ++i) {
                const auto& output = created->mweb_tx.outputs[i];
                BOOST_REQUIRE(output.address);
                BOOST_REQUIRE(output.amount);
                if (i == change_index) {
                    BOOST_CHECK_EQUAL(*output.amount, change_amount);
                } else {
                    const auto payment = expected_mweb_payments.find(*output.address);
                    BOOST_REQUIRE(payment != expected_mweb_payments.end());
                    BOOST_CHECK_EQUAL(*output.amount, payment->second);
                    expected_mweb_payments.erase(payment);
                }
                const auto output_id = output.CalcOutputID();
                BOOST_REQUIRE(output_id);
                BOOST_REQUIRE(new_owned_outputs.emplace(*output_id, *output.amount).second);
                Output finalized;
                BOOST_REQUIRE(tx.mweb_tx.GetOutput(*output_id, finalized));
                BOOST_CHECK(finalized == *output.Finalized());
                mweb_output_total += *output.amount;
            }
            BOOST_CHECK(expected_mweb_payments.empty());
            std::set<mw::Hash> output_ids;
            for (const auto& entry : new_owned_outputs) output_ids.insert(entry.first);
            BOOST_CHECK(tx.mweb_tx.GetOutputIDs() == output_ids);
            BOOST_REQUIRE(tx.mweb_tx.GetFee());
            const CAmount pegin_amount{pegins.empty() ? 0 : pegins.front().GetAmount()};
            const CAmount pegout_total{phase.recipient_type == OutputType::MWEB ? 0 : payment_total};
            BOOST_CHECK_EQUAL((phase.mweb_input ? mweb_input_amount : 0) + pegin_amount,
                mweb_output_total + pegout_total + *tx.mweb_tx.GetFee());
            BOOST_CHECK_EQUAL(created->fee, input_total - (phase.mweb_input ? mweb_input_amount : 0) - pegin_amount + *tx.mweb_tx.GetFee());

            wallet->CommitTransaction(created->tx);
            {
                LOCK(::cs_main);
                const auto admitted = Assert(m_node.chainman)->ProcessTransaction(created->tx);
                BOOST_REQUIRE_MESSAGE(admitted.m_result_type == MempoolAcceptResult::ResultType::VALID, admitted.m_state.ToString());
            }
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            MineMWEBEraBlock();
            m_node.validation_signals->SyncWithValidationInterfaceQueue();

            LOCK(wallet->cs_wallet);
            const auto* confirmed = wallet->GetWalletTx(tx.GetHash());
            BOOST_REQUIRE(confirmed);
            BOOST_CHECK(!confirmed->IsMWEBPlaceholder());
            BOOST_CHECK(confirmed->GetTx()->GetHash() == tx.GetHash());
            BOOST_CHECK(confirmed->GetTx()->mweb_tx.GetSpentIDs() == expected_spent);
            BOOST_CHECK(confirmed->GetTx()->mweb_tx.GetOutputIDs() == output_ids);
            BOOST_CHECK(confirmed->GetTx()->mweb_tx.GetKernelIDs() == tx.mweb_tx.GetKernelIDs());
            BOOST_CHECK_EQUAL(wallet->GetTxDepthInMainChain(*confirmed), 1);
            for (size_t i = 0; i < output_count; ++i) {
                const auto& output = created->mweb_tx.outputs[i];
                const auto output_id = output.CalcOutputID();
                BOOST_REQUIRE(output_id);
                mw::Coin coin;
                BOOST_REQUIRE(wallet->GetCoin(*output_id, coin));
                BOOST_CHECK(coin.output_id == *output_id);
                BOOST_CHECK(coin.address == output.address);
                BOOST_CHECK_EQUAL(coin.amount, *output.amount);
                BOOST_CHECK(coin.IsMine());
                BOOST_CHECK_EQUAL(coin.IsChange(), i == change_index);
                BOOST_CHECK_EQUAL(wallet->GetMWWallet()->IsChange(*output.address), i == change_index);
                if (i == change_index) BOOST_CHECK_EQUAL(coin.address_index, mw::CHANGE_INDEX);
                mw::Coin persisted;
                BOOST_REQUIRE(wallet->GetDatabase().MakeBatch()->Read(std::make_pair(wallet::DBKeys::MWEB_COIN, *output_id), persisted));
                BOOST_CHECK(persisted.Serialized() == coin.SanitizeForDisk().Serialized());
            }
            auto expected_inventory = funding;
            for (const auto& id : expected_spent) BOOST_REQUIRE_EQUAL(expected_inventory.erase(id), 1U);
            for (const auto& [id, amount] : new_owned_outputs) BOOST_REQUIRE(expected_inventory.emplace(id, amount).second);
            std::map<mw::Hash, CAmount> inventory;
            for (const auto& entry : wallet->ListMWEBUnspent(1, 9999999, false, nullptr, 0, MAX_MONEY)) {
                BOOST_REQUIRE(inventory.emplace(entry.output_id, entry.amount).second);
                if (new_owned_outputs.contains(entry.output_id)) {
                    BOOST_CHECK(entry.txid == tx.GetHash());
                    BOOST_CHECK_EQUAL(entry.depth, 1);
                    BOOST_CHECK(entry.safe);
                }
            }
            BOOST_CHECK(inventory == expected_inventory);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(pegout_preset_tops_up_from_other_mweb_coins, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);
    // The peg-in makes a 5 coin output and an MWEB change output.
    const std::map<mw::Hash, CAmount> mweb_coins = wallet::PegInAndMine(*this, *wallet, 5 * COIN);
    BOOST_REQUIRE_EQUAL(mweb_coins.size(), 2U);
    const auto preset_it = std::find_if(mweb_coins.begin(), mweb_coins.end(), [](const auto& coin) { return coin.second == 5 * COIN; });
    BOOST_REQUIRE(preset_it != mweb_coins.end());
    const mw::Hash preset = preset_it->first;

    const wallet::CRecipient l1_recipient{wallet::getNewDestination(*wallet, OutputType::BECH32), 7 * COIN, /*subtract_fee=*/false};
    wallet::CCoinControl peg_out;
    peg_out.m_mweb_peg_out = true;
    peg_out.m_feerate = CFeeRate{10'000};
    peg_out.SelectMWEB(preset);

    peg_out.m_allow_other_inputs = false;
    const auto res_preset_only = wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, peg_out);
    BOOST_CHECK(!res_preset_only);
    BOOST_CHECK_EQUAL(util::ErrorString(res_preset_only).original, "Insufficient funds");

    // The preset coin is too small, so the wallet adds its other MWEB coin and no L1 coin.
    peg_out.m_allow_other_inputs = true;
    const auto res = wallet::CreateTransaction(*wallet, {l1_recipient}, /*change_pos=*/std::nullopt, peg_out);
    BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
    BOOST_CHECK(res->tx->IsMWEBOnly());
    std::set<mw::Hash> expected_spent;
    for (const auto& [output_id, amount] : mweb_coins) expected_spent.insert(output_id);
    BOOST_CHECK(res->tx->mweb_tx.GetSpentIDs() == expected_spent);
    const std::vector<PegOutCoin> pegouts = res->tx->mweb_tx.GetPegOuts();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);
    BOOST_CHECK_EQUAL(pegouts[0].GetAmount(), 7 * COIN);
}

BOOST_FIXTURE_TEST_CASE(peek_new_destination_matches_next_address, TestChain100Setup)
{
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    for (const OutputType type : {OutputType::LEGACY, OutputType::P2SH_SEGWIT, OutputType::BECH32, OutputType::BECH32M}) {
        const auto peeked = wallet->PeekNewDestination(type);
        BOOST_REQUIRE_MESSAGE(peeked, util::ErrorString(peeked).original);
        // Peeking takes nothing, so peeking again and then taking return the same address.
        const auto peeked_again = wallet->PeekNewDestination(type);
        BOOST_REQUIRE(peeked_again);
        BOOST_CHECK(*peeked_again == *peeked);
        BOOST_CHECK(!WITH_LOCK(wallet->cs_wallet, return wallet->FindAddressBookEntry(*peeked)));
        const auto taken = wallet->GetNewDestination(type, "");
        BOOST_REQUIRE(taken);
        BOOST_CHECK(*taken == *peeked);
        const auto peeked_next = wallet->PeekNewDestination(type);
        BOOST_REQUIRE(peeked_next);
        BOOST_CHECK(*peeked_next != *peeked);
        BOOST_CHECK(*peeked_next == *Assert(wallet->GetNewDestination(type, "")));
    }

    BOOST_CHECK(!wallet->PeekNewDestination(OutputType::MWEB));
}

// A sweep whose recipients pay the fee builds no change output, so its fee
// must not pay for one, on the peg-out and mixed paths too.
BOOST_FIXTURE_TEST_CASE(sweep_pays_no_change_fee, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);
    const std::map<mw::Hash, CAmount> mweb_coins = wallet::PegInAndMine(*this, *wallet, 10 * COIN);
    BOOST_REQUIRE(!mweb_coins.empty());

    const CFeeRate feerate{1'000};
    // Preset sweeps select their coins, as sendall does; the others leave
    // selection to the wallet.
    const auto sweep = [&](bool with_mweb_inputs, bool with_l1_input, OutputType dest_type, bool preset) {
        wallet::CCoinControl cc;
        cc.m_feerate = feerate;
        cc.fOverrideFeeRate = true;
        cc.m_allow_other_inputs = !preset;
        CAmount total{0};
        for (const auto& [output_id, amount] : mweb_coins) {
            if (!with_mweb_inputs) break;
            if (preset) cc.SelectMWEB(output_id);
            total += amount;
        }
        if (with_l1_input) {
            LOCK(wallet->cs_wallet);
            const wallet::COutput l1_coin = wallet::AvailableCoins(*wallet).All().at(0);
            if (preset) cc.Select(l1_coin.outpoint);
            total += l1_coin.txout.nValue;
        }
        const wallet::CRecipient recipient{wallet::getNewDestination(*wallet, dest_type), total, /*subtract_fee=*/true};
        const auto res = wallet::CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, cc, /*sign=*/true);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        return std::make_pair(recipient, *res);
    };

    // Peg-out: no L1 bytes but the peg-out itself, so the fee is exact.
    {
        const auto [recipient, res] = sweep(/*with_mweb_inputs=*/true, /*with_l1_input=*/false, OutputType::BECH32, /*preset=*/true);
        const CTransaction& tx = *res.tx;
        BOOST_REQUIRE(tx.IsMWEBOnly());
        BOOST_CHECK(tx.mweb_tx.GetOutputIDs().empty());
        const uint64_t weight{MWEB::CalcMWEBWeight(MWEB::TxType::PEGOUT, /*change_on_mweb=*/false, {recipient})};
        BOOST_CHECK_EQUAL(tx.mweb_tx.GetMWEBWeight(), weight);
        BOOST_CHECK_EQUAL(res.fee, feerate.GetTotalFee(MWEB::CalcPegOutBytes(MWEB::TxType::PEGOUT, {recipient}), weight));
        BOOST_CHECK_EQUAL(*tx.mweb_tx.GetFee(), res.fee);
    }

    // Mixed inputs to an L1 address, and a peg-in of an L1 coin: the L1 size
    // is estimated before signing, so allow the signature size margin, which
    // is far below a change output's 1,800 sat. The last case leaves one L1
    // coin unlocked, so the wallet must add L1 coins to its MWEB coins.
    for (const auto& [with_mweb_inputs, dest_type, mweb_outputs, type, preset] : {
             std::tuple{true, OutputType::BECH32, size_t{0}, MWEB::TxType::PEGOUT, true},
             std::tuple{false, OutputType::MWEB, size_t{1}, MWEB::TxType::PEGIN, true},
             std::tuple{true, OutputType::BECH32, size_t{0}, MWEB::TxType::PEGOUT, false}}) {
        if (!preset) {
            LOCK(wallet->cs_wallet);
            const std::vector<wallet::COutput> l1_coins = wallet::AvailableCoins(*wallet).All();
            for (size_t i = 1; i < l1_coins.size(); ++i) {
                wallet->LockCoin(l1_coins[i].outpoint, /*persist=*/false);
            }
        }
        const auto [recipient, res] = sweep(with_mweb_inputs, /*with_l1_input=*/true, dest_type, preset);
        const CTransaction& tx = *res.tx;
        BOOST_REQUIRE(!tx.vin.empty());
        BOOST_CHECK_EQUAL(tx.mweb_tx.GetOutputIDs().size(), mweb_outputs);
        BOOST_CHECK_EQUAL(tx.mweb_tx.GetMWEBWeight(), MWEB::CalcMWEBWeight(type, /*change_on_mweb=*/false, {recipient}));
        const CAmount required{MWEB::ComputeFeeNeeded(feerate,
            GetVirtualTransactionSize(MWEB::EstimateBuiltTxWeight(CMutableTransaction{tx}), 0, 0), tx.mweb_tx.GetMWEBWeight(), /*bump_fees=*/0)};
        BOOST_CHECK_GE(res.fee, required);
        BOOST_CHECK_LE(res.fee, required + 2);
    }
}

// After MWEB size-limit trim raises mwebminfee, CreateTransaction pays base + rolling excess.
BOOST_FIXTURE_TEST_CASE(wallet_pays_mweb_mempool_min_fee, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    {
        const auto notifications = m_node.chain->handleNotifications(shared_wallet);
        BOOST_REQUIRE(!wallet::PegInAndMine(*this, *wallet, 10 * COIN).empty());
    }

    // Bump mwebminfee with a mempool-only submit (no wallet notifications) so TrimToSize
    // cannot race wallet scheduler callbacks, and the wallet still sees its coins as free.
    const wallet::CRecipient bump_payee{wallet::getNewDestination(*wallet, OutputType::MWEB), 1 * COIN, /*subtract_fee=*/false};
    const auto bump = wallet::CreateTransaction(*wallet, {bump_payee}, /*change_pos=*/std::nullopt, wallet::CCoinControl{});
    BOOST_REQUIRE_MESSAGE(bump, util::ErrorString(bump).original);
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(Assert(m_node.chainman)->ProcessTransaction(bump->tx).m_result_type ==
                      MempoolAcceptResult::ResultType::VALID);
    }
    {
        CTxMemPool& pool{*Assert(m_node.mempool)};
        LOCK(pool.cs);
        pool.TrimToSize(0);
    }
    BOOST_REQUIRE(m_node.chain->mempoolMWEBMinFee() > CFeeRate{0});

    const wallet::CRecipient payee{wallet::getNewDestination(*wallet, OutputType::MWEB), 1 * COIN, /*subtract_fee=*/false};
    const auto paid = wallet::CreateTransaction(*wallet, {payee}, /*change_pos=*/std::nullopt, wallet::CCoinControl{});
    BOOST_REQUIRE_MESSAGE(paid, util::ErrorString(paid).original);
    const uint64_t weight{paid->tx->mweb_tx.GetMWEBWeight()};
    const CAmount required{CFeeRate::GetMWEBFee(weight) +
                           m_node.chain->mempoolMWEBMinFee().GetFee(static_cast<int32_t>(weight))};
    BOOST_REQUIRE_MESSAGE(paid->fee >= required,
                          strprintf("fee %d < required %d (base %d + mwebmin %d)", paid->fee, required,
                                    CFeeRate::GetMWEBFee(weight),
                                    m_node.chain->mempoolMWEBMinFee().GetFee(static_cast<int32_t>(weight))));

    LOCK(::cs_main);
    const auto accept{Assert(m_node.chainman)->ProcessTransaction(paid->tx)};
    BOOST_REQUIRE_MESSAGE(accept.m_result_type == MempoolAcceptResult::ResultType::VALID, accept.m_state.ToString());
}

BOOST_FIXTURE_TEST_CASE(external_mweb_payment_cached_accounting_and_mined_change, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain,
        WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);
    const auto funding = wallet::PegInAndMine(*this, *wallet, 10 * COIN);
    const auto selected = std::find_if(funding.begin(), funding.end(), [](const auto& coin) { return coin.second == 10 * COIN; });
    BOOST_REQUIRE(selected != funding.end());
    const mw::Hash input_id{selected->first};
    constexpr CAmount input_amount{10 * COIN};
    constexpr CAmount payment{COIN};
    // One input has zero weight, two standard outputs weigh 18 each, and
    // the signed plain kernel weighs 3, charged at 100 sat per weight unit.
    constexpr uint64_t expected_weight{2 * 18 + 3};
    constexpr CAmount fee{expected_weight * 100};
    constexpr CAmount change_amount{input_amount - payment - fee};
    const StealthAddress recipient = StealthAddress::Random();
    BOOST_REQUIRE(!WITH_LOCK(wallet->cs_wallet, return wallet->IsMine(CTxDestination{recipient})));

    wallet::CCoinControl coin_control;
    coin_control.SelectMWEB(input_id);
    coin_control.m_allow_other_inputs = false;
    coin_control.m_feerate = CFeeRate{10'000};
    coin_control.fOverrideFeeRate = true;
    const auto created = wallet::CreateTransaction(*wallet, {{recipient, payment, /*subtract_fee=*/false}},
        /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    const CTransaction& tx = *created->tx;
    BOOST_REQUIRE(tx.IsMWEBOnly());
    BOOST_CHECK(tx.mweb_tx.GetSpentIDs() == std::set<mw::Hash>{input_id});
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.GetOutputIDs().size(), 2U);
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.m_transaction->GetKernels().size(), 1U);
    BOOST_CHECK(tx.mweb_tx.GetPegIns().empty());
    BOOST_CHECK(tx.mweb_tx.GetPegOuts().empty());
    BOOST_CHECK_EQUAL(tx.mweb_tx.GetMWEBWeight(), expected_weight);
    BOOST_REQUIRE(tx.mweb_tx.GetFee());
    BOOST_CHECK_EQUAL(*tx.mweb_tx.GetFee(), fee);
    BOOST_CHECK_EQUAL(created->fee, fee);

    wallet->CommitTransaction(created->tx);
    {
        LOCK(::cs_main);
        const auto admitted = Assert(m_node.chainman)->ProcessTransaction(created->tx);
        BOOST_REQUIRE_MESSAGE(admitted.m_result_type == MempoolAcceptResult::ResultType::VALID, admitted.m_state.ToString());
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    std::optional<mw::Coin> external_coin, change_coin;
    {
        LOCK(wallet->cs_wallet);
        for (const mw::Hash& id : tx.mweb_tx.GetOutputIDs()) {
            mw::Coin coin;
            BOOST_REQUIRE(wallet->GetCoin(id, coin));
            BOOST_CHECK(coin.output_id == id);
            BOOST_REQUIRE(coin.address);
            if (coin.IsMine()) {
                BOOST_REQUIRE(!change_coin);
                BOOST_CHECK(coin.IsChange());
                BOOST_CHECK_EQUAL(coin.address_index, mw::CHANGE_INDEX);
                BOOST_CHECK_EQUAL(coin.amount, change_amount);
                BOOST_CHECK(wallet->IsMine(CTxDestination{*coin.address}));
                BOOST_CHECK(wallet->GetMWWallet()->IsChange(*coin.address));
                change_coin = coin;
            } else {
                BOOST_REQUIRE(!external_coin);
                BOOST_CHECK(!coin.IsChange());
                BOOST_CHECK_EQUAL(coin.amount, payment);
                BOOST_CHECK(*coin.address == recipient);
                external_coin = coin;
            }
        }
        BOOST_REQUIRE(external_coin);
        BOOST_REQUIRE(change_coin);
        const auto* stored = wallet->GetWalletTx(tx.GetHash());
        BOOST_REQUIRE(stored);
        BOOST_CHECK(stored->GetTx()->HasMWEBTx());
        BOOST_CHECK(!stored->IsMWEBPlaceholder());
        BOOST_CHECK(stored->GetTx()->GetHash() == tx.GetHash());
        const auto check_entry = [&](const wallet::COutputEntry& entry, const mw::Coin& coin) {
            BOOST_REQUIRE(entry.mweb_out);
            BOOST_CHECK(*entry.mweb_out == coin.output_id);
            BOOST_CHECK_EQUAL(entry.vout, -1);
            BOOST_CHECK_EQUAL(entry.amount, coin.amount);
            BOOST_CHECK(entry.destination == CTxDestination{*coin.address});
        };
        for (int repeat{0}; repeat < 2; ++repeat) {
            BOOST_CHECK_EQUAL(wallet::CachedTxGetDebit(*wallet, *stored, /*avoid_reuse=*/false), input_amount);
            BOOST_CHECK_EQUAL(wallet::CachedTxGetCredit(*wallet, *stored, /*avoid_reuse=*/false), change_amount);
            // CachedTxGetChange sums canonical vout only. MWEB change is
            // asserted through its owned coin metadata and inventory below.
            BOOST_CHECK_EQUAL(wallet::CachedTxGetChange(*wallet, *stored), 0);
            BOOST_CHECK_EQUAL(wallet::CachedTxGetFee(*wallet, *stored), fee);
            BOOST_CHECK_EQUAL(wallet::CachedTxGetAmount(*wallet, *stored), -payment);
            for (const bool include_change : {false, true}) {
                std::list<wallet::COutputEntry> received, sent;
                CAmount listed_fee{-1};
                wallet::CachedTxGetAmounts(*wallet, *stored, received, sent, listed_fee, include_change);
                BOOST_CHECK_EQUAL(listed_fee, fee);
                BOOST_REQUIRE_EQUAL(sent.size(), include_change ? 2U : 1U);
                BOOST_REQUIRE_EQUAL(received.size(), include_change ? 1U : 0U);
                std::set<mw::Hash> sent_ids;
                for (const auto& entry : sent) {
                    BOOST_REQUIRE(entry.mweb_out);
                    BOOST_CHECK(sent_ids.insert(*entry.mweb_out).second);
                    check_entry(entry, *entry.mweb_out == external_coin->output_id ? *external_coin : *change_coin);
                }
                const auto expected_sent = include_change
                    ? std::set<mw::Hash>{external_coin->output_id, change_coin->output_id}
                    : std::set<mw::Hash>{external_coin->output_id};
                BOOST_CHECK(sent_ids == expected_sent);
                if (include_change) check_entry(received.front(), *change_coin);
            }
        }
    }

    MineMWEBEraBlock();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    LOCK(wallet->cs_wallet);
    const auto* confirmed = wallet->GetWalletTx(tx.GetHash());
    BOOST_REQUIRE(confirmed);
    BOOST_CHECK_EQUAL(wallet->GetTxDepthInMainChain(*confirmed), 1);
    std::map<mw::Hash, CAmount> inventory;
    for (const auto& entry : wallet->ListMWEBUnspent(1, 9999999, false, nullptr, 0, MAX_MONEY)) {
        inventory.emplace(entry.output_id, entry.amount);
        if (entry.output_id == change_coin->output_id) {
            BOOST_CHECK(entry.txid == tx.GetHash());
            BOOST_CHECK_EQUAL(entry.depth, 1);
            BOOST_CHECK(entry.safe);
        }
    }
    auto expected_inventory = funding;
    BOOST_REQUIRE_EQUAL(expected_inventory.erase(input_id), 1U);
    BOOST_REQUIRE(expected_inventory.emplace(change_coin->output_id, change_amount).second);
    BOOST_CHECK(inventory == expected_inventory);
    BOOST_CHECK(!inventory.contains(input_id));
    BOOST_CHECK(!inventory.contains(external_coin->output_id));
    BOOST_REQUIRE(inventory.contains(change_coin->output_id));
    BOOST_CHECK_EQUAL(inventory.at(change_coin->output_id), change_amount);
}

// MWEB uses its own inventory/selection APIs, leaving Bitcoin ListCoins untouched.
BOOST_FIXTURE_TEST_CASE(mweb_inventory_keeps_locked_coins_and_selection_filters_depth, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain,
        WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::shared_ptr<wallet::CWallet> shared_wallet{wallet.get(), [](wallet::CWallet*) {}};
    const auto notifications = m_node.chain->handleNotifications(shared_wallet);

    // A warm-up peg-in creates a receive and default MWEB change. Retain those
    // coins in inventory, but lock them to isolate the two receive outputs below.
    const auto baseline = wallet::PegInAndMine(*this, *wallet, 3 * COIN);
    BOOST_REQUIRE(!baseline.empty());
    std::set<mw::Hash> baseline_ids;
    {
        LOCK(wallet->cs_wallet);
        for (const auto& [id, amount] : baseline) {
            baseline_ids.insert(id);
            BOOST_REQUIRE(wallet->LockCoin(id, /*persist=*/false));
        }
    }

    // Explicit transparent change leaves exactly the requested receive on MWEB.
    auto deposit = [&](const CTxDestination& destination, CAmount amount) {
        wallet::CCoinControl coin_control;
        coin_control.m_mweb_peg_in = true;
        coin_control.m_feerate = CFeeRate{10'000};
        coin_control.destChange = wallet::getNewDestination(*wallet, OutputType::BECH32);
        const auto pegin = wallet::CreateTransaction(*wallet, {{destination, amount, /*subtract_fee=*/false}},
            /*change_pos=*/std::nullopt, coin_control);
        BOOST_REQUIRE_MESSAGE(pegin, util::ErrorString(pegin).original);
        BOOST_REQUIRE(!pegin->tx->mweb_tx.GetPegIns().empty());
        BOOST_REQUIRE_EQUAL(pegin->tx->mweb_tx.GetOutputIDs().size(), 1U);
        {
            LOCK(::cs_main);
            const auto accept = Assert(m_node.chainman)->ProcessTransaction(pegin->tx);
            BOOST_REQUIRE_MESSAGE(accept.m_result_type == MempoolAcceptResult::ResultType::VALID, accept.m_state.ToString());
        }
        MineMWEBEraBlock();
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        std::map<mw::Hash, CAmount> coins;
        LOCK(wallet->cs_wallet);
        for (const auto& entry : wallet->ListMWEBUnspent(1, 9999999, false, nullptr, 0, MAX_MONEY)) {
            coins.emplace(entry.output_id, entry.amount);
        }
        return coins;
    };

    const auto small_destination = wallet::getNewDestination(*wallet, OutputType::MWEB);
    const auto first = deposit(small_destination, 5 * COIN);
    BOOST_REQUIRE_EQUAL(first.size(), baseline_ids.size() + 1);
    for (const auto& id : baseline_ids) {
        BOOST_REQUIRE(first.contains(id));
    }
    std::set<mw::Hash> first_deposit;
    for (const auto& [id, amount] : first) {
        if (!baseline_ids.contains(id)) first_deposit.insert(id);
    }
    BOOST_REQUIRE_EQUAL(first_deposit.size(), 1U);
    const auto small_id = *first_deposit.begin();
    BOOST_CHECK_EQUAL(first.at(small_id), 5 * COIN);

    const auto large_destination = wallet::getNewDestination(*wallet, OutputType::MWEB);
    const auto both = deposit(large_destination, 7 * COIN);
    BOOST_REQUIRE_EQUAL(both.size(), first.size() + 1);
    for (const auto& [id, amount] : first) {
        BOOST_REQUIRE(both.contains(id));
        BOOST_CHECK_EQUAL(both.at(id), amount);
    }
    std::set<mw::Hash> second_deposit;
    for (const auto& [id, amount] : both) {
        if (!first.contains(id)) second_deposit.insert(id);
    }
    BOOST_REQUIRE_EQUAL(second_deposit.size(), 1U);
    const auto large_id = *second_deposit.begin();
    BOOST_CHECK_EQUAL(both.at(large_id), 7 * COIN);

    LOCK(wallet->cs_wallet);
    const std::set<CTxDestination> receive_destinations{small_destination, large_destination};
    BOOST_REQUIRE_EQUAL(receive_destinations.size(), 2U);
    BOOST_REQUIRE(wallet->LockCoin(small_id, /*persist=*/false));
    const auto inventory = wallet->ListMWEBUnspent(1, 9999999, false, &receive_destinations, 0, MAX_MONEY);
    BOOST_REQUIRE_EQUAL(inventory.size(), 2U);
    std::set<mw::Hash> ids;
    for (const auto& entry : inventory) {
        ids.insert(entry.output_id);
        BOOST_CHECK_EQUAL(entry.depth, entry.output_id == small_id ? 2 : 1);
        mw::Coin coin;
        BOOST_REQUIRE(wallet->GetCoin(entry.output_id, coin));
        BOOST_REQUIRE(coin.address);
        BOOST_CHECK(entry.address == *coin.address);
        BOOST_CHECK(CTxDestination{entry.address} == (entry.output_id == small_id ? small_destination : large_destination));
    }
    BOOST_CHECK(ids == std::set<mw::Hash>({small_id, large_id}));
    const MWEB::SelectionTargets targets{COIN, COIN};
    const auto unlocked = MWEB::SelectMWEBCoins(*wallet, targets, false, false, 1, 9999999, false);
    BOOST_REQUIRE(unlocked);
    BOOST_REQUIRE_EQUAL(unlocked->coins.size(), 1U);
    BOOST_CHECK(unlocked->coins.begin()->GetMWEBCoin().output_id == large_id);
    BOOST_CHECK(!MWEB::SelectMWEBCoins(*wallet, targets, false, false, 2, 9999999, false));
    BOOST_REQUIRE(wallet->UnlockCoin(small_id));
    const auto deep = MWEB::SelectMWEBCoins(*wallet, targets, false, false, 2, 9999999, false);
    BOOST_REQUIRE(deep);
    BOOST_REQUIRE_EQUAL(deep->coins.size(), 1U);
    BOOST_CHECK(deep->coins.begin()->GetMWEBCoin().output_id == small_id);
    const auto shallow = MWEB::SelectMWEBCoins(*wallet, targets, false, false, 1, 1, false);
    BOOST_REQUIRE(shallow);
    BOOST_REQUIRE_EQUAL(shallow->coins.size(), 1U);
    BOOST_CHECK(shallow->coins.begin()->GetMWEBCoin().output_id == large_id);
}

BOOST_FIXTURE_TEST_CASE(native_funding_preserves_preset_metadata_before_appended_inputs, MWEBRegtest100Setup)
{
    MineToMWEBActivation();
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain,
        WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    LOCK(wallet->cs_wallet);
    const auto available = wallet::AvailableCoins(*wallet).All();
    BOOST_REQUIRE(!available.empty());
    const COutPoint preset = available.front().outpoint;
    constexpr CAmount payment{60 * COIN};
    BOOST_REQUIRE_LT(available.front().txout.nValue, payment);
    const CScript script_sig = CScript{} << OP_TRUE;
    constexpr uint32_t sequence{12345};
    CMutableTransaction draft;
    draft.version = 2;
    draft.nLockTime = 789;
    draft.vin.emplace_back(preset, script_sig, sequence);
    const StealthAddress recipient = StealthAddress::Random();
    const std::vector<wallet::CRecipient> recipients{{recipient, payment, false}};
    wallet::CCoinControl control;
    control.m_allow_other_inputs = true;
    control.m_avoid_partial_spends = true;
    control.m_feerate = CFeeRate{10'000};
    control.fOverrideFeeRate = true;
    // Funding preserves caller-supplied script data without signing or
    // validating that partial script as a complete transaction signature.
    const auto funded = wallet::FundTransaction(*wallet, draft, recipients, std::nullopt,
        /*lockUnspents=*/false, control, /*sign=*/false);
    BOOST_REQUIRE_MESSAGE(funded, util::ErrorString(funded).original);
    const CTransaction& tx = *funded->tx;
    BOOST_CHECK_EQUAL(tx.version, 2);
    BOOST_CHECK_EQUAL(tx.nLockTime, 789U);
    BOOST_REQUIRE_GT(tx.vin.size(), 1U);
    BOOST_CHECK(tx.vin.front().prevout == preset);
    BOOST_CHECK(tx.vin.front().scriptSig == script_sig);
    BOOST_CHECK_EQUAL(tx.vin.front().nSequence, sequence);
    CAmount input_total{0};
    std::set<COutPoint> selected;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CTxIn& input = tx.vin[i];
        BOOST_CHECK(selected.insert(input.prevout).second);
        if (i > 0) {
            BOOST_CHECK(input.prevout != preset);
            BOOST_CHECK(input.scriptSig.empty());
        }
        const auto* previous = wallet->GetWalletTx(input.prevout.hash);
        BOOST_REQUIRE(previous);
        input_total += previous->GetTx()->vout.at(input.prevout.n).nValue;
        BOOST_CHECK(!wallet->IsLockedCoin(input.prevout));
    }
    BOOST_CHECK(funded->mweb_tx.inputs.empty());
    BOOST_REQUIRE_EQUAL(funded->mweb_tx.kernels.size(), 1U);
    BOOST_REQUIRE(funded->mweb_tx.kernels.front().pegin);
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 1U);
    BOOST_CHECK(tx.vout.front().scriptPubKey.IsMWEBPegin());
    BOOST_CHECK_EQUAL(tx.vout.front().nValue, *funded->mweb_tx.kernels.front().pegin);
    BOOST_CHECK(!funded->change_pos);
    BOOST_REQUIRE(funded->mweb_change_index);
    BOOST_REQUIRE_EQUAL(funded->mweb_tx.outputs.size(), 2U);
    CAmount output_total{0};
    size_t payments{0};
    for (const auto& output : funded->mweb_tx.outputs) {
        BOOST_REQUIRE(output.amount && output.address);
        output_total += *output.amount;
        if (*output.address == recipient) {
            ++payments;
            BOOST_CHECK_EQUAL(*output.amount, payment);
        }
    }
    BOOST_CHECK_EQUAL(payments, 1U);
    BOOST_CHECK_GT(funded->fee, 0);
    BOOST_CHECK_EQUAL(input_total, output_total + funded->fee);
}

BOOST_AUTO_TEST_SUITE_END()
