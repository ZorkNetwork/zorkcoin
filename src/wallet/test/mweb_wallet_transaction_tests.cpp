// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/transaction.h>
#include <wallet/receive.h>
#include <wallet/walletdb.h>
#include <chainparams.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <kernel/chain.h>
#include <kernel/mempool_removal_reason.h>
#include <mw/consensus/aggregation.h>
#include <mweb/mweb_spend.h>
#include <mweb/mweb_wallet.h>
#include <mweb/mweb_wallet_types.h>
#include <mw/models/block/block.h>
#include <mw/models/block/header.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/output.h>
#include <mw/models/wallet/coin.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/wallet/keychain.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <serialize.h>
#include <streams.h>
#include <util/btcsignals.h>
#include <util/strencodings.h>
#include <test_framework/models/tx.h>
#include <test_framework/tx_builder.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <map>

namespace wallet {
namespace {
struct FrozenMWEBWalletTestingSetup : WalletTestingSetup {
    FrozenMWEBWalletTestingSetup() : WalletTestingSetup(ChainType::REGTEST) {}
};

CTransactionRef NativeMWEBTransaction(const test::Tx& transaction)
{
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*transaction.GetTransaction());
    return MakeTransactionRef(std::move(tx));
}

// Exercise native cached accounting and component/inventory accounting together.
// The cached change helper is L1-only, and sent MWEB credit counts change only.
void CheckNativeBridgeAccounting(CWallet& wallet, bool l1_input, bool pegout)
{
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();
    wallet.SetLastBlockProcessed(10, uint256::ONE);
    const auto destination = wallet.GetNewDestination(OutputType::MWEB, "self");
    BOOST_REQUIRE(destination);
    const auto address = std::get<StealthAddress>(*destination);
    constexpr CAmount input_amount{3 * COIN};
    constexpr CAmount mw_fee{1000};
    const CAmount l1_fee = l1_input ? 2000 : 0;
    const CAmount payment = input_amount - l1_fee - mw_fee;
    const CAmount change = !l1_input && pegout ? COIN : 0;
    const CTxDestination recipient{WitnessV0KeyHash{uint160{}}};
    mw::Coin source;
    COutPoint l1_source;
    if (l1_input) {
        const auto l1_destination = wallet.GetNewDestination(OutputType::BECH32, "source");
        BOOST_REQUIRE(l1_destination);
        CMutableTransaction funding;
        funding.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{2}), 0});
        funding.vout.emplace_back(input_amount, GetScriptForDestination(*l1_destination));
        const auto tx = MakeTransactionRef(std::move(funding));
        BOOST_REQUIRE(wallet.AddToWallet(tx, TxStateConfirmed{uint256::ONE, 5, 0}));
        l1_source = COutPoint{tx->GetHash(), 0};
    } else {
        const auto funding = test::TxBuilder().AddPeginKernel(input_amount)
            .AddOutput(input_amount, SecretKey::Random(), address).Build();
        BOOST_REQUIRE(wallet.GetMWWallet()->RewindOutput(funding.GetOutputs().front().GetOutput(), source));
        BOOST_REQUIRE(source.HasSpendMaterial());
        BOOST_REQUIRE(wallet.AddToWallet(NativeMWEBTransaction(funding), TxStateConfirmed{uint256::ONE, 5, 0}));
    }

    test::TxBuilder builder;
    if (l1_input) {
        builder.AddPeginKernel(input_amount - l1_fee);
    } else {
        builder.AddInput(source.amount, *source.spend_key, *source.blind, source.output_id);
    }
    if (pegout) {
        builder.AddPegoutKernel({PegOutCoin{payment - change, GetScriptForDestination(recipient)}}, mw_fee);
        if (change) {
            auto* account = wallet.GetExternalMWEBScriptPubKeyMan();
            BOOST_REQUIRE(account);
            StealthAddress change_address;
            BOOST_REQUIRE(wallet.GetMWEBChangeAddress(*account, change_address));
            builder.AddOutput(change, SecretKey::Random(), change_address);
        }
    } else {
        builder.AddOutput(payment, SecretKey::Random(), address);
        builder.AddPlainKernel(mw_fee);
    }
    const auto spend = builder.Build();
    BOOST_CHECK_NO_THROW(spend.GetTransaction()->Validate());
    for (const auto& output : spend.GetOutputs()) {
        mw::Coin coin;
        BOOST_REQUIRE(wallet.GetMWWallet()->RewindOutput(output.GetOutput(), coin));
    }
    CMutableTransaction mutable_tx;
    mutable_tx.mweb_tx = mw::MutableTx::From(*spend.GetTransaction());
    if (l1_input) {
        mutable_tx.vin.emplace_back(l1_source);
        const auto pegins = mutable_tx.mweb_tx.GetPegIns();
        BOOST_REQUIRE_EQUAL(pegins.size(), 1U);
        mutable_tx.vout.emplace_back(input_amount - l1_fee, GetScriptForPegin(pegins.front().GetKernelID()));
    }
    const auto* wtx = wallet.AddToWallet(MakeTransactionRef(std::move(mutable_tx)), TxStateConfirmed{uint256::ONE, 10, 0});
    BOOST_REQUIRE(wtx);
    BOOST_CHECK_EQUAL(CachedTxGetDebit(wallet, *wtx, false), input_amount);
    BOOST_CHECK_EQUAL(CachedTxGetCredit(wallet, *wtx, false), change);
    BOOST_CHECK_EQUAL(CachedTxGetChange(wallet, *wtx), 0);
    BOOST_CHECK_EQUAL(CachedTxGetFee(wallet, *wtx), l1_fee + mw_fee);
    std::list<COutputEntry> received, sent;
    CAmount fee{-1};
    CachedTxGetAmounts(wallet, *wtx, received, sent, fee, false);
    BOOST_CHECK_EQUAL(fee, l1_fee + mw_fee);
    BOOST_REQUIRE_EQUAL(sent.size(), 1U);
    BOOST_CHECK_EQUAL(sent.front().amount, payment - change);
    BOOST_CHECK(sent.front().destination == (pegout ? recipient : *destination));
    BOOST_REQUIRE(sent.front().mweb_out);
    if (pegout) {
        BOOST_CHECK(received.empty());
        BOOST_CHECK(sent.front().mweb_out->IsZero());
    } else {
        BOOST_REQUIRE_EQUAL(received.size(), 1U);
        BOOST_CHECK(received.front().mweb_out == sent.front().mweb_out);
        BOOST_CHECK_EQUAL(received.front().amount, payment);
        // Native self-send history has matching send/receive components; their
        // sum plus the fee is the fee-only net, independent of cached credit.
        BOOST_CHECK_EQUAL(received.front().amount - sent.front().amount - fee, -fee);
    }
    const auto unspent = wallet.ListMWEBUnspent(0, 999, true, nullptr, 0, MAX_MONEY);
    const CAmount available = pegout ? change : payment;
    BOOST_REQUIRE_EQUAL(unspent.size(), available ? 1U : 0U);
    if (available) {
        BOOST_CHECK_EQUAL(unspent.front().amount, available);
        BOOST_CHECK(wtx->GetTx()->mweb_tx.GetOutputIDs().contains(unspent.front().output_id));
        BOOST_CHECK_EQUAL(wallet.GetMWWallet()->IsChange(unspent.front().address), change != 0);
    }
    BOOST_CHECK_EQUAL(GetBalance(wallet, 0, false, false, true).m_mine_trusted, available);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_wallet_transaction_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(mweb_gethash_placeholder_vs_full)
{
    // Placeholder (null L1, no extension): keyed by mweb_wtx_info (Litecoin IsPartialMWEB).
    BlindingFactor blind;
    const StealthAddress addr = StealthAddress::Random();
    const Output output = Output::Create(&blind, SecretKey::Random(), addr, COIN);
    mw::Coin coin;
    coin.address_index = 1;
    coin.address = addr;
    coin.amount = COIN;
    coin.output_id = output.GetOutputID();

    CTransactionRef empty_tx = MakeTransactionRef(CMutableTransaction{});
    BOOST_REQUIRE(empty_tx->IsNull());
    BOOST_REQUIRE(!empty_tx->HasMWEBTx());
    CWalletTx placeholder{empty_tx, TxStateInactive{}};
    placeholder.mweb_wtx_info = MWEB::WalletTxInfo{coin};
    BOOST_CHECK(placeholder.GetHash() == Txid::FromUint256(placeholder.mweb_wtx_info->GetHash()));
    // Domain separation: neither receive nor spend placeholder keys by raw output_id.
    const Txid raw_output_key = Txid::FromUint256(uint256(coin.output_id.vec()));
    BOOST_CHECK(placeholder.GetHash() != raw_output_key);
    // Receive placeholder must not collide with a spend placeholder for the same output_id.
    CWalletTx spend_ph{empty_tx, TxStateInactive{}};
    spend_ph.mweb_wtx_info = MWEB::WalletTxInfo{coin.output_id};
    BOOST_CHECK(spend_ph.GetHash() != placeholder.GetHash());
    BOOST_CHECK(spend_ph.GetHash() != raw_output_key);
    BOOST_CHECK(spend_ph.mweb_wtx_info->GetHash() != placeholder.mweb_wtx_info->GetHash());

    // Full MWEB-only tx is also IsNull() but must keep tx->GetHash() even with mweb_wtx_info attached.
    CMutableTransaction mtx;
    mtx.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(COIN).GetTransaction());
    CTransactionRef mweb_tx = MakeTransactionRef(std::move(mtx));
    BOOST_REQUIRE(mweb_tx->HasMWEBTx());
    BOOST_REQUIRE(mweb_tx->IsNull());
    CWalletTx full{mweb_tx, TxStateInactive{}};
    full.mweb_wtx_info = MWEB::WalletTxInfo{coin};
    BOOST_CHECK(full.GetHash() == mweb_tx->GetHash());
    BOOST_CHECK(full.GetHash() != Txid::FromUint256(full.mweb_wtx_info->GetHash()));
}

BOOST_AUTO_TEST_CASE(mweb_placeholder_serialization_roundtrip)
{
    BlindingFactor blind;
    const StealthAddress addr = StealthAddress::Random();
    const Output output = Output::Create(&blind, SecretKey::Random(), addr, COIN);
    mw::Coin coin;
    coin.address_index = 1;
    coin.address = addr;
    coin.amount = COIN;
    coin.output_id = output.GetOutputID();

    CWalletTx placeholder{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
    placeholder.mweb_wtx_info = MWEB::WalletTxInfo{coin};
    BOOST_REQUIRE(placeholder.IsMWEBPlaceholder());
    DataStream ss;
    ss << placeholder;

    CWalletTx loaded{deserialize, ss, /*variants=*/{}};
    BOOST_REQUIRE(loaded.mweb_wtx_info);
    BOOST_CHECK(loaded.IsMWEBPlaceholder());
    BOOST_CHECK(loaded.GetHash() == placeholder.GetHash());

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(COIN, CScript() << OP_TRUE);
    CTransactionRef full_tx = MakeTransactionRef(std::move(mtx));
    loaded.ReplaceMWEBPlaceholder(full_tx);
    BOOST_CHECK(!loaded.IsMWEBPlaceholder());
    BOOST_CHECK(loaded.GetHash() == full_tx->GetHash());
    BOOST_CHECK_EQUAL(loaded.GetTxs().size(), 1U);
}

BOOST_AUTO_TEST_CASE(mweb_confirmed_state_roundtrip_uses_native_position_contract)
{
    const uint256 block_hash{uint256{2}};
    const auto full = NativeMWEBTransaction(test::Tx::CreatePegIn(COIN));
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    const auto output_ids = full->mweb_tx.GetOutputIDs();
    BOOST_REQUIRE(!output_ids.empty());
    mw::Coin coin;
    coin.output_id = *output_ids.begin();
    coin.amount = COIN;
    const std::vector<std::optional<MWEB::WalletTxInfo>> records{
        std::nullopt, MWEB::WalletTxInfo{coin, 7}, MWEB::WalletTxInfo{coin.output_id, 7}};
    for (const auto& info : records) {
        // Extension scans use native confirmed position zero. It identifies
        // confirmed state, not an MWEB transaction's canonical block-array slot.
        CWalletTx original{info ? empty : full, TxStateConfirmed{block_hash, 123, 0}};
        original.mweb_wtx_info = info;
        const Txid id = original.GetHash();
        DataStream stream;
        stream << original;
        CWalletTx loaded{deserialize, stream, /*variants=*/{}};
        BOOST_CHECK(stream.empty());
        BOOST_CHECK(loaded.GetHash() == id);
        BOOST_CHECK_EQUAL(loaded.IsMWEBPlaceholder(), info.has_value());
        const auto* confirmed = loaded.state<TxStateConfirmed>();
        BOOST_REQUIRE(confirmed);
        BOOST_CHECK(confirmed->confirmed_block_hash == block_hash);
        BOOST_CHECK_EQUAL(confirmed->position_in_block, 0);
        // Block height is filled from the chain after loading, not persisted.
        BOOST_CHECK_EQUAL(confirmed->confirmed_block_height, -1);
        BOOST_CHECK_EQUAL(TxStateSerializedIndex(loaded.m_state), 0);
        BOOST_CHECK(TxStateSerializedBlockHash(loaded.m_state) == block_hash);
        if (info) {
            BOOST_REQUIRE(loaded.mweb_wtx_info);
            BOOST_CHECK(loaded.mweb_wtx_info->GetHash() == info->GetHash());
            BOOST_CHECK(loaded.mweb_wtx_info->leaf_index == info->leaf_index);
        }
    }

    const TxState positioned = TxStateInterpretSerialized({block_hash, 3});
    BOOST_REQUIRE(std::get_if<TxStateConfirmed>(&positioned));
    BOOST_CHECK_EQUAL(std::get<TxStateConfirmed>(positioned).position_in_block, 3);
    const TxState conflicted = TxStateInterpretSerialized({block_hash, -1});
    BOOST_REQUIRE(std::get_if<TxStateBlockConflicted>(&conflicted));
    // Native negative indices other than the conflict marker stay unrecognized;
    // Litecoin's separate no-position sentinel is deliberately not introduced.
    for (const int index : {-2, -3}) {
        const TxState unknown = TxStateInterpretSerialized({block_hash, index});
        BOOST_REQUIRE(std::get_if<TxStateUnrecognized>(&unknown));
        BOOST_CHECK(TxStateSerializedBlockHash(unknown) == block_hash);
        BOOST_CHECK_EQUAL(TxStateSerializedIndex(unknown), index);
    }
}

// A full body may replace several independently discovered receive records.
BOOST_AUTO_TEST_CASE(full_mweb_transaction_coalesces_partial_receives)
{
    const auto first = test::Tx::CreatePegIn(COIN).GetTransaction();
    const auto second = test::Tx::CreatePegIn(2 * COIN).GetTransaction();
    const auto combined = Aggregation::Aggregate({first, second});
    CMutableTransaction mutable_tx;
    mutable_tx.mweb_tx = mw::MutableTx::From(*combined);
    const auto full = MakeTransactionRef(std::move(mutable_tx));
    BOOST_REQUIRE(full->HasMWEBTx());
    BOOST_REQUIRE(full->IsNull());
    BOOST_REQUIRE_EQUAL(full->mweb_tx.GetOutputIDs().size(), 2U);

    LOCK(m_wallet.cs_wallet);
    std::vector<Txid> partial_keys;
    int64_t earliest_order = -1;
    for (const auto& output_id : full->mweb_tx.GetOutputIDs()) {
        mw::Coin coin;
        coin.output_id = output_id;
        coin.amount = COIN;
        auto* partial = m_wallet.AddToWallet(MakeTransactionRef(CMutableTransaction{}),
            TxStateInactive{}, nullptr, false, MWEB::WalletTxInfo{coin});
        BOOST_REQUIRE(partial);
        partial_keys.push_back(partial->GetHash());
        if (earliest_order == -1) {
            earliest_order = partial->nOrderPos;
            partial->m_comment = "preserved receive metadata";
        }
    }
    BOOST_REQUIRE_EQUAL(m_wallet.mapWallet.size(), 2U);
    auto* upgraded = m_wallet.AddToWallet(full, TxStateInMempool{});
    BOOST_REQUIRE(upgraded);
    BOOST_CHECK(upgraded->GetHash() == full->GetHash());
    BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 1U);
    BOOST_CHECK_EQUAL(upgraded->nOrderPos, earliest_order);
    BOOST_REQUIRE(upgraded->m_comment);
    BOOST_CHECK_EQUAL(*upgraded->m_comment, "preserved receive metadata");
    BOOST_CHECK_EQUAL(m_wallet.wtxOrdered.size(), 1U);
    for (const auto& output_id : full->mweb_tx.GetOutputIDs()) {
        BOOST_CHECK(m_wallet.FindWalletTxByOutputId(output_id) == upgraded);
    }
    for (const auto& kernel_id : full->mweb_tx.GetKernelIDs()) {
        BOOST_CHECK(m_wallet.FindWalletTxByKernelId(kernel_id) == upgraded);
    }
    auto batch = m_wallet.GetDatabase().MakeBatch();
    for (const auto& key : partial_keys) {
        BOOST_CHECK(!m_wallet.mapWallet.contains(key));
        BOOST_CHECK(!batch->Exists(std::make_pair(DBKeys::TX, key)));
    }
    BOOST_CHECK(batch->Exists(std::make_pair(DBKeys::TX, full->GetHash())));
    BOOST_CHECK(m_wallet.AddToWallet(full, TxStateInMempool{}) == upgraded);
    BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 1U);
}

// The persistent spend index is distinct from a spend active in chain/mempool.
BOOST_AUTO_TEST_CASE(native_self_send_accounting)
{
    CheckNativeBridgeAccounting(m_wallet, false, false);
}
BOOST_AUTO_TEST_CASE(native_pegin_self_accounting)
{
    CheckNativeBridgeAccounting(m_wallet, true, false);
}
BOOST_AUTO_TEST_CASE(native_pegout_accounting)
{
    CheckNativeBridgeAccounting(m_wallet, false, true);
}
BOOST_AUTO_TEST_CASE(native_pegin_pegout_accounting)
{
    CheckNativeBridgeAccounting(m_wallet, true, true);
}

BOOST_AUTO_TEST_CASE(partial_mweb_spend_does_not_invent_a_fee)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "source");
    BOOST_REQUIRE(destination);
    constexpr CAmount amount{3 * COIN};
    const auto funding = test::TxBuilder().AddPeginKernel(amount)
        .AddOutput(amount, SecretKey::Random(), std::get<StealthAddress>(*destination)).Build();
    mw::Coin coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(funding.GetOutputs().front().GetOutput(), coin));
    m_wallet.SetLastBlockProcessed(10, uint256::ONE);
    BOOST_REQUIRE(m_wallet.AddToWallet(NativeMWEBTransaction(funding), TxStateConfirmed{uint256::ONE, 5, 0}));
    BOOST_CHECK_EQUAL(GetBalance(m_wallet, 0, false, false, true).m_mine_trusted, amount);
    const auto* spent = m_wallet.AddToWallet(MakeTransactionRef(CMutableTransaction{}),
        TxStateConfirmed{uint256::ONE, 10, 0}, nullptr, false, MWEB::WalletTxInfo{coin.output_id});
    BOOST_REQUIRE(spent && spent->IsMWEBPlaceholder());
    BOOST_CHECK_EQUAL(CachedTxGetDebit(m_wallet, *spent, false), amount);
    BOOST_CHECK_EQUAL(CachedTxGetCredit(m_wallet, *spent, false), 0);
    BOOST_CHECK_EQUAL(CachedTxGetChange(m_wallet, *spent), 0);
    BOOST_CHECK_EQUAL(CachedTxGetFee(m_wallet, *spent), 0);
    std::list<COutputEntry> received, sent;
    CAmount fee{-1};
    CachedTxGetAmounts(m_wallet, *spent, received, sent, fee, false);
    BOOST_CHECK(sent.empty() && received.empty());
    BOOST_CHECK_EQUAL(fee, 0);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet, 0, false, false, true).m_mine_trusted, 0);
    BOOST_CHECK(m_wallet.ListMWEBUnspent(0, 999, true, nullptr, 0, MAX_MONEY).empty());
    const Txid partial_id = spent->GetHash();
    constexpr CAmount actual_fee{1000};
    const auto full = test::TxBuilder().AddInput(coin.amount, *coin.spend_key, *coin.blind, coin.output_id)
        .AddOutput(amount - actual_fee, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(actual_fee).Build();
    const auto* upgraded = m_wallet.AddToWallet(NativeMWEBTransaction(full), TxStateConfirmed{uint256::ONE, 10, 0});
    BOOST_REQUIRE(upgraded && !upgraded->IsMWEBPlaceholder());
    BOOST_CHECK(!m_wallet.mapWallet.contains(partial_id));
    BOOST_CHECK_EQUAL(CachedTxGetDebit(m_wallet, *upgraded, false), amount);
    BOOST_CHECK_EQUAL(CachedTxGetCredit(m_wallet, *upgraded, false), 0);
    BOOST_CHECK_EQUAL(CachedTxGetFee(m_wallet, *upgraded), actual_fee);
}

BOOST_AUTO_TEST_CASE(partial_mweb_spend_tracks_wallet_state_transitions)
{
    const auto funding = test::Tx::CreatePegIn(COIN).GetTransaction();
    const auto output_id = funding->GetOutputs().front().GetOutputID();
    const MWEB::WalletTxInfo info{output_id};
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetLastBlockProcessed(10, uint256::ONE);
    const std::vector<std::pair<TxState, bool>> states{
        {TxStateConfirmed{uint256::ONE, 5, 0}, true},
        {TxStateInactive{}, false},
        {TxStateInMempool{}, true},
        {TxStateBlockConflicted{uint256::ONE, 5}, false},
        {TxStateInactive{true}, false},
        {TxStateConfirmed{uint256::ONE, 5, 0}, true},
    };
    for (const auto& [state, active_spend] : states) {
        const auto* spend = m_wallet.AddToWallet(empty, state, nullptr, false, info);
        BOOST_REQUIRE(spend);
        BOOST_CHECK(spend->IsMWEBPlaceholder());
        BOOST_CHECK(m_wallet.IsSpentMWEB(output_id));
        BOOST_CHECK_EQUAL(m_wallet.IsSpentMWEBInChainOrMempool(output_id), active_spend);
        BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 1U);
    }
}

BOOST_AUTO_TEST_CASE(partial_mweb_receive_accounting_tracks_pending_and_confirmed_state)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "receive");
    BOOST_REQUIRE(destination);
    const auto* address = std::get_if<StealthAddress>(&*destination);
    BOOST_REQUIRE(address);
    constexpr CAmount amount{123'456'789};
    const auto funding = test::TxBuilder().AddPeginKernel(amount)
        .AddOutput(amount, SecretKey::Random(), *address).Build();
    const Output& output = funding.GetOutputs().front().GetOutput();
    mw::Coin coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, coin));
    BOOST_REQUIRE(coin.IsMine());
    const MWEB::WalletTxInfo info{coin};
    const Txid receive_key = Txid::FromUint256(info.GetHash());
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    CTransactionRef transaction{empty};
    Txid expected_key{receive_key};
    bool expect_partial{true};
    m_wallet.SetLastBlockProcessed(10, uint256::ONE);

    const auto check_state = [&](const TxState& state, int depth, bool available, bool trusted, bool pending) {
        LOCK(m_wallet.cs_wallet);
        const auto* received = m_wallet.AddToWallet(transaction, state, nullptr, false,
            expect_partial ? std::make_optional(info) : std::nullopt);
        BOOST_REQUIRE(received);
        BOOST_REQUIRE_EQUAL(received->IsMWEBPlaceholder(), expect_partial);
        BOOST_CHECK(received->GetHash() == expected_key);
        BOOST_CHECK_EQUAL(m_wallet.GetTxDepthInMainChain(*received), depth);
        BOOST_CHECK_EQUAL(CachedTxGetCredit(m_wallet, *received, /*avoid_reuse=*/false), amount);
        BOOST_CHECK_EQUAL(CachedTxGetDebit(m_wallet, *received, /*avoid_reuse=*/false), 0);
        BOOST_CHECK_EQUAL(CachedTxGetChange(m_wallet, *received), 0);
        BOOST_CHECK_EQUAL(CachedTxGetFee(m_wallet, *received), 0);
        BOOST_CHECK_EQUAL(CachedTxGetAmount(m_wallet, *received), amount);
        BOOST_CHECK_EQUAL(CachedTxIsTrusted(m_wallet, *received), trusted);
        for (const bool include_change : {false, true}) {
            std::list<COutputEntry> received_amounts, sent_amounts;
            CAmount fee{-1};
            CachedTxGetAmounts(m_wallet, *received, received_amounts, sent_amounts, fee, include_change);
            BOOST_REQUIRE_EQUAL(received_amounts.size(), 1U);
            BOOST_CHECK(sent_amounts.empty());
            BOOST_CHECK_EQUAL(fee, 0);
            const auto& entry = received_amounts.front();
            BOOST_CHECK(entry.destination == *destination);
            BOOST_CHECK_EQUAL(entry.amount, amount);
            BOOST_CHECK_EQUAL(entry.vout, -1);
            BOOST_REQUIRE(entry.mweb_out);
            BOOST_CHECK(*entry.mweb_out == output.GetOutputID());
        }
        const auto unspent = m_wallet.ListMWEBUnspent(0, 999, /*include_unsafe=*/true, nullptr, 0, MAX_MONEY);
        BOOST_REQUIRE_EQUAL(unspent.size(), available ? 1U : 0U);
        if (available) {
            BOOST_CHECK(unspent.front().output_id == output.GetOutputID());
            BOOST_CHECK(unspent.front().txid == expected_key);
            BOOST_CHECK_EQUAL(unspent.front().amount, amount);
            BOOST_CHECK_EQUAL(unspent.front().depth, depth);
            BOOST_CHECK_EQUAL(unspent.front().safe, trusted);
        }
        const Balance balance = GetBalance(m_wallet, 0, /*avoid_reuse=*/false,
            /*include_nonmempool=*/false, /*include_mweb=*/true);
        BOOST_CHECK_EQUAL(balance.m_mine_trusted, trusted ? amount : 0);
        BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, pending ? amount : 0);
        BOOST_CHECK_EQUAL(balance.m_mine_immature, 0);
        const Balance l1_balance = GetBalance(m_wallet);
        BOOST_CHECK_EQUAL(l1_balance.m_mine_trusted, 0);
        BOOST_CHECK_EQUAL(l1_balance.m_mine_untrusted_pending, 0);
        BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 1U);
        BOOST_CHECK_EQUAL(m_wallet.wtxOrdered.size(), 1U);
    };

    check_state(TxStateInMempool{}, 0, /*available=*/true, /*trusted=*/false, /*pending=*/true);
    check_state(TxStateConfirmed{uint256::ONE, 5, 0}, 6, /*available=*/true, /*trusted=*/true, /*pending=*/false);
    check_state(TxStateInactive{}, 0, /*available=*/false, /*trusted=*/false, /*pending=*/false);
    check_state(TxStateInMempool{}, 0, /*available=*/true, /*trusted=*/false, /*pending=*/true);

    CMutableTransaction mutable_tx;
    mutable_tx.mweb_tx = mw::MutableTx::From(*funding.GetTransaction());
    transaction = MakeTransactionRef(std::move(mutable_tx));
    expected_key = transaction->GetHash();
    expect_partial = false;
    BOOST_REQUIRE(expected_key != receive_key);
    check_state(TxStateConfirmed{uint256::ONE, 5, 0}, 6, /*available=*/true, /*trusted=*/true, /*pending=*/false);
    BOOST_CHECK(!m_wallet.mapWallet.contains(receive_key));
    auto batch = m_wallet.GetDatabase().MakeBatch();
    BOOST_CHECK(!batch->Exists(std::make_pair(DBKeys::TX, receive_key)));
    BOOST_CHECK(batch->Exists(std::make_pair(DBKeys::TX, expected_key)));
    // Repeated full-body delivery cannot create another credit or component.
    check_state(TxStateConfirmed{uint256::ONE, 5, 0}, 6, /*available=*/true, /*trusted=*/true, /*pending=*/false);
}

BOOST_AUTO_TEST_CASE(partial_change_receive_reconstructs_wallet_visible_output)
{
    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;
    const std::shared_ptr<CWallet> shared_wallet{&m_wallet, [](CWallet*) {}};
    const auto interface_wallet = interfaces::MakeWallet(context, shared_wallet);
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    auto* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    StealthAddress address;
    BOOST_REQUIRE(m_wallet.GetMWEBChangeAddress(*account, address));
    constexpr CAmount amount{123'456};
    const Output output = Output::Create(nullptr, SecretKey::Random(), address, amount);
    mw::Coin coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, coin));
    BOOST_REQUIRE(coin.IsMine() && coin.IsChange());
    const MWEB::WalletTxInfo info{coin, 7};
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    m_wallet.SetLastBlockProcessed(10, uint256{3});
    auto* received = m_wallet.AddToWallet(empty, TxStateConfirmed{uint256{2}, 5, 0}, nullptr, false, info);
    BOOST_REQUIRE(received);
    const auto check_record = [&](const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        BOOST_CHECK(wtx.IsMWEBPlaceholder());
        BOOST_CHECK(wtx.GetHash() == Txid::FromUint256(info.GetHash()));
        BOOST_CHECK(wtx.GetTx()->vout.empty());
        BOOST_CHECK(wtx.GetTx()->mweb_tx.GetOutputIDs().empty());
        const auto outputs = WalletTxMWEBReceived(m_wallet, wtx);
        BOOST_REQUIRE_EQUAL(outputs.size(), 1U);
        BOOST_CHECK(outputs.front().first == address);
        BOOST_CHECK(outputs.front().second.output_id == output.GetOutputID());
        BOOST_CHECK_EQUAL(outputs.front().second.amount, amount);
        BOOST_CHECK(outputs.front().second.IsMine());
        BOOST_CHECK(outputs.front().second.IsChange());
        BOOST_CHECK(outputs.front().second.address == address);
        BOOST_CHECK_EQUAL(CachedTxGetCredit(m_wallet, wtx, false), amount);
        BOOST_CHECK_EQUAL(CachedTxGetDebit(m_wallet, wtx, false), 0);
        BOOST_CHECK_EQUAL(CachedTxGetFee(m_wallet, wtx), 0);
        BOOST_CHECK_EQUAL(CachedTxGetAmount(m_wallet, wtx), amount);
        // The generic cached change total remains canonical-only; MWEB
        // classification is carried by the reconstructed output component.
        BOOST_CHECK_EQUAL(CachedTxGetChange(m_wallet, wtx), 0);
    };
    check_record(*received);
    const auto visible = interface_wallet->getWalletTx(received->GetHash());
    BOOST_REQUIRE_EQUAL(visible.mweb_outs.size(), 1U);
    BOOST_CHECK(visible.mweb_outs.front().output_id == output.GetOutputID());
    BOOST_CHECK_EQUAL(visible.mweb_outs.front().amount, amount);
    BOOST_CHECK(visible.mweb_outs.front().address == CTxDestination{address});
    BOOST_CHECK(visible.mweb_outs.front().is_mine && visible.mweb_outs.front().is_change);
    DataStream stream;
    stream << *received;
    CWalletTx loaded{deserialize, stream, /*variants=*/{}};
    BOOST_CHECK(stream.empty());
    check_record(loaded);
}

BOOST_FIXTURE_TEST_CASE(frozen_mweb_receive_retains_credit_but_cannot_fund, FrozenMWEBWalletTestingSetup)
{
    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;
    const std::shared_ptr<CWallet> shared_wallet{&m_wallet, [](CWallet*) {}};
    const auto interface_wallet = interfaces::MakeWallet(context, shared_wallet);

    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "frozen receive");
    BOOST_REQUIRE(destination);
    const auto* address = std::get_if<StealthAddress>(&*destination);
    BOOST_REQUIRE(address);
    constexpr CAmount frozen_amount{COIN};
    constexpr CAmount normal_amount{2 * COIN};
    const Output source = Output::Create(nullptr, SecretKey::Random(), *address, frozen_amount);
    mw::Coin frozen_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(source, frozen_coin));

    const auto& frozen_ids = Params().GetConsensus().frozen_mweb_output_ids;
    BOOST_REQUIRE_EQUAL(frozen_ids.size(), 1U);
    const mw::Hash frozen_id{std::vector<uint8_t>(frozen_ids.front().begin(), frozen_ids.front().end())};
    BOOST_REQUIRE(source.GetOutputID() != frozen_id);
    // Regtest's frozen ID is synthetic. Seed partial-receive metadata for wallet
    // filtering; this does not construct its output preimage or mine a receipt.
    frozen_coin.output_id = frozen_id;
    m_wallet.GetMWWallet()->LoadToWallet(frozen_coin);
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    m_wallet.SetLastBlockProcessed(10, uint256::ONE);
    const auto* received = m_wallet.AddToWallet(empty, TxStateConfirmed{uint256::ONE, 5, 0},
        nullptr, false, MWEB::WalletTxInfo{frozen_coin});
    BOOST_REQUIRE(received);
    const Txid receive_id = received->GetHash();
    BOOST_REQUIRE(MWEB::IsFrozenOutput(frozen_id));
    mw::Coin stored_coin;
    BOOST_REQUIRE(m_wallet.GetCoin(frozen_id, stored_coin));
    BOOST_REQUIRE(stored_coin.IsMine());
    BOOST_REQUIRE(stored_coin.HasSpendMaterial());
    BOOST_REQUIRE_EQUAL(stored_coin.amount, frozen_amount);
    BOOST_REQUIRE(!stored_coin.IsChange());
    StealthAddress stored_address;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->GetStealthAddress(stored_coin, stored_address));
    BOOST_REQUIRE(CTxDestination{stored_address} == *destination);
    BOOST_REQUIRE(!m_wallet.IsLocked());
    BOOST_REQUIRE(!m_wallet.IsLockedCoin(frozen_id));
    BOOST_REQUIRE(!m_wallet.IsSpentMWEBInChainOrMempool(frozen_id));
    BOOST_REQUIRE_EQUAL(m_wallet.GetTxDepthInMainChain(*received), 6);
    BOOST_REQUIRE(CachedTxIsTrusted(m_wallet, *received));

    const auto check_frozen_history = [&]() EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        BOOST_CHECK(m_wallet.FindWalletTxByOutputId(frozen_id) == received);
        BOOST_CHECK_EQUAL(CachedTxGetCredit(m_wallet, *received, /*avoid_reuse=*/false), frozen_amount);
        BOOST_CHECK_EQUAL(CachedTxGetDebit(m_wallet, *received, /*avoid_reuse=*/false), 0);
        BOOST_CHECK_EQUAL(CachedTxGetChange(m_wallet, *received), 0);
        BOOST_CHECK_EQUAL(CachedTxGetFee(m_wallet, *received), 0);
        BOOST_CHECK_EQUAL(CachedTxGetAmount(m_wallet, *received), frozen_amount);
        std::list<COutputEntry> received_amounts, sent_amounts;
        CAmount fee{-1};
        CachedTxGetAmounts(m_wallet, *received, received_amounts, sent_amounts, fee, /*include_change=*/false);
        BOOST_REQUIRE_EQUAL(received_amounts.size(), 1U);
        BOOST_CHECK(sent_amounts.empty());
        BOOST_CHECK_EQUAL(fee, 0);
        const auto& entry = received_amounts.front();
        BOOST_CHECK(entry.destination == *destination);
        BOOST_CHECK_EQUAL(entry.amount, frozen_amount);
        BOOST_CHECK_EQUAL(entry.vout, -1);
        BOOST_REQUIRE(entry.mweb_out);
        BOOST_CHECK(*entry.mweb_out == frozen_id);
        const auto history = interface_wallet->getWalletTx(receive_id);
        BOOST_CHECK_EQUAL(history.credit, frozen_amount);
        BOOST_CHECK_EQUAL(history.debit, 0);
        BOOST_CHECK_EQUAL(history.change, 0);
        BOOST_CHECK_EQUAL(history.fee, 0);
        BOOST_REQUIRE_EQUAL(history.mweb_outs.size(), 1U);
        BOOST_CHECK(history.mweb_outs.front().output_id == frozen_id);
        BOOST_CHECK_EQUAL(history.mweb_outs.front().amount, frozen_amount);
        BOOST_CHECK(history.mweb_outs.front().is_mine);
        BOOST_CHECK(!history.mweb_outs.front().is_change);
        BOOST_CHECK(history.mweb_outs.front().address == *destination);
    };

    mw::Coin normal_coin;
    const auto check_available = [&](bool normal_present) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        const CAmount expected = normal_present ? normal_amount : 0;
        for (const bool include_unsafe : {false, true}) {
            const auto inventory = m_wallet.ListMWEBUnspent(1, 999, include_unsafe, nullptr, 0, MAX_MONEY);
            BOOST_REQUIRE_EQUAL(inventory.size(), normal_present ? 1U : 0U);
            if (normal_present) {
                BOOST_CHECK(inventory.front().output_id == normal_coin.output_id);
                BOOST_CHECK_EQUAL(inventory.front().amount, normal_amount);
                BOOST_CHECK_EQUAL(inventory.front().depth, 6);
                BOOST_CHECK(inventory.front().safe);
            }
            const auto balances = MWEB::GetBalances(m_wallet, 1, 999, include_unsafe);
            BOOST_CHECK_EQUAL(balances.selectable, expected);
            BOOST_CHECK_EQUAL(balances.locked, 0);
            BOOST_CHECK_EQUAL(balances.watch_only, 0);
            const auto selection = MWEB::SelectMWEBCoins(m_wallet, {1, 1}, /*allow_changeless=*/false,
                /*allow_partial=*/false, 1, 999, include_unsafe);
            BOOST_REQUIRE_EQUAL(selection.has_value(), normal_present);
            if (selection) {
                BOOST_REQUIRE_EQUAL(selection->coins.size(), 1U);
                BOOST_CHECK(selection->coins.begin()->GetMWEBCoin().output_id == normal_coin.output_id);
                BOOST_CHECK_EQUAL(selection->total, normal_amount);
            }
        }
        const Balance balance = GetBalance(m_wallet, 1, /*avoid_reuse=*/false,
            /*include_nonmempool=*/false, /*include_mweb=*/true);
        BOOST_CHECK_EQUAL(balance.m_mine_trusted, expected);
        BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, 0);
        BOOST_CHECK_EQUAL(balance.m_mine_immature, 0);
    };

    check_frozen_history();
    check_available(/*normal_present=*/false);
    BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 1U);
    BOOST_CHECK_EQUAL(m_wallet.wtxOrdered.size(), 1U);

    // The genuine output ID is the positive control for the same account,
    // confirmation state and spend material as the synthetic frozen record.
    const Output normal_output = Output::Create(nullptr, SecretKey::Random(), *address, normal_amount);
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(normal_output, normal_coin));
    BOOST_REQUIRE(normal_coin.IsMine());
    BOOST_REQUIRE(normal_coin.HasSpendMaterial());
    BOOST_REQUIRE(!MWEB::IsFrozenOutput(normal_coin.output_id));
    BOOST_REQUIRE(!m_wallet.IsLockedCoin(normal_coin.output_id));
    BOOST_REQUIRE(m_wallet.AddToWallet(empty, TxStateConfirmed{uint256::ONE, 5, 1},
        nullptr, false, MWEB::WalletTxInfo{normal_coin}));
    check_available(/*normal_present=*/true);

    CCoinControl coin_control;
    coin_control.SelectMWEB(frozen_id);
    coin_control.m_allow_other_inputs = true;
    const std::vector<CRecipient> recipients{{StealthAddress::Random(), COIN / 2, /*subtract_fee=*/false}};
    for (const bool require_spend_material : {false, true}) {
        MWEB::FundingState state;
        const auto result = MWEB::TryEarlyFunding(m_wallet, recipients, coin_control, CFeeRate{1000},
            /*subtract_fee_outputs=*/false, COIN / 2, /*sending_to_mweb=*/true, state, require_spend_material);
        BOOST_REQUIRE(!result);
        BOOST_CHECK_EQUAL(util::ErrorString(result).original,
            "MWEB output " + frozen_id.ToHex() + " is frozen and cannot be spent");
        BOOST_CHECK(state.mweb_selected.empty());
        BOOST_CHECK(!state.funded_with_mweb);
    }
    check_frozen_history();
    check_available(/*normal_present=*/true);
    BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 2U);
    BOOST_CHECK_EQUAL(m_wallet.wtxOrdered.size(), 2U);
}

BOOST_FIXTURE_TEST_CASE(mweb_inventory_and_selection_track_combined_wallet_states, FrozenMWEBWalletTestingSetup)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    BOOST_REQUIRE(!m_wallet.IsLocked());
    const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "state matrix");
    BOOST_REQUIRE(destination);
    const auto* address = std::get_if<StealthAddress>(&*destination);
    BOOST_REQUIRE(address);
    const auto* active_account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(active_account);

    // Import a distinct account's scan secret and spend public key. Its coins
    // are genuinely watch-only, rather than signing coins with keys cleared.
    const SecretKey scan_secret = SecretKey::Random();
    CKey scan_key;
    scan_key.Set(scan_secret.vec().begin(), scan_secret.vec().end(), true);
    const PublicKey spend_public = PublicKey::From(SecretKey::Random());
    const std::string watch_descriptor = "mweb(" + EncodeSecret(scan_key) + "," + HexStr(spend_public.vec()) + ",*)";
    FlatSigningProvider watch_keys;
    std::string error;
    auto descriptors = Parse(watch_descriptor, watch_keys, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(descriptors.size() == 1U, error);
    WalletDescriptor descriptor(std::move(descriptors.front()), /*creation_time=*/0,
        /*range_start=*/0, /*range_end=*/3, /*next_index=*/2);
    auto imported = m_wallet.AddWalletDescriptor(descriptor, watch_keys, "", /*internal=*/false);
    BOOST_REQUIRE_MESSAGE(imported, util::ErrorString(imported).original);
    DescriptorScriptPubKeyMan& watch_account = imported->get();
    const auto watch_keychain = WITH_LOCK(watch_account.cs_desc_man, return watch_account.GetMWEBKeychain());
    BOOST_REQUIRE(watch_keychain);
    BOOST_REQUIRE(watch_keychain->HasSpendPubKey());
    BOOST_REQUIRE(!watch_keychain->HasSpendSecret());
    const StealthAddress watch_address = watch_keychain->GetStealthAddress(2);
    BOOST_REQUIRE(m_wallet.IsMine(watch_address));
    BOOST_REQUIRE(m_wallet.GetExternalMWEBScriptPubKeyMan() == active_account);

    const auto empty = MakeTransactionRef(CMutableTransaction{});
    m_wallet.SetLastBlockProcessed(10, uint256::ONE);
    const TxState confirmed{TxStateConfirmed{uint256::ONE, 5, 0}};
    // The output IDs and ownership are real; confirmation/mempool states model
    // wallet notifications without claiming these receipts were chain-validated.
    const auto receive = [&](const StealthAddress& dest, CAmount amount, const TxState& state) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        const Output output = Output::Create(nullptr, SecretKey::Random(), dest, amount);
        mw::Coin coin;
        BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(output, coin));
        BOOST_REQUIRE(coin.IsMine());
        BOOST_REQUIRE_EQUAL(coin.amount, amount);
        BOOST_REQUIRE(coin.output_id == output.GetOutputID());
        BOOST_REQUIRE(!MWEB::IsFrozenOutput(coin.output_id));
        BOOST_REQUIRE(m_wallet.AddToWallet(empty, state, nullptr, false, MWEB::WalletTxInfo{coin}));
        return coin;
    };
    const mw::Coin safe = receive(*address, 2 * COIN, confirmed);
    const mw::Coin unsafe = receive(*address, 3 * COIN, TxStateInMempool{});
    const mw::Coin locked = receive(*address, 5 * COIN, confirmed);
    const mw::Coin spent = receive(*address, 7 * COIN, confirmed);
    const mw::Coin inactive = receive(*address, 11 * COIN, TxStateInactive{});
    const mw::Coin watch = receive(watch_address, 13 * COIN, confirmed);
    for (const auto* coin : {&safe, &unsafe, &locked, &spent, &inactive}) {
        BOOST_REQUIRE(coin->HasSpendMaterial());
        BOOST_REQUIRE(m_wallet.GetMWEBAccountForCoin(*coin) == active_account);
    }
    BOOST_REQUIRE(!watch.HasSpendMaterial());
    BOOST_REQUIRE(!watch.HasSpendKey());
    BOOST_REQUIRE(m_wallet.GetMWEBAccountForCoin(watch) == &watch_account);
    BOOST_REQUIRE(m_wallet.LockCoin(locked.output_id, /*persist=*/false));
    BOOST_REQUIRE(m_wallet.IsLockedCoin(locked.output_id));
    const auto* unsafe_receive = m_wallet.FindWalletTxByOutputId(unsafe.output_id);
    BOOST_REQUIRE(unsafe_receive);
    BOOST_REQUIRE(unsafe_receive->InMempool());
    BOOST_REQUIRE(!CachedTxIsTrusted(m_wallet, *unsafe_receive));
    const auto* inactive_receive = m_wallet.FindWalletTxByOutputId(inactive.output_id);
    BOOST_REQUIRE(inactive_receive);
    BOOST_REQUIRE(inactive_receive->isInactive());
    BOOST_REQUIRE(!inactive_receive->InMempool());

    const auto& frozen_ids = Params().GetConsensus().frozen_mweb_output_ids;
    BOOST_REQUIRE_EQUAL(frozen_ids.size(), 1U);
    mw::Coin frozen = safe;
    // Synthetic frozen-ID metadata only: no valid output preimage or mined
    // receipt is claimed for the configured regtest ID.
    frozen.output_id = mw::Hash{std::vector<uint8_t>(frozen_ids.front().begin(), frozen_ids.front().end())};
    m_wallet.GetMWWallet()->LoadToWallet(frozen);
    BOOST_REQUIRE(m_wallet.AddToWallet(empty, confirmed, nullptr, false, MWEB::WalletTxInfo{frozen}));
    BOOST_REQUIRE(MWEB::IsFrozenOutput(frozen.output_id));
    BOOST_REQUIRE(!m_wallet.IsLockedCoin(frozen.output_id));

    const MWEB::WalletTxInfo spend_info{spent.output_id};
    BOOST_REQUIRE(m_wallet.AddToWallet(empty, TxStateInMempool{}, nullptr, false, spend_info));
    const auto check_matrix = [&](bool active_spend) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        BOOST_REQUIRE(m_wallet.IsSpentMWEB(spent.output_id));
        BOOST_REQUIRE_EQUAL(m_wallet.IsSpentMWEBInChainOrMempool(spent.output_id), active_spend);
        for (const bool include_unsafe : {false, true}) {
            std::map<mw::Hash, CAmount> signed_coins{{safe.output_id, safe.amount}};
            if (!active_spend) signed_coins.emplace(spent.output_id, spent.amount);
            if (include_unsafe) signed_coins.emplace(unsafe.output_id, unsafe.amount);
            auto unsigned_coins = signed_coins;
            unsigned_coins.emplace(watch.output_id, watch.amount);
            auto expected_inventory = unsigned_coins;
            expected_inventory.emplace(locked.output_id, locked.amount);
            std::map<mw::Hash, CAmount> inventory;
            for (const auto& entry : m_wallet.ListMWEBUnspent(0, 999, include_unsafe, nullptr, 0, MAX_MONEY)) {
                BOOST_REQUIRE(inventory.emplace(entry.output_id, entry.amount).second);
                BOOST_CHECK_EQUAL(entry.depth, entry.output_id == unsafe.output_id ? 0 : 6);
                BOOST_CHECK_EQUAL(entry.safe, entry.output_id != unsafe.output_id);
            }
            // Native inventory retains locked and watch-only coins. Funding
            // skips locks; signed funding additionally requires spend material.
            BOOST_CHECK(inventory == expected_inventory);
            for (const bool require_spend_material : {false, true}) {
                const auto& expected = require_spend_material ? signed_coins : unsigned_coins;
                // A target above the entire wallet and allow_partial force the
                // complete eligible set, independent of amount/account ordering.
                const auto selection = MWEB::SelectMWEBCoins(m_wallet, {MAX_MONEY, MAX_MONEY},
                    /*allow_changeless=*/false, /*allow_partial=*/true, 0, 999,
                    include_unsafe, require_spend_material);
                BOOST_REQUIRE(selection);
                std::map<mw::Hash, CAmount> selected;
                for (const auto& coin : selection->coins) {
                    BOOST_REQUIRE(selected.emplace(coin.GetMWEBCoin().output_id, coin.GetAmount()).second);
                }
                BOOST_CHECK(selected == expected);
                CAmount expected_total{0};
                for (const auto& [id, amount] : expected) expected_total += amount;
                BOOST_CHECK_EQUAL(selection->total, expected_total);
                BOOST_CHECK(!selection->changeless);
            }
        }
        const Balance balance = GetBalance(m_wallet, 0, /*avoid_reuse=*/false,
            /*include_nonmempool=*/false, /*include_mweb=*/true);
        BOOST_CHECK_EQUAL(balance.m_mine_trusted,
            safe.amount + locked.amount + watch.amount + (active_spend ? 0 : spent.amount));
        BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, unsafe.amount);
        BOOST_CHECK_EQUAL(balance.m_mine_immature, 0);
        BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 8U);
        BOOST_CHECK_EQUAL(m_wallet.wtxOrdered.size(), 8U);
    };
    check_matrix(/*active_spend=*/true);
    // A historical spend index alone must not suppress the funding coin once
    // that spender is inactive; reconfirming the spender removes it again.
    BOOST_REQUIRE(m_wallet.AddToWallet(empty, TxStateInactive{}, nullptr, false, spend_info));
    check_matrix(/*active_spend=*/false);
    BOOST_REQUIRE(m_wallet.AddToWallet(empty, TxStateConfirmed{uint256::ONE, 6, 1}, nullptr, false, spend_info));
    check_matrix(/*active_spend=*/true);
}

BOOST_AUTO_TEST_CASE(native_mweb_conflicts_include_full_and_partial_spends)
{
    const auto funding = test::Tx::CreatePegIn(3 * COIN);
    const auto spend = [&] {
        return NativeMWEBTransaction(test::TxBuilder().AddInput(funding.GetOutputs().front())
            .AddOutput(3 * COIN - 1000).AddPlainKernel(1000).Build());
    };
    const auto first = spend();
    const auto second = spend();
    const auto unrelated = NativeMWEBTransaction(test::Tx::CreatePegIn(COIN));
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    const MWEB::WalletTxInfo info{funding.GetOutputs().front().GetOutputID()};

    LOCK(m_wallet.cs_wallet);
    BOOST_REQUIRE(m_wallet.AddToWallet(first, TxStateInactive{}));
    BOOST_REQUIRE(m_wallet.AddToWallet(second, TxStateInactive{}));
    BOOST_REQUIRE(m_wallet.AddToWallet(unrelated, TxStateInactive{}));
    const auto* partial = m_wallet.AddToWallet(empty, TxStateInactive{}, nullptr, false, info);
    BOOST_REQUIRE(partial);
    const Txid partial_id{partial->GetHash()};
    BOOST_REQUIRE(partial_id != empty->GetHash());
    const std::set<Txid> all_spenders{first->GetHash(), second->GetHash(), partial_id};
    for (const auto& txid : all_spenders) {
        BOOST_CHECK(m_wallet.GetConflicts(txid) == all_spenders);
        auto expected = all_spenders;
        expected.erase(txid);
        BOOST_CHECK(m_wallet.GetTxConflicts(m_wallet.mapWallet.at(txid)) == expected);
    }
    BOOST_CHECK(m_wallet.GetConflicts(unrelated->GetHash()).empty());
    BOOST_CHECK(m_wallet.GetConflicts(empty->GetHash()).empty());
}

BOOST_AUTO_TEST_CASE(native_mweb_confirmation_conflicts_full_and_partial_descendants)
{
    const auto funding = test::Tx::CreatePegIn(3 * COIN);
    const auto loser_tx = test::TxBuilder().AddInput(funding.GetOutputs().front())
        .AddOutput(3 * COIN - 1000).AddPlainKernel(1000).Build();
    const auto loser = NativeMWEBTransaction(loser_tx);
    const auto child = NativeMWEBTransaction(test::TxBuilder().AddInput(loser_tx.GetOutputs().front())
        .AddOutput(3 * COIN - 2000).AddPlainKernel(1000).Build());
    const auto winner_tx = test::TxBuilder().AddInput(funding.GetOutputs().front())
        .AddOutput(3 * COIN - 2000).AddPlainKernel(2000).Build();
    const auto winner = NativeMWEBTransaction(winner_tx);
    const auto unrelated = NativeMWEBTransaction(test::Tx::CreatePegIn(COIN));
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    const uint256 block_hash{m_rng.rand256()};

    LOCK(m_wallet.cs_wallet);
    m_wallet.SetLastBlockProcessed(10, block_hash);
    for (const auto& tx : {loser, child, winner, unrelated}) {
        BOOST_REQUIRE(m_wallet.AddToWallet(tx, TxStateInactive{}));
    }
    const auto* partial_child = m_wallet.AddToWallet(empty, TxStateInactive{}, nullptr, false,
        MWEB::WalletTxInfo{loser_tx.GetOutputs().front().GetOutputID()});
    BOOST_REQUIRE(partial_child);
    const Txid partial_child_id{partial_child->GetHash()};

    m_wallet.transactionAddedToMempool(winner);
    for (const auto& txid : {loser->GetHash(), child->GetHash(), partial_child_id}) {
        BOOST_CHECK(m_wallet.mapWallet.at(txid).mempool_conflicts == std::set<Txid>{winner->GetHash()});
    }
    BOOST_CHECK(m_wallet.mapWallet.at(unrelated->GetHash()).mempool_conflicts.empty());
    m_wallet.transactionRemovedFromMempool(winner, MemPoolRemovalReason::REPLACED);
    for (const auto& txid : {loser->GetHash(), child->GetHash(), partial_child_id}) {
        BOOST_CHECK(m_wallet.mapWallet.at(txid).mempool_conflicts.empty());
    }
    std::set<Txid> updated;
    const btcsignals::scoped_connection connection{m_wallet.NotifyTransactionChanged.connect(
        [&](const Txid& txid, ChangeType type) {
            if (type == CT_UPDATED) updated.insert(txid);
        })};
    CBlock block;
    const auto header = std::make_shared<mw::Header>(5, mw::Hash{}, mw::Hash{}, mw::Hash{},
        winner_tx.GetKernelOffset(), winner_tx.GetStealthOffset(), 1, 1);
    block.mweb_block = MWEB::Block{std::make_shared<mw::Block>(header, winner_tx.GetTransaction()->GetBody())};
    m_wallet.ScanMWEBExtensionBlock(block, 5, block_hash);

    auto batch = m_wallet.GetDatabase().MakeBatch();
    for (const auto& txid : {loser->GetHash(), child->GetHash(), partial_child_id}) {
        BOOST_CHECK(updated.contains(txid));
        const auto& wtx = m_wallet.mapWallet.at(txid);
        const auto* conflict = wtx.state<TxStateBlockConflicted>();
        BOOST_REQUIRE(conflict);
        BOOST_CHECK(conflict->conflicting_block_hash == block_hash);
        BOOST_CHECK_EQUAL(conflict->conflicting_block_height, 5);
        BOOST_CHECK_EQUAL(m_wallet.GetTxDepthInMainChain(wtx), -6);
        CWalletTx stored{empty, TxStateInactive{}};
        BOOST_REQUIRE(batch->Read(std::make_pair(DBKeys::TX, txid), stored));
        BOOST_REQUIRE(stored.state<TxStateBlockConflicted>());
        BOOST_CHECK(stored.state<TxStateBlockConflicted>()->conflicting_block_hash == block_hash);
        BOOST_CHECK(stored.GetHash() == txid);
    }
    BOOST_CHECK(!updated.contains(unrelated->GetHash()));
    BOOST_CHECK(m_wallet.mapWallet.at(unrelated->GetHash()).isInactive());
    BOOST_CHECK_EQUAL(m_wallet.GetTxDepthInMainChain(m_wallet.mapWallet.at(winner->GetHash())), 6);
    BOOST_CHECK(m_wallet.GetTxConflicts(m_wallet.mapWallet.at(winner->GetHash())) == std::set<Txid>{loser->GetHash()});
    BOOST_CHECK(!m_wallet.IsSpentMWEBInChainOrMempool(loser_tx.GetOutputs().front().GetOutputID()));
}

BOOST_AUTO_TEST_CASE(unknown_mweb_winner_preserves_spend_placeholder_and_disconnects_conflicts)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "conflict");
    BOOST_REQUIRE(destination);
    const auto* address = std::get_if<StealthAddress>(&*destination);
    BOOST_REQUIRE(address);
    const auto funding = test::TxBuilder().AddPeginKernel(3 * COIN)
        .AddOutput(3 * COIN, SecretKey::Random(), *address).Build();
    mw::Coin funding_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(funding.GetOutputs().front().GetOutput(), funding_coin));
    BOOST_REQUIRE(funding_coin.HasSpendMaterial());
    const auto spend = [](const mw::Coin& coin, const StealthAddress& recipient) {
        return test::TxBuilder().AddInput(coin.amount, *coin.spend_key, *coin.blind, coin.output_id)
            .AddOutput(coin.amount - 1000, SecretKey::Random(), recipient).AddPlainKernel(1000).Build();
    };
    const auto loser_tx = spend(funding_coin, *address);
    mw::Coin change_coin;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(loser_tx.GetOutputs().front().GetOutput(), change_coin));
    BOOST_REQUIRE(change_coin.HasSpendMaterial());
    const auto loser = NativeMWEBTransaction(loser_tx);
    const auto child = NativeMWEBTransaction(spend(change_coin, StealthAddress::Random()));
    const auto winner = spend(funding_coin, StealthAddress::Random());
    const auto late_loser = NativeMWEBTransaction(spend(funding_coin, StealthAddress::Random()));
    const auto unrelated = NativeMWEBTransaction(test::Tx::CreatePegIn(COIN));
    const uint256 previous_hash{m_rng.rand256()};
    CBlock block;
    block.hashPrevBlock = previous_hash;
    // Supply the extension body directly to the wallet; block consensus validation is separate.
    const auto header = std::make_shared<mw::Header>(6, mw::Hash{}, mw::Hash{}, mw::Hash{},
        winner.GetKernelOffset(), winner.GetStealthOffset(), 1, 1);
    block.mweb_block = MWEB::Block{std::make_shared<mw::Block>(header, winner.GetTransaction()->GetBody())};
    const uint256 block_hash{block.GetHash()};
    m_wallet.SetLastBlockProcessed(6, block_hash);
    BOOST_REQUIRE(m_wallet.AddToWallet(NativeMWEBTransaction(funding), TxStateConfirmed{previous_hash, 5, 0}));
    for (const auto& tx : {loser, child, unrelated}) {
        BOOST_REQUIRE(m_wallet.AddToWallet(tx, TxStateInactive{}));
    }
    const MWEB::WalletTxInfo spend_info{funding_coin.output_id};
    const Txid spend_id = Txid::FromUint256(spend_info.GetHash());
    std::set<Txid> updated;
    const btcsignals::scoped_connection connection{m_wallet.NotifyTransactionChanged.connect(
        [&](const Txid& txid, ChangeType type) {
            if (type == CT_UPDATED) updated.insert(txid);
        })};
    m_wallet.ScanMWEBExtensionBlock(block, 6, block_hash);

    const auto check_confirmed_spend = [&]() EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        const auto it = m_wallet.mapWallet.find(spend_id);
        BOOST_REQUIRE(it != m_wallet.mapWallet.end());
        BOOST_REQUIRE(it->second.IsMWEBPlaceholder());
        const auto* confirmed = it->second.state<TxStateConfirmed>();
        BOOST_REQUIRE(confirmed);
        BOOST_CHECK(confirmed->confirmed_block_hash == block_hash);
        BOOST_CHECK_EQUAL(confirmed->confirmed_block_height, 6);
        BOOST_CHECK(m_wallet.IsSpentMWEBInChainOrMempool(funding_coin.output_id));
    };
    check_confirmed_spend();
    for (const auto& tx : {loser, child}) {
        BOOST_CHECK(updated.contains(tx->GetHash()));
        const auto* conflict = m_wallet.mapWallet.at(tx->GetHash()).state<TxStateBlockConflicted>();
        BOOST_REQUIRE(conflict);
        BOOST_CHECK(conflict->conflicting_block_hash == block_hash);
        BOOST_CHECK_EQUAL(conflict->conflicting_block_height, 6);
    }
    BOOST_CHECK(!updated.contains(unrelated->GetHash()));
    BOOST_CHECK(m_wallet.GetTxConflicts(m_wallet.mapWallet.at(loser->GetHash())) == std::set<Txid>{spend_id});
    BOOST_CHECK(!m_wallet.mapWallet.contains(NativeMWEBTransaction(winner)->GetHash()));
    BOOST_REQUIRE_EQUAL(m_wallet.mapWallet.size(), 5U);

    // Sharing an input with the unknown winner does not prove this later body is that winner.
    BOOST_REQUIRE(m_wallet.AddToWallet(late_loser, TxStateInactive{}));
    check_confirmed_spend();
    BOOST_CHECK(m_wallet.mapWallet.contains(late_loser->GetHash()));
    m_wallet.ScanMWEBExtensionBlock(block, 6, block_hash);
    check_confirmed_spend();
    BOOST_REQUIRE_EQUAL(m_wallet.mapWallet.size(), 6U);
    BOOST_CHECK(m_wallet.GetTxConflicts(m_wallet.mapWallet.at(spend_id)) ==
        (std::set<Txid>{loser->GetHash(), late_loser->GetHash()}));
    for (const auto& tx : {loser, child, late_loser}) {
        BOOST_CHECK_EQUAL(m_wallet.GetTxDepthInMainChain(m_wallet.mapWallet.at(tx->GetHash())), -1);
    }
    BOOST_CHECK(m_wallet.mapWallet.at(unrelated->GetHash()).isInactive());
    BOOST_CHECK(m_wallet.ListMWEBUnspent(0, 999, true, nullptr, 0, MAX_MONEY).empty());

    interfaces::BlockInfo disconnected{block_hash};
    disconnected.prev_hash = &previous_hash;
    disconnected.height = 6;
    disconnected.data = &block;
    m_wallet.blockDisconnected(disconnected);
    for (const auto& txid : {spend_id, loser->GetHash(), child->GetHash(), late_loser->GetHash()}) {
        BOOST_CHECK(m_wallet.mapWallet.at(txid).isInactive());
    }
    BOOST_CHECK(!m_wallet.IsSpentMWEBInChainOrMempool(funding_coin.output_id));
    const auto unspent = m_wallet.ListMWEBUnspent(0, 999, true, nullptr, 0, MAX_MONEY);
    BOOST_REQUIRE_EQUAL(unspent.size(), 1U);
    BOOST_CHECK(unspent.front().output_id == funding_coin.output_id);
    BOOST_CHECK_EQUAL(unspent.front().depth, 1);
    BOOST_REQUIRE_EQUAL(m_wallet.mapWallet.size(), 6U);
    BOOST_CHECK(!m_wallet.mapWallet.contains(MakeTransactionRef(CMutableTransaction{})->GetHash()));

    // Confirmation in the same block positively identifies the unknown body's
    // spend record, so its later full body can replace that placeholder.
    m_wallet.SetLastBlockProcessed(6, block_hash);
    m_wallet.ScanMWEBExtensionBlock(block, 6, block_hash);
    check_confirmed_spend();
    const int64_t original_order = m_wallet.mapWallet.at(spend_id).nOrderPos;
    const auto full_winner = NativeMWEBTransaction(winner);
    const auto* upgraded = m_wallet.AddToWallet(full_winner, TxStateConfirmed{block_hash, 6, 0});
    BOOST_REQUIRE(upgraded);
    BOOST_CHECK(!upgraded->IsMWEBPlaceholder());
    BOOST_CHECK_EQUAL(upgraded->nOrderPos, original_order);
    BOOST_REQUIRE(upgraded->state<TxStateConfirmed>());
    BOOST_CHECK(upgraded->state<TxStateConfirmed>()->confirmed_block_hash == block_hash);
    BOOST_CHECK(!m_wallet.mapWallet.contains(spend_id));
    BOOST_CHECK(m_wallet.FindWalletTxByKernelId(*full_winner->mweb_tx.GetKernelIDs().begin()) == upgraded);
    BOOST_CHECK(m_wallet.GetTxConflicts(m_wallet.mapWallet.at(loser->GetHash())) ==
        (std::set<Txid>{full_winner->GetHash(), late_loser->GetHash()}));
    BOOST_REQUIRE_EQUAL(m_wallet.mapWallet.size(), 6U);
    const auto batch = m_wallet.GetDatabase().MakeBatch();
    BOOST_CHECK(!batch->Exists(std::make_pair(DBKeys::TX, spend_id)));
    BOOST_CHECK(batch->Exists(std::make_pair(DBKeys::TX, full_winner->GetHash())));
}

BOOST_AUTO_TEST_CASE(partial_mweb_receive_reconfirms_through_extension_scan)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "reconfirm");
    BOOST_REQUIRE(destination);
    const auto* address = std::get_if<StealthAddress>(&*destination);
    BOOST_REQUIRE(address);
    const auto unknown = test::TxBuilder().AddPeginKernel(COIN)
        .AddOutput(COIN, SecretKey::Random(), *address).Build();
    const auto known = test::TxBuilder().AddPeginKernel(2 * COIN)
        .AddOutput(2 * COIN, SecretKey::Random(), *address).Build();
    const auto full = NativeMWEBTransaction(known);
    const auto full_body = full->mweb_tx.m_transaction->Serialized();
    const auto output_id = unknown.GetOutputs().front().GetOutputID();
    mw::Coin identity;
    identity.output_id = output_id;
    const Txid receive_id = Txid::FromUint256(MWEB::WalletTxInfo{identity}.GetHash());
    const auto empty = MakeTransactionRef(CMutableTransaction{});
    const auto aggregate = Aggregation::Aggregate({unknown.GetTransaction(), known.GetTransaction()});
    const uint256 previous_hash{m_rng.rand256()};
    CBlock block;
    block.hashPrevBlock = previous_hash;
    // Wallet notification data exercises scanning; block validation is separate.
    const auto header = std::make_shared<mw::Header>(6, mw::Hash{}, mw::Hash{}, mw::Hash{},
        aggregate->GetKernelOffset(), aggregate->GetStealthOffset(), 2, 2);
    block.mweb_block = MWEB::Block{std::make_shared<mw::Block>(header, aggregate->GetBody())};
    const uint256 block_hash{block.GetHash()};
    m_wallet.SetLastBlockProcessed(6, block_hash);
    BOOST_REQUIRE(m_wallet.AddToWallet(full, TxStateInactive{}));
    m_wallet.ScanMWEBExtensionBlock(block, 6, block_hash);
    BOOST_REQUIRE(m_wallet.mapWallet.contains(receive_id));
    const auto& initial = m_wallet.mapWallet.at(receive_id);
    const int64_t order = initial.nOrderPos;
    const auto received_time = initial.nTimeReceived;
    const auto smart_time = initial.nTimeSmart;

    const auto check_receives = [&](bool confirmed) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
        BOOST_REQUIRE_EQUAL(m_wallet.mapWallet.size(), 2U);
        BOOST_REQUIRE_EQUAL(m_wallet.wtxOrdered.size(), 2U);
        const auto& received = m_wallet.mapWallet.at(receive_id);
        BOOST_REQUIRE(received.IsMWEBPlaceholder());
        BOOST_REQUIRE(received.mweb_wtx_info->received_coin);
        BOOST_CHECK(received.mweb_wtx_info->received_coin->output_id == output_id);
        BOOST_CHECK_EQUAL(received.mweb_wtx_info->received_coin->amount, COIN);
        BOOST_CHECK_EQUAL(received.nOrderPos, order);
        BOOST_CHECK_EQUAL(received.nTimeReceived, received_time);
        BOOST_CHECK_EQUAL(received.nTimeSmart, smart_time);
        BOOST_CHECK(m_wallet.FindWalletTxByOutputId(output_id) == &received);
        BOOST_CHECK(!m_wallet.FindWalletTxByKernelId(unknown.GetKernels().front().GetKernelID()));
        BOOST_CHECK(!m_wallet.mapWallet.contains(NativeMWEBTransaction(unknown)->GetHash()));
        const auto& existing_full = m_wallet.mapWallet.at(full->GetHash());
        BOOST_CHECK(!existing_full.IsMWEBPlaceholder());
        BOOST_CHECK(!existing_full.mweb_wtx_info);
        BOOST_REQUIRE(existing_full.GetTx()->HasMWEBTx());
        BOOST_CHECK(existing_full.GetTx()->mweb_tx.m_transaction->Serialized() == full_body);
        BOOST_CHECK(m_wallet.FindWalletTxByOutputId(known.GetOutputs().front().GetOutputID()) == &existing_full);
        BOOST_CHECK(m_wallet.FindWalletTxByKernelId(known.GetKernels().front().GetKernelID()) == &existing_full);

        const auto batch = m_wallet.GetDatabase().MakeBatch();
        for (const auto& txid : {receive_id, full->GetHash()}) {
            const auto& wtx = m_wallet.mapWallet.at(txid);
            BOOST_CHECK_EQUAL(m_wallet.GetTxDepthInMainChain(wtx), confirmed ? 1 : 0);
            BOOST_REQUIRE_EQUAL(wtx.isConfirmed(), confirmed);
            CWalletTx stored{empty, TxStateInactive{}};
            BOOST_REQUIRE(batch->Read(std::make_pair(DBKeys::TX, txid), stored));
            BOOST_CHECK(stored.GetHash() == txid);
            BOOST_CHECK_EQUAL(stored.nOrderPos, wtx.nOrderPos);
            BOOST_CHECK_EQUAL(stored.nTimeReceived, wtx.nTimeReceived);
            BOOST_CHECK_EQUAL(stored.nTimeSmart, wtx.nTimeSmart);
            BOOST_CHECK_EQUAL(stored.IsMWEBPlaceholder(), wtx.IsMWEBPlaceholder());
            BOOST_REQUIRE_EQUAL(stored.isConfirmed(), confirmed);
            if (confirmed) {
                BOOST_CHECK(wtx.state<TxStateConfirmed>()->confirmed_block_hash == block_hash);
                BOOST_CHECK_EQUAL(wtx.state<TxStateConfirmed>()->confirmed_block_height, 6);
                BOOST_CHECK(stored.state<TxStateConfirmed>()->confirmed_block_hash == block_hash);
            } else {
                BOOST_CHECK(wtx.isInactive());
                BOOST_CHECK(stored.isInactive());
            }
        }
        BOOST_CHECK(!batch->Exists(std::make_pair(DBKeys::TX, empty->GetHash())));
        const auto unspent = m_wallet.ListMWEBUnspent(0, 999, false, nullptr, 0, MAX_MONEY);
        BOOST_CHECK_EQUAL(unspent.size(), confirmed ? 2U : 0U);
        const Balance balance = GetBalance(m_wallet, 0, false, false, true);
        BOOST_CHECK_EQUAL(balance.m_mine_trusted, confirmed ? 3 * COIN : 0);
        BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, 0);
        BOOST_CHECK_EQUAL(balance.m_mine_immature, 0);
    };
    check_receives(true);
    m_wallet.ScanMWEBExtensionBlock(block, 6, block_hash);
    check_receives(true);

    interfaces::BlockInfo disconnected{block_hash};
    disconnected.prev_hash = &previous_hash;
    disconnected.height = 6;
    disconnected.data = &block;
    m_wallet.blockDisconnected(disconnected);
    check_receives(false);

    m_wallet.SetLastBlockProcessed(6, block_hash);
    m_wallet.ScanMWEBExtensionBlock(block, 6, block_hash);
    check_receives(true);
    m_wallet.ScanMWEBExtensionBlock(block, 6, block_hash);
    check_receives(true);
}

BOOST_AUTO_TEST_CASE(repeated_output_id_tracks_occurrences_across_full_and_partial_scans)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "repeated");
    BOOST_REQUIRE(destination);
    const auto* address = std::get_if<StealthAddress>(&*destination);
    BOOST_REQUIRE(address);

    const SecretKey fixed_sender_key = SecretKey::Random();
    const auto create_first = test::TxBuilder().AddPeginKernel(COIN)
        .AddOutput(COIN, fixed_sender_key, *address).Build();
    const auto second_kernel_tx = test::TxBuilder().AddPeginKernel(COIN)
        .AddOutput(COIN, fixed_sender_key, *address).Build();
    const auto create_second_tx = mw::Transaction::Create(
        second_kernel_tx.GetKernelOffset(),
        second_kernel_tx.GetStealthOffset(),
        {},
        {create_first.GetOutputs().front().GetOutput()},
        second_kernel_tx.GetKernels());
    const test::Tx create_second{create_second_tx, create_first.GetOutputs()};
    const mw::Hash output_id = create_first.GetOutputs().front().GetOutputID();
    BOOST_REQUIRE(create_second.GetOutputs().front().GetOutputID() == output_id);
    BOOST_REQUIRE(create_first.GetKernels().front().GetKernelID() !=
                  create_second.GetKernels().front().GetKernelID());

    mw::Coin rewound;
    BOOST_REQUIRE(m_wallet.GetMWWallet()->RewindOutput(create_first.GetOutputs().front().GetOutput(), rewound));
    BOOST_REQUIRE(rewound.HasSpendMaterial());
    const auto spend_first = test::TxBuilder()
        .AddInput(rewound.amount, *rewound.spend_key, *rewound.blind, rewound.output_id)
        .AddOutput(rewound.amount - 1000, SecretKey::Random(), StealthAddress::Random())
        .AddPlainKernel(1000).Build();

    const uint256 genesis_hash{m_rng.rand256()};
    CBlock block5;
    block5.hashPrevBlock = genesis_hash;
    block5.mweb_block = MWEB::Block{std::make_shared<mw::Block>(
        std::make_shared<mw::Header>(5, mw::Hash{}, mw::Hash{}, mw::Hash{},
            create_first.GetKernelOffset(), create_first.GetStealthOffset(), 1, 1),
        create_first.GetTransaction()->GetBody())};
    const uint256 hash5{block5.GetHash()};

    CBlock block6;
    block6.hashPrevBlock = hash5;
    block6.mweb_block = MWEB::Block{std::make_shared<mw::Block>(
        std::make_shared<mw::Header>(6, mw::Hash{}, mw::Hash{}, mw::Hash{},
            spend_first.GetKernelOffset(), spend_first.GetStealthOffset(), 2, 2),
        spend_first.GetTransaction()->GetBody())};
    const uint256 hash6{block6.GetHash()};

    CBlock block7;
    block7.hashPrevBlock = hash6;
    block7.mweb_block = MWEB::Block{std::make_shared<mw::Block>(
        std::make_shared<mw::Header>(7, mw::Hash{}, mw::Hash{}, mw::Hash{},
            create_second.GetKernelOffset(), create_second.GetStealthOffset(), 3, 3),
        create_second.GetTransaction()->GetBody())};
    const uint256 hash7{block7.GetHash()};

    // 1. Extension-only scan across create (h=5, leaf=0) -> spend (h=6) -> recreate (h=7, leaf=2).
    m_wallet.SetLastBlockProcessed(5, hash5);
    m_wallet.ScanMWEBExtensionBlock(block5, 5, hash5);
    m_wallet.SetLastBlockProcessed(6, hash6);
    m_wallet.ScanMWEBExtensionBlock(block6, 6, hash6);
    m_wallet.SetLastBlockProcessed(7, hash7);
    m_wallet.ScanMWEBExtensionBlock(block7, 7, hash7);
    // Repeat scan of both blocks must not assert or corrupt either occurrence.
    m_wallet.ScanMWEBExtensionBlock(block5, 5, hash5, /*rescanning_old_block=*/true);
    m_wallet.ScanMWEBExtensionBlock(block7, 7, hash7, /*rescanning_old_block=*/false);

    const auto matches = m_wallet.FindWalletTxsByOutputId(output_id);
    BOOST_REQUIRE_EQUAL(matches.size(), 2U);
    const CWalletTx* leaf2_wtx = m_wallet.FindWalletTxByOutputId(output_id, 2);
    BOOST_REQUIRE(leaf2_wtx);
    BOOST_REQUIRE(leaf2_wtx->state<TxStateConfirmed>());
    BOOST_CHECK(leaf2_wtx->state<TxStateConfirmed>()->confirmed_block_hash == hash7);
    BOOST_CHECK_EQUAL(leaf2_wtx->state<TxStateConfirmed>()->confirmed_block_height, 7);

    // 2. Full-transaction promotion of the second occurrence preserves the first occurrence.
    const auto full_first = NativeMWEBTransaction(create_first);
    const auto full_second = NativeMWEBTransaction(create_second);
    BOOST_REQUIRE(m_wallet.AddToWallet(full_first, TxStateConfirmed{hash5, 5, 0}));
    BOOST_REQUIRE(m_wallet.AddToWallet(full_second, TxStateConfirmed{hash7, 7, 0}));
    m_wallet.ScanMWEBExtensionBlock(block5, 5, hash5, /*rescanning_old_block=*/true);
    m_wallet.ScanMWEBExtensionBlock(block7, 7, hash7, /*rescanning_old_block=*/false);

    const auto full_matches = m_wallet.FindWalletTxsByOutputId(output_id);
    BOOST_REQUIRE_EQUAL(full_matches.size(), 2U);
    BOOST_CHECK(m_wallet.mapWallet.at(full_first->GetHash()).state<TxStateConfirmed>()->confirmed_block_hash == hash5);
    BOOST_CHECK(m_wallet.mapWallet.at(full_second->GetHash()).state<TxStateConfirmed>()->confirmed_block_hash == hash7);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
