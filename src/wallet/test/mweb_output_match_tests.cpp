// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/tx_body.h>
#include <mw/models/block/block.h>
#include <mw/models/block/header.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/wallet/keychain.h>
#include <mweb/mweb_output_match.h>
#include <mweb/mweb_wallet.h>
#include <primitives/block.h>
#include <util/threadpool.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/scriptpubkeyman.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

namespace wallet {
namespace {

Output PayTo(const StealthAddress& address)
{
    BlindingFactor blind;
    return Output::Create(&blind, SecretKey::Random(), address, COIN);
}

BOOST_FIXTURE_TEST_SUITE(mweb_output_match_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(candidates_match_with_and_without_pool)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.m_mweb_keypool_size = 5;
    m_wallet.SetupDescriptorScriptPubKeyMans();
    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const mw::Keychain::Ptr keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);

    const std::vector<Output> ours{PayTo(keychain->GetStealthAddress(1)), PayTo(keychain->GetStealthAddress(3))};
    std::vector<Output> strangers;
    strangers.reserve(6);
    for (int i = 0; i < 6; ++i) {
        strangers.push_back(PayTo(StealthAddress::Random()));
    }

    // Enough outputs for several chunks; ours sit at multiples of 97.
    std::vector<Output> outputs;
    std::vector<size_t> our_indices;
    for (size_t i = 0; i < 3 * MWEB::OUTPUT_MATCH_CHUNK_SIZE + 11; ++i) {
        if (i % 97 == 0) {
            our_indices.push_back(i);
            outputs.push_back(ours[i % ours.size()]);
        } else {
            outputs.push_back(strangers[i % strangers.size()]);
        }
    }

    const std::vector<SecretKey> secrets{keychain->GetScanSecret(), SecretKey::Random()};
    const std::vector<size_t> serial = MWEB::FindCandidateOutputs(outputs, secrets, nullptr);

    // Base name must stay <=10 chars: ThreadPool workers are named "%s.%02d"
    // and util::ThreadRename requires the full name length <=13.
    ThreadPool pool("mwmatchtst");
    pool.Start(3);
    const std::vector<size_t> parallel = MWEB::FindCandidateOutputs(outputs, secrets, &pool);
    pool.Stop();

    BOOST_CHECK(serial == parallel);
    BOOST_CHECK(std::is_sorted(serial.begin(), serial.end()));
    for (const size_t i : our_indices) {
        BOOST_CHECK(std::binary_search(serial.begin(), serial.end(), i));
    }

    BOOST_CHECK(MWEB::FindCandidateOutputs(outputs, {}, nullptr).empty());
    BOOST_CHECK(MWEB::FindCandidateOutputs({}, secrets, nullptr).empty());

    // The wallet's own entry point agrees, and its pool gives the same answer.
    const MWEB::OutputCandidates from_wallet = m_wallet.GetMWWallet()->FindCandidateOutputs(outputs);
    BOOST_CHECK(from_wallet.indices == MWEB::FindCandidateOutputs(outputs, from_wallet.scan_secrets, nullptr));
    for (const size_t i : our_indices) {
        BOOST_CHECK(std::binary_search(from_wallet.indices.begin(), from_wallet.indices.end(), i));
    }
}

BOOST_AUTO_TEST_CASE(outputs_to_rewind_keeps_known_coins)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.m_mweb_keypool_size = 5;
    m_wallet.SetupDescriptorScriptPubKeyMans();
    DescriptorScriptPubKeyMan* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const mw::Keychain::Ptr keychain = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keychain);

    const std::vector<Output> outputs{PayTo(StealthAddress::Random()), PayTo(keychain->GetStealthAddress(2)), PayTo(StealthAddress::Random())};

    // Pretend the third output is already a wallet coin, and the candidates list missed it.
    mw::Coin known;
    known.output_id = outputs[2].GetOutputID();
    known.amount = COIN;
    m_wallet.GetMWWallet()->LoadToWallet(known);

    MWEB::OutputCandidates precomputed = m_wallet.GetMWWallet()->FindCandidateOutputs(outputs);
    precomputed.indices = {1};
    BOOST_CHECK((m_wallet.GetMWWallet()->OutputsToRewind(outputs, &precomputed) == std::vector<size_t>{1, 2}));

    // Precomputed candidates for other scan secrets are recomputed.
    precomputed.scan_secrets = {SecretKey::Random()};
    precomputed.indices = {};
    const std::vector<size_t> recomputed = m_wallet.GetMWWallet()->OutputsToRewind(outputs, &precomputed);
    BOOST_CHECK(std::binary_search(recomputed.begin(), recomputed.end(), 1u));
    BOOST_CHECK(std::binary_search(recomputed.begin(), recomputed.end(), 2u));
}

BOOST_AUTO_TEST_CASE(extension_scan_retries_an_earlier_output_after_lookahead_moves)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.m_mweb_keypool_size = 2;
    m_wallet.SetupDescriptorScriptPubKeyMans();
    auto* account = m_wallet.GetExternalMWEBScriptPubKeyMan();
    BOOST_REQUIRE(account);
    const auto keys = WITH_LOCK(account->cs_desc_man, return account->GetMWEBKeychain());
    BOOST_REQUIRE(keys);
    const uint32_t next = WITH_LOCK(account->cs_desc_man, return account->GetWalletDescriptor().GetNext());
    const StealthAddress outside_address = keys->GetStealthAddress(next + 3);
    const StealthAddress boundary_address = keys->GetStealthAddress(next + 1);
    BOOST_REQUIRE(!m_wallet.IsMine(outside_address));
    BOOST_REQUIRE(m_wallet.IsMine(boundary_address));
    const Output outside = PayTo(outside_address), boundary = PayTo(boundary_address);
    mw::Coin coin;
    BOOST_CHECK(!m_wallet.GetMWWallet()->RewindOutput(outside, coin));
    BOOST_CHECK(!m_wallet.GetCoin(outside.GetOutputID(), coin));

    CBlock block;
    // Synthetic wallet notification: fix the adverse scan order explicitly.
    // Consensus validation and signed/mined ordering are covered separately.
    const auto header = std::make_shared<mw::Header>(10, mw::Hash{}, mw::Hash{}, mw::Hash{},
        BlindingFactor{}, BlindingFactor{}, 2, 0);
    block.mweb_block = MWEB::Block{std::make_shared<mw::Block>(header,
        TxBody{{}, {outside, boundary}, {}})};
    const auto hash = block.GetHash();
    m_wallet.SetLastBlockProcessed(10, hash);
    m_wallet.ScanMWEBExtensionBlock(block, 10, hash);
    for (const auto& output : {outside, boundary}) {
        BOOST_REQUIRE(m_wallet.GetCoin(output.GetOutputID(), coin));
        BOOST_CHECK(coin.IsMine());
        BOOST_CHECK_EQUAL(coin.amount, COIN);
    }
    BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 2U);
    BOOST_CHECK_EQUAL(WITH_LOCK(account->cs_desc_man, return account->GetWalletDescriptor().GetNext()), next + 4);
    const auto coins = m_wallet.ListMWEBUnspent(0, 999, true, nullptr, 0, MAX_MONEY);
    BOOST_REQUIRE_EQUAL(coins.size(), 2U);
    BOOST_CHECK_EQUAL(coins[0].amount + coins[1].amount, 2 * COIN);
    m_wallet.ScanMWEBExtensionBlock(block, 10, hash);
    BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
