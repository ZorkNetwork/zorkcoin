// Copyright (c) The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/btc_launch_lock.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <kernel/chainparams.h>
#include <kernel/genesis_mainnet.h>
#include <kernel/genesis_testnet.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(btc_launch_lock_tests, BasicTestingSetup)

// Bitcoin block 962490 (2026-08-14). Valid SHA256d at nBits 0x1702353d;
// unix time 1786747596 is before the launch lock.
static const char REAL_BTC_HEADER_HEX[] =
    "0060052091750d840394d89f31bcc717662df2a7be82b455f32401000000000000000000"
    "df984faa27aecb53192f9c7b21baa4ba8c060a2abc7b30d6cb38d5b2394ddd16cc9a7f6a"
    "3d350217ba5fe2ab";

// Ground SHA256d header at nBits 0x207fffff, nTime 1795296330, nonce 2.
static const char EASY_BTC_HEADER_HEX[] =
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000004a0c026b"
    "ffff7f2002000000";

// Ground SHA256d header at nBits 0x207fffff, nTime 1793568277 (BTC_LAUNCH_TESTNET_MIN_UNIX), nonce 0.
static const char EASY_TESTNET_BOUNDARY_OK_HEX[] =
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000015aee76a"
    "ffff7f2000000000";

// Ground SHA256d header at nBits 0x207fffff, nTime 1793568276 (BTC_LAUNCH_TESTNET_MIN_UNIX - 1), nonce 0.
static const char EASY_TESTNET_BOUNDARY_EARLY_HEX[] =
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000014aee76a"
    "ffff7f2000000000";

static std::vector<unsigned char> HeaderFromHex(const char* hex)
{
    auto out = ParseHex(hex);
    BOOST_REQUIRE_EQUAL(out.size(), BTC_LAUNCH_HEADER_SIZE);
    return out;
}

static CTransaction MakeCoinbaseWith(const std::vector<CTxOut>& extra)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx.vout.insert(tx.vout.end(), extra.begin(), extra.end());
    return CTransaction(tx);
}

BOOST_AUTO_TEST_CASE(mainnet_pins)
{
    const auto chainParams = CChainParams::Main();
    const auto& lock = chainParams->GetConsensus().btc_launch_lock;
    BOOST_CHECK(lock.enabled);
    BOOST_CHECK_EQUAL(lock.nbits_floor, BTC_LAUNCH_NBITS_FLOOR);
    BOOST_CHECK_EQUAL(lock.min_unix_time, BTC_LAUNCH_MIN_UNIX);
    BOOST_CHECK_EQUAL(BTC_LAUNCH_NBITS_FLOOR, 0x1702353du);
    BOOST_CHECK_EQUAL(BTC_LAUNCH_MIN_UNIX, 1795296330u);
}

BOOST_AUTO_TEST_CASE(testnet_pins)
{
    const auto chainParams = CChainParams::TestNet();
    const auto& lock = chainParams->GetConsensus().btc_launch_lock;
    BOOST_CHECK(lock.enabled);
    BOOST_CHECK_EQUAL(lock.nbits_floor, BTC_LAUNCH_TESTNET_NBITS_FLOOR);
    BOOST_CHECK_EQUAL(lock.min_unix_time, BTC_LAUNCH_TESTNET_MIN_UNIX);
    BOOST_CHECK_EQUAL(BTC_LAUNCH_TESTNET_NBITS_FLOOR, 0x1702353du);
    BOOST_CHECK_EQUAL(BTC_LAUNCH_TESTNET_MIN_UNIX, 1793568277u);

    CChainParams::TestNetOptions disabled_opts{};
    disabled_opts.btc_launch_lock = false;
    const auto disabledParams = CChainParams::TestNet(disabled_opts);
    BOOST_CHECK(!disabledParams->GetConsensus().btc_launch_lock.enabled);
}

BOOST_AUTO_TEST_CASE(real_header_meets_floor_but_too_early_for_testnet)
{
    const auto header = HeaderFromHex(REAL_BTC_HEADER_HEX);
    BlockValidationState state;
    BOOST_CHECK(!CheckBtcLaunchLockHeader(header, BTC_LAUNCH_TESTNET_MIN_UNIX, BTC_LAUNCH_TESTNET_NBITS_FLOOR, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btc-lock-time");
}

BOOST_AUTO_TEST_CASE(testnet_min_unix_time_boundary)
{
    const auto exact = HeaderFromHex(EASY_TESTNET_BOUNDARY_OK_HEX);
    BlockValidationState ok_state;
    BOOST_CHECK(CheckBtcLaunchLockHeader(exact, BTC_LAUNCH_TESTNET_MIN_UNIX, /*nbits_floor=*/0x207fffff, ok_state));

    const auto one_sec_early = HeaderFromHex(EASY_TESTNET_BOUNDARY_EARLY_HEX);
    BlockValidationState early_state;
    BOOST_CHECK(!CheckBtcLaunchLockHeader(one_sec_early, BTC_LAUNCH_TESTNET_MIN_UNIX, /*nbits_floor=*/0x207fffff, early_state));
    BOOST_CHECK_EQUAL(early_state.GetRejectReason(), "bad-btc-lock-time");
}

BOOST_AUTO_TEST_CASE(script_roundtrip)
{
    const auto header = HeaderFromHex(EASY_BTC_HEADER_HEX);
    const CScript script = BuildBtcLaunchLockScript(header);
    std::vector<unsigned char> parsed;
    BOOST_CHECK(ParseBtcLaunchLockScript(script, parsed));
    BOOST_CHECK(parsed == header);

    CScript extra = script;
    extra << OP_DROP;
    BOOST_CHECK(!ParseBtcLaunchLockScript(extra, parsed));

    CScript wrong_tag = CScript() << OP_RETURN << std::vector<unsigned char>{'b', 't', 'c'} << int64_t{41} << header;
    BOOST_CHECK(!ParseBtcLaunchLockScript(wrong_tag, parsed));
}

BOOST_AUTO_TEST_CASE(real_header_meets_floor_but_too_early)
{
    const auto header = HeaderFromHex(REAL_BTC_HEADER_HEX);
    BlockValidationState state;
    BOOST_CHECK(!CheckBtcLaunchLockHeader(header, BTC_LAUNCH_MIN_UNIX, BTC_LAUNCH_NBITS_FLOOR, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btc-lock-time");

    BlockValidationState ok;
    BOOST_CHECK(CheckBtcLaunchLockHeader(header, /*min_unix_time=*/0, BTC_LAUNCH_NBITS_FLOOR, ok));
}

BOOST_AUTO_TEST_CASE(easy_header_rejected_by_floor)
{
    const auto header = HeaderFromHex(EASY_BTC_HEADER_HEX);
    BlockValidationState easy;
    BOOST_CHECK(CheckBtcLaunchLockHeader(header, BTC_LAUNCH_MIN_UNIX, /*nbits_floor=*/0x207fffff, easy));

    BlockValidationState floor;
    BOOST_CHECK(!CheckBtcLaunchLockHeader(header, BTC_LAUNCH_MIN_UNIX, BTC_LAUNCH_NBITS_FLOOR, floor));
    BOOST_CHECK_EQUAL(floor.GetRejectReason(), "bad-btc-lock-nbits");
}

BOOST_AUTO_TEST_CASE(coinbase_exactly_one_zero_value)
{
    const auto header = HeaderFromHex(EASY_BTC_HEADER_HEX);
    Consensus::BtcLaunchLock lock;
    lock.enabled = true;
    lock.min_unix_time = BTC_LAUNCH_MIN_UNIX;
    lock.nbits_floor = 0x207fffff;

    {
        BlockValidationState state;
        BOOST_CHECK(!CheckBtcLaunchLock(MakeCoinbaseWith({}), lock, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btc-lock-missing");
    }

    CTxOut good;
    good.nValue = 0;
    good.scriptPubKey = BuildBtcLaunchLockScript(header);
    {
        BlockValidationState state;
        BOOST_CHECK(CheckBtcLaunchLock(MakeCoinbaseWith({good}), lock, state));
    }
    {
        BlockValidationState state;
        BOOST_CHECK(!CheckBtcLaunchLock(MakeCoinbaseWith({good, good}), lock, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btc-lock-duplicate");
    }

    CTxOut paid = good;
    paid.nValue = 1;
    {
        BlockValidationState state;
        BOOST_CHECK(!CheckBtcLaunchLock(MakeCoinbaseWith({paid}), lock, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btc-lock-value");
    }

    // Witness-commitment-shaped OP_RETURN must not be mistaken for the lock.
    CTxOut witness;
    witness.nValue = 0;
    witness.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
    witness.scriptPubKey[0] = OP_RETURN;
    witness.scriptPubKey[1] = 0x24;
    witness.scriptPubKey[2] = 0xaa;
    witness.scriptPubKey[3] = 0x21;
    witness.scriptPubKey[4] = 0xa9;
    witness.scriptPubKey[5] = 0xed;
    {
        BlockValidationState state;
        BOOST_CHECK(CheckBtcLaunchLock(MakeCoinbaseWith({witness, good}), lock, state));
        BOOST_CHECK_EQUAL(*GetBtcLaunchLockOutputIndex(MakeCoinbaseWith({witness, good})), 2);
    }
}

BOOST_AUTO_TEST_CASE(template_without_header_vs_submitted_block)
{
    const auto chainParams = CChainParams::TestNet();
    const auto& consensus = chainParams->GetConsensus();

    CBlock block;
    block.nVersion = 0x20000000;
    block.hashPrevBlock = consensus.hashGenesisBlock;
    block.nTime = TESTNET_GENESIS_NTIME + 1000;
    block.nBits = TESTNET_GENESIS_NBITS;
    block.nNonce = 0;

    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << 1 << OP_0;
    cb.vout.resize(1);
    cb.vout[0].nValue = 50 * COIN;
    cb.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(cb));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // Unmined template check (!fCheckPOW && !fCheckMerkleRoot) passes without -btclaunchheader.
    {
        BlockValidationState state;
        BOOST_CHECK(CheckBlock(block, state, consensus, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
    }

    // Proposal / submission check (fCheckMerkleRoot=true) rejects missing launch-lock OP_RETURN.
    {
        BlockValidationState state;
        BOOST_CHECK(!CheckBlock(block, state, consensus, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btc-lock-missing");
    }

    // If a template embeds an invalid launch-lock output, even the unmined template check rejects it.
    CTxOut early_out;
    early_out.nValue = 0;
    early_out.scriptPubKey = BuildBtcLaunchLockScript(HeaderFromHex(REAL_BTC_HEADER_HEX));
    cb.vout.push_back(early_out);
    block.vtx[0] = MakeTransactionRef(cb);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    {
        BlockValidationState state;
        BOOST_CHECK(!CheckBlock(block, state, consensus, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btc-lock-time");
    }
}

BOOST_AUTO_TEST_SUITE_END()
