// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <mw/models/block/block.h>
#include <mw/models/block/header.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/tx_body.h>
#include <pow.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/common.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test_framework/test_mweb.h>
#include <test_framework/tx_builder.h>

#include <boost/test/unit_test.hpp>

namespace {
const std::vector<std::pair<Wtxid, CTransactionRef>> empty_extra_txn;

/** A coinbase and two spends of random outpoints, with valid regtest proof of work. */
CBlock BuildBlock(FastRandomContext& ctx)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(10);
    tx.vout.resize(1);
    tx.vout[0].nValue = 42;

    CBlock block;
    block.vtx.resize(3);
    block.vtx[0] = MakeTransactionRef(tx);
    block.nVersion = 42;
    block.hashPrevBlock = ctx.rand256();
    block.nBits = 0x207fffff;

    tx.vin[0].prevout.hash = Txid::FromUint256(ctx.rand256());
    tx.vin[0].prevout.n = 0;
    block.vtx[1] = MakeTransactionRef(tx);

    tx.vin.resize(10);
    for (size_t i = 0; i < tx.vin.size(); i++) {
        tx.vin[i].prevout.hash = Txid::FromUint256(ctx.rand256());
        tx.vin[i].prevout.n = 0;
    }
    block.vtx[2] = MakeTransactionRef(tx);

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);
    while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    return block;
}

/** Writes a compact block with chosen prefilled transactions and short IDs. */
class TestHeaderAndShortIDs
{
public:
    CBlockHeader header;
    uint64_t nonce;
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;
    MWEB::Block mweb_block;

    explicit TestHeaderAndShortIDs(const CBlockHeaderAndShortTxIDs& orig)
    {
        DataStream stream{};
        stream << orig;
        stream >> *this;
    }
    explicit TestHeaderAndShortIDs(const CBlock& block, FastRandomContext& ctx)
        : TestHeaderAndShortIDs(CBlockHeaderAndShortTxIDs{block, ctx.rand64()}) {}

    uint64_t GetShortID(const Wtxid& txhash) const
    {
        DataStream stream{};
        stream << *this;
        CBlockHeaderAndShortTxIDs base;
        stream >> base;
        return base.GetShortID(txhash);
    }

    SERIALIZE_METHODS(TestHeaderAndShortIDs, obj)
    {
        READWRITE(obj.header, obj.nonce, Using<VectorFormatter<CustomUintFormatter<CBlockHeaderAndShortTxIDs::SHORTTXIDS_LENGTH>>>(obj.shorttxids), obj.prefilledtxn);
        if (MwebAllowedInBlockSerialization(s)) {
            READWRITE(obj.mweb_block);
        }
    }
};

/** Attach a non-null MWEB extension without changing wtxid/txid (extension excluded from hashes). */
CTransactionRef WithSpuriousMWEBExtension(const CTransactionRef& tx)
{
    BOOST_REQUIRE(!tx->HasMWEBTx());
    CMutableTransaction mtx(*tx);
    mtx.mweb_tx = mw::MutableTx::From(*test::Tx::CreatePegIn(COIN).GetTransaction());
    CTransactionRef poisoned = MakeTransactionRef(std::move(mtx));
    BOOST_REQUIRE(poisoned->HasMWEBTx());
    BOOST_REQUIRE_EQUAL(poisoned->GetWitnessHash(), tx->GetWitnessHash());
    BOOST_REQUIRE_EQUAL(poisoned->GetHash(), tx->GetHash());
    return poisoned;
}

/** Append a HogEx and attach an empty MWEB block, keeping valid regtest proof of work. */
void AddHogEx(CBlock& block, FastRandomContext& ctx)
{
    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vin.resize(1);
    hogex.vin[0].prevout.hash = Txid::FromUint256(ctx.rand256());
    hogex.vin[0].prevout.n = 0;
    hogex.vout.resize(1);
    hogex.vout[0].nValue = 42;
    hogex.vout[0].scriptPubKey = CScript() << OP_8 << std::vector<unsigned char>(32, 0x00);
    block.vtx.push_back(MakeTransactionRef(std::move(hogex)));
    BOOST_REQUIRE(block.vtx.back()->IsHogEx());

    const auto header = std::make_shared<mw::Header>(1, mw::Hash{}, mw::Hash{}, mw::Hash{}, BlindingFactor{}, BlindingFactor{}, 0, 0);
    block.mweb_block = MWEB::Block(std::make_shared<mw::Block>(header, TxBody({}, {}, {})));

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    BOOST_REQUIRE(!mutated);
    while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_blockencodings_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(StripMWEBExtension_peer_supplied_prefilled_and_missing)
{
    // Invariant: after BIP152 reconstruction, canonical vtx must not carry mweb_tx,
    // including when peers attach a spurious extension to prefilled or blocktxn txs.
    CTxMemPool& pool = *Assert(m_node.mempool);
    TestMemPoolEntryHelper entry;
    auto rand_ctx(FastRandomContext(uint256{42}));
    CBlock block(BuildBlock(rand_ctx));

    LOCK2(cs_main, pool.cs);
    TryAddToMempool(pool, entry.FromTx(block.vtx[2]));

    const CTransactionRef poisoned_coinbase = WithSpuriousMWEBExtension(block.vtx[0]);
    const CTransactionRef poisoned_missing = WithSpuriousMWEBExtension(block.vtx[1]);

    TestHeaderAndShortIDs shortIDs(block, rand_ctx);
    // Prefill only the poisoned coinbase; leave vtx[1] to be supplied via vtx_missing.
    shortIDs.prefilledtxn.resize(1);
    shortIDs.prefilledtxn[0] = {0, poisoned_coinbase};
    shortIDs.shorttxids.resize(2);
    shortIDs.shorttxids[0] = shortIDs.GetShortID(block.vtx[1]->GetWitnessHash());
    shortIDs.shorttxids[1] = shortIDs.GetShortID(block.vtx[2]->GetWitnessHash());

    DataStream stream{};
    stream << shortIDs;
    CBlockHeaderAndShortTxIDs cmpctblock;
    stream >> cmpctblock;

    PartiallyDownloadedBlock partial(&pool);
    BOOST_CHECK(partial.InitData(cmpctblock, empty_extra_txn) == READ_STATUS_OK);
    BOOST_CHECK(partial.IsTxAvailable(0));
    BOOST_CHECK(!partial.IsTxAvailable(1));
    BOOST_CHECK(partial.IsTxAvailable(2));

    CBlock reconstructed;
    BOOST_CHECK(partial.FillBlock(reconstructed, {poisoned_missing}, /*segwit_active=*/true) == READ_STATUS_OK);
    BOOST_CHECK_EQUAL(reconstructed.GetHash(), block.GetHash());
    BOOST_REQUIRE_EQUAL(reconstructed.vtx.size(), 3U);
    for (const auto& tx : reconstructed.vtx) {
        BOOST_CHECK(!tx->HasMWEBTx());
    }
    BOOST_CHECK_EQUAL(reconstructed.vtx[0]->GetWitnessHash(), block.vtx[0]->GetWitnessHash());
    BOOST_CHECK_EQUAL(reconstructed.vtx[1]->GetWitnessHash(), block.vtx[1]->GetWitnessHash());
    BOOST_CHECK_EQUAL(reconstructed.vtx[2]->GetWitnessHash(), block.vtx[2]->GetWitnessHash());
}

BOOST_AUTO_TEST_CASE(HogExIsPrefilled)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    TestMemPoolEntryHelper entry;
    auto rand_ctx(FastRandomContext(uint256{43}));
    CBlock block(BuildBlock(rand_ctx));
    AddHogEx(block, rand_ctx);
    const size_t n{block.vtx.size()};

    LOCK2(cs_main, pool.cs);
    TryAddToMempool(pool, entry.FromTx(block.vtx[1]));
    TryAddToMempool(pool, entry.FromTx(block.vtx[2]));

    CBlockHeaderAndShortTxIDs cmpctblock{block, rand_ctx.rand64()};
    TestHeaderAndShortIDs shortIDs{cmpctblock};
    BOOST_CHECK(!shortIDs.mweb_block.IsNull());
    BOOST_REQUIRE_EQUAL(shortIDs.prefilledtxn.size(), 2U);
    BOOST_CHECK_EQUAL(shortIDs.prefilledtxn[0].index, 0U);
    // Prefilled indexes are differential: the HogEx at index n - 1 follows the coinbase at 0.
    BOOST_CHECK_EQUAL(shortIDs.prefilledtxn[1].index, n - 2);
    BOOST_CHECK(shortIDs.prefilledtxn[1].tx->IsHogEx());
    BOOST_REQUIRE_EQUAL(shortIDs.shorttxids.size(), n - 2);
    const uint64_t hogex_id{cmpctblock.GetShortID(block.vtx.back()->GetWitnessHash())};
    for (const uint64_t id : shortIDs.shorttxids) BOOST_CHECK(id != hogex_id);

    DataStream stream{};
    stream << TX_WITH_WITNESS(cmpctblock);
    CBlockHeaderAndShortTxIDs received;
    stream >> TX_WITH_WITNESS(received);

    PartiallyDownloadedBlock partial(&pool);
    BOOST_REQUIRE(partial.InitData(received, empty_extra_txn) == READ_STATUS_OK);
    for (size_t i = 0; i < n; i++) BOOST_CHECK(partial.IsTxAvailable(i));

    CBlock reconstructed;
    BOOST_REQUIRE(partial.FillBlock(reconstructed, {}, /*segwit_active=*/true) == READ_STATUS_OK);
    BOOST_CHECK_EQUAL(reconstructed.GetHash(), block.GetHash());
    BOOST_REQUIRE_EQUAL(reconstructed.vtx.size(), n);
    BOOST_CHECK(reconstructed.vtx.back()->IsHogEx());
    BOOST_CHECK(reconstructed.mweb_block.GetHash() == block.mweb_block.GetHash());
}

BOOST_AUTO_TEST_CASE(NoMWEBBlockPrefillsOnlyCoinbase)
{
    auto rand_ctx(FastRandomContext(uint256{44}));
    CBlock block(BuildBlock(rand_ctx));

    TestHeaderAndShortIDs shortIDs{block, rand_ctx};
    BOOST_CHECK(shortIDs.mweb_block.IsNull());
    BOOST_REQUIRE_EQUAL(shortIDs.prefilledtxn.size(), 1U);
    BOOST_CHECK_EQUAL(shortIDs.prefilledtxn[0].index, 0U);
    BOOST_CHECK_EQUAL(shortIDs.shorttxids.size(), block.vtx.size() - 1);
}

BOOST_AUTO_TEST_CASE(NoMWEBSerializationOmitsExtension)
{
    // Version 2 compact blocks carry no MWEB field; version 3 always carries it.
    auto rand_ctx(FastRandomContext(uint256{45}));
    CBlock block(BuildBlock(rand_ctx));
    const CBlockHeaderAndShortTxIDs cmpctblock{block, rand_ctx.rand64()};

    DataStream with_mweb{};
    with_mweb << TX_WITH_WITNESS(cmpctblock);
    DataStream no_mweb{};
    no_mweb << TX_NO_MWEB(cmpctblock);
    BOOST_CHECK_EQUAL(with_mweb.size(), no_mweb.size() + 1);

    CBlockHeaderAndShortTxIDs received;
    no_mweb >> TX_NO_MWEB(received);
    BOOST_CHECK(no_mweb.empty());
    BOOST_CHECK(received.mweb_block.IsNull());
    BOOST_CHECK_EQUAL(received.header.GetHash(), block.GetHash());
    BOOST_CHECK_EQUAL(received.BlockTxCount(), block.vtx.size());
}

BOOST_AUTO_TEST_SUITE_END()
