// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <config/bitcoin-config.h>
#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <deploymentinfo.h>
#include <hash.h> // for signet block challenge hash
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint64_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << OP_0 << 1130459756 << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = (uint64_t)nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = (uint64_t)nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint64_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "LTC BLK: a403d2d80e3297a8b496bff77882147af1ce2caa0bdd4ce13216930b569dfa00";
    const CScript genesisOutputScript = CScript() << ParseHex("040241e2ab92d48de2889fe28891ceb7cf84e28487d18f70c2aed19753e284ae24588d0429a6a46d555360b9f3b83a60a6c49895a62abad18fd8182c0009492308") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP16Height = 0; // always enforce P2SH
        consensus.BIP34Height = 0; // blocks always have block height
        consensus.BIP34Hash = uint256S("0x982982bd117211d385933b0467b140d59247651bd4f74048ccbb8ab395053526");
        consensus.BIP65Height = 0; // CHECKLOCKTIMEVERIFY always available
        consensus.BIP66Height = 0; // DERSIG always required
        consensus.CSVHeight = 0; // always enabled
        consensus.SegwitHeight = 0; // SegWit always enabled
        consensus.MinBIP9WarningHeight = 0; // BIP9 enabled from the start
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60 * 1000; // 3.5 days (in milliseconds)
        consensus.nPowTargetSpacing = 2.5 * 60 * 1000; // 2.5 minutes (in milliseconds)
        consensus.nASERTHalfLife = 12 * 60 * 60 * 1000; // 12 hours in milliseconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 209665; // 364 days later

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.defaultAssumeValid = uint256S("0x80cdb35c080484df5bf384b311fde3c4694d3405765bc0f596e9eb369ff286e5"); // 2772730

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf7;
        pchMessageStart[1] = 0x1d;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0x3d;
        nDefaultPort = 24301;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 40;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1770399953638, 3249457866, 0x1e0ffff0, 0x20000000UL, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x982982bd117211d385933b0467b140d59247651bd4f74048ccbb8ab395053526"));
        assert(genesis.hashMerkleRoot == uint256S("0x521ad721f223f09b9235f2e5cc4819580adffd78755447c9639375c79d278daa"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("mainnet-seed.zork.network");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,80);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,54);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,167);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "zork";
        mweb_hrp = "zorkmweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {      0, uint256S("0x982982bd117211d385933b0467b140d59247651bd4f74048ccbb8ab395053526")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 17280 fdb81fc2edae4e315716890bd343d814184ea50331cd47166e19120a5163a678
            // Use 64-bit literal so * 1000 is done in int64_t (UBSan)
            /* nTime    */ 1758215212LL * 1000,
            /* nTxCount */ 1,
            /* dTxRate  */ 0.009810333551340745,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on testnet
        consensus.BIP34Height = 0; // blocks always have block height
        consensus.BIP34Hash = uint256S("0x07b8d2ce2a913d73072e83c556bc66b035207f17022be85ea65098620287534b");
        consensus.BIP65Height = 0; // CHECKLOCKTIMEVERIFY always available
        consensus.BIP66Height = 0; // DERSIG always required
        consensus.CSVHeight = 0; // always enabled
        consensus.SegwitHeight = 0; // SegWit always enabled
        consensus.MinBIP9WarningHeight = 0; // BIP9 enabled from the start
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60 * 1000; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60 * 1000;
        consensus.nASERTHalfLife = 12 * 60 * 60 * 1000; // 12 hours in milliseconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 209665; // 364 days later

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.defaultAssumeValid = uint256S("0x4a280c0e150e3b74ebe19618e6394548c8a39d5549fd9941b9c431c73822fbd5"); // 1737876

        pchMessageStart[0] = 0xf7;
        pchMessageStart[1] = 0x2d;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0x3d;
        nDefaultPort = 23295;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 4;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1770399539383, 18797917, 0x1f0007f8, 0x20000000UL, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x07b8d2ce2a913d73072e83c556bc66b035207f17022be85ea65098620287534b"));
        assert(genesis.hashMerkleRoot == uint256S("0x521ad721f223f09b9235f2e5cc4819580adffd78755447c9639375c79d278daa"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.zork.network");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "zorktest";
        mweb_hrp = "tmweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {      0, uint256S("0x07b8d2ce2a913d73072e83c556bc66b035207f17022be85ea65098620287534b")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 36d8ad003bac090cf7bf4e24fbe1d319554c8933b9314188d6096ac12648764d
            /* nTime    */ 1763418790000,
            /* nTxCount */ 1,
            /* dTxRate  */ 0.009810333551340745,
        };
    }
};

/**
 * Parse -testactivationheight=name@height from args into RegTestOptions.
 */
static void ReadRegTestArgs(const ArgsManager& args, RegTestOptions& options)
{
    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        size_t pos = arg.find('@');
        if (pos == std::string::npos || pos == 0 || pos == arg.size() - 1) {
            throw std::runtime_error(strprintf("Invalid -testactivationheight=%s (expected name@height)", arg));
        }
        std::string name = arg.substr(0, pos);
        std::string height_str = arg.substr(pos + 1);
        int64_t height;
        if (!ParseInt64(height_str, &height)) {
            throw std::runtime_error(strprintf("Invalid height in -testactivationheight=%s", arg));
        }
        Optional<Consensus::BuriedDeployment> dep = GetBuriedDeployment(name);
        if (!dep) {
            throw std::runtime_error(strprintf("Unknown deployment '%s' in -testactivationheight=%s (use: bip34, dersig, cltv, csv, segwit)", name, arg));
        }
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for %s is out of valid range. Use -1 to disable.", height, name));
        }
        if (height == -1) {
            if (*dep == Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT) {
                LogPrintf("Segwit disabled for testing\n");
            }
            height = std::numeric_limits<int>::max();
        }
        options.activation_heights[*dep] = static_cast<int>(height);
    }
}

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const RegTestOptions& opts, const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0; // blocks always have block height
        consensus.BIP34Hash = uint256S("0x3667e6d73c22bbc85d5c67fa26e3ff8b7ed90786744291cc060a13a42a4646e6");
        consensus.BIP65Height = 0; // CHECKLOCKTIMEVERIFY always available
        consensus.BIP66Height = 0; // DERSIG always required
        consensus.CSVHeight = 0; // always enabled
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60 * 1000; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60 * 1000;
        consensus.nASERTHalfLife = 12 * 60 * 60 * 1000; // 12 hours in milliseconds
        consensus.fPowAllowMinDifficultyBlocks = true;
#if defined(ENABLE_ASERT_REGTEST) && ENABLE_ASERT_REGTEST
        consensus.fPowNoRetargeting = false; // Enable ASERT retargeting for extended tests
#else
        consensus.fPowNoRetargeting = true;
#endif
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of MWEB (LIP-0002 and LIP-0003)
        // Regtest: active from genesis+1 so MWEB can activate after the first block; tests use -vbparams or mine to activation.
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartTime = 1765210800000 + 1; // genesis block time + 1
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Apply activation heights from RegTestOptions
        for (const auto& pair : opts.activation_heights) {
            Consensus::BuriedDeployment dep = pair.first;
            int height = pair.second;
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB: consensus.BIP34Height = height; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG: consensus.BIP66Height = height; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV: consensus.BIP65Height = height; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV: consensus.CSVHeight = height; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT: consensus.SegwitHeight = height; break;
            }
        }

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xf7;
        pchMessageStart[1] = 0x4d;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0x3d;
        nDefaultPort = 20497;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        genesis = CreateGenesisBlock(1765210800000, 0xC0FFEE08, 0x207fffff, 0x20000000UL, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x3667e6d73c22bbc85d5c67fa26e3ff8b7ed90786744291cc060a13a42a4646e6"));
        assert(genesis.hashMerkleRoot == uint256S("0x521ad721f223f09b9235f2e5cc4819580adffd78755447c9639375c79d278daa"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        // Checkpoint at 300 is for functional test p2p_dos_header_tree.py, which uses
        // data/blockheader_testnet.hex (regtest headers). GetLastCheckpoint() only uses
        // checkpoints that exist in the current chain, so other regtest tests are unaffected.
        // TODO: convert p2p_dos_header_tree back to testnet: mine testnet past block 300,
        // regenerate blockheader_testnet.hex from testnet, add testnet checkpoint at 300 here
        // (in CTestNetParams), remove this regtest checkpoint, and switch the test to chain='testnet'.
        // See p2p_dos_header_tree.py for full conversion instructions.
        checkpointData = {
            {
                {0, uint256S("0x3667e6d73c22bbc85d5c67fa26e3ff8b7ed90786744291cc060a13a42a4646e6")},
                {300, uint256S("0x21ab8f9555ec58552b2491c20babc7872bf9e991d387630a7cf508c0c85b3ebc")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "zorksim";
        mweb_hrp = "tmweb";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nStartHeight, int64_t nTimeoutHeight)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        consensus.vDeployments[d].nStartHeight = nStartHeight;
        consensus.vDeployments[d].nTimeoutHeight = nTimeoutHeight;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() < 3 || 5 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:heightstart:heightend]");
        }
        int64_t nStartTime, nTimeout, nStartHeight, nTimeoutHeight;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() > 3 && !ParseInt64(vDeploymentParams[3], &nStartHeight)) {
            throw std::runtime_error(strprintf("Invalid nStartHeight (%s)", vDeploymentParams[3]));
        }
        if (vDeploymentParams.size() > 4 && !ParseInt64(vDeploymentParams[4], &nTimeoutHeight)) {
            throw std::runtime_error(strprintf("Invalid nTimeoutHeight (%s)", vDeploymentParams[4]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, nStartHeight, nTimeoutHeight);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, start_height=%d, timeout_height=%d\n", vDeploymentParams[0], nStartTime, nTimeout, nStartHeight, nTimeoutHeight);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams()); // TODO: Support SigNet
    } else if (chain == CBaseChainParams::REGTEST) {
        RegTestOptions opts;
        ReadRegTestArgs(args, opts);
        return std::unique_ptr<CChainParams>(new CRegTestParams(opts, args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
