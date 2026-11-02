// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bech32.h>
#include <chainparams.h>
#include <key_io.h>
#include <mw/models/wallet/stealth_address.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <variant>
#include <vector>

namespace {

//! Re-encodes an MWEB address under another HRP, keeping its data.
std::string WithHRP(const std::string& address, const std::string& hrp)
{
    const bech32::DecodeResult dec = bech32::Decode(address, bech32::CharLimit::MWEB);
    BOOST_REQUIRE(dec.encoding == bech32::Encoding::BECH32);
    return bech32::Encode(bech32::Encoding::BECH32, hrp, dec.data);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_key_io_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mweb_address_rejects_foreign_hrp)
{
    const StealthAddress stealth = StealthAddress::Random();
    for (const ChainType chain : {ChainType::MAIN, ChainType::REGTEST}) {
        SelectParams(chain);
        const std::string address = EncodeDestination(stealth);
        BOOST_CHECK(address.starts_with(Params().MWEB_HRP() + "1"));
        const CTxDestination dest = DecodeDestination(address);
        BOOST_REQUIRE(std::holds_alternative<StealthAddress>(dest));
        BOOST_CHECK(std::get<StealthAddress>(dest) == stealth);

        // Other chains' MWEB HRPs (Litecoin's ltcmweb and tmweb, and rmweb) are never accepted.
        for (const std::string hrp : {"ltcmweb", "tmweb", "rmweb"}) {
            const std::string foreign = WithHRP(address, hrp);
            BOOST_CHECK_MESSAGE(!IsValidDestinationString(foreign), foreign);
        }
    }

    // Each network refuses the others' MWEB addresses.
    const std::vector<ChainType> chains{ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST};
    std::vector<std::string> addresses;
    for (const ChainType chain : chains) {
        SelectParams(chain);
        addresses.push_back(EncodeDestination(stealth));
    }
    for (size_t i = 0; i < chains.size(); ++i) {
        SelectParams(chains[i]);
        for (size_t j = 0; j < chains.size(); ++j) {
            if (i != j) BOOST_CHECK_MESSAGE(!IsValidDestinationString(addresses[j]), addresses[j]);
        }
    }
    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
