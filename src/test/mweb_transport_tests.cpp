// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/consensus.h>
#include <protocol.h>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(mweb_transport_tests)
BOOST_AUTO_TEST_CASE(mweb_envelopes_respect_bip324_type_encoding)
{
    constexpr size_t MAX_V2_PAYLOAD = ((size_t{1} << 24) - 1) - (1 + CMessageHeader::MESSAGE_TYPE_SIZE);
    // Short-id `block` application payload may use one more MESSAGE_TYPE_SIZE
    // bytes than long-form MAX_V2_PAYLOAD; mining uses that larger cap.
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_BIP324, ((size_t{1} << 24) - 1) - 1);
    BOOST_CHECK(MAX_BLOCK_SERIALIZED_SIZE_BIP324 > MAX_V2_PAYLOAD);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB, MAX_BLOCK_SERIALIZED_SIZE_BIP324);
}
BOOST_AUTO_TEST_SUITE_END()
