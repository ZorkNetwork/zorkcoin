// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <external_signer.h>
#include <key.h>
#include <key_io.h>
#include <psbt.h>
#include <test/util/psbt.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <string>

using namespace psbt_test;

namespace {

PartiallySignedTransaction PSBTWithMWEBAddressDescriptor(const std::string& descriptor)
{
    PartiallySignedTransaction psbt = EmptyPSBT();
    PSBTInput input = MWEBInput(TestHash(1));
    input.mweb_address_descriptor = descriptor;
    psbt.inputs.push_back(std::move(input));
    return psbt;
}

std::string IndexedDescriptor(const std::string& scan_origin, const std::string& spend_origin)
{
    return strprintf("mweb(%s%s,%s%s,3)", scan_origin, EncodeSecret(ToCKey(TestSecret('1'))), spend_origin, EncodeSecret(ToCKey(TestSecret('2'))));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_external_signer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mweb_address_descriptor_origin_matches_signer)
{
    // The command fails, so a matching fingerprint is seen as the signer being run.
    const std::vector<std::string> command{"false"};
    const std::string matching = IndexedDescriptor("[d34db33f/0h/100h/0h]", "[d34db33f/0h/100h/1h]");
    const std::string spend_only = IndexedDescriptor("", "[d34db33f/0h/100h/1h]");

    const std::string matching_descriptors[] = {matching, spend_only};
    for (const std::string& descriptor : matching_descriptors) {
        PartiallySignedTransaction psbt = PSBTWithMWEBAddressDescriptor(descriptor);
        ExternalSigner signer(command, "regtest", "d34db33f", "test");
        std::string error;
        BOOST_CHECK_THROW(signer.SignTransaction(psbt, error), std::runtime_error);
    }

    // Only MWEB descriptors are considered.
    const std::string wpkh = strprintf("wpkh([d34db33f/0h]%s)", EncodeSecret(ToCKey(TestSecret('1'))));
    {
        PartiallySignedTransaction psbt = PSBTWithMWEBAddressDescriptor(wpkh);
        ExternalSigner signer(command, "regtest", "d34db33f", "test");
        std::string error;
        BOOST_CHECK(!signer.SignTransaction(psbt, error));
    }

    const std::string mismatched_descriptors[] = {matching, IndexedDescriptor("", "")};
    for (const std::string& descriptor : mismatched_descriptors) {
        PartiallySignedTransaction psbt = PSBTWithMWEBAddressDescriptor(descriptor);
        ExternalSigner signer(command, "regtest", "00000000", "test");
        std::string error;
        BOOST_CHECK(!signer.SignTransaction(psbt, error));
        BOOST_CHECK(error.starts_with("Signer fingerprint 00000000 does not match any of the inputs"));
    }
}

BOOST_AUTO_TEST_SUITE_END()
