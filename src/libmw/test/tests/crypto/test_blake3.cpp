// Copyright (c) 2026 ADGL Enterprises, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <mw/crypto/hasher.h>

#include <test_framework/test_mweb.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// Known answers from src/crypto/blake3/test_vectors/test_vectors.json (first
// 32 bytes of the unkeyed hash). Inputs spanning many 1 KiB chunks exercise
// the SIMD hash_many implementations (up to 16-way with AVX-512).
static const std::vector<std::pair<size_t, std::string>> BLAKE3_VECTORS{
    {0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
    {1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"},
    {1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"},
    {1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"},
    {1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"},
    {2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"},
    {2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"},
    {4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"},
    {8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"},
    {16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"},
    {31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"},
    {102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"},
};

static std::vector<uint8_t> VectorInput(size_t len)
{
    std::vector<uint8_t> input(len);
    for (size_t i = 0; i < len; ++i) {
        input[i] = static_cast<uint8_t>(i % 251);
    }
    return input;
}

BOOST_FIXTURE_TEST_SUITE(TestBlake3, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(OneShot)
{
    for (const auto& [len, expected] : BLAKE3_VECTORS) {
        BOOST_CHECK_MESSAGE(Hashed(VectorInput(len)).ToHex() == expected, "input_len=" << len);
    }
}

BOOST_AUTO_TEST_CASE(Incremental)
{
    for (const auto& [len, expected] : BLAKE3_VECTORS) {
        const std::vector<uint8_t> input = VectorInput(len);
        Hasher hasher;
        size_t pos = 0;
        size_t step = 1;
        while (pos < input.size()) {
            const size_t n = std::min(step, input.size() - pos);
            hasher.write(reinterpret_cast<const char*>(input.data() + pos), n);
            pos += n;
            step = step * 3 + 7;
        }
        BOOST_CHECK_MESSAGE(hasher.hash().ToHex() == expected, "input_len=" << len);
    }
}

BOOST_AUTO_TEST_SUITE_END()
