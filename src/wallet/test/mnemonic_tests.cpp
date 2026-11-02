// Copyright (c) 2017-2026 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <test/util/json.h>

#include <test/data/bip39_vectors_chinese_simplified.json.h>
#include <test/data/bip39_vectors_chinese_traditional.json.h>
#include <test/data/bip39_vectors_czech.json.h>
#include <test/data/bip39_vectors_english.json.h>
#include <test/data/bip39_vectors_french.json.h>
#include <test/data/bip39_vectors_italian.json.h>
#include <test/data/bip39_vectors_japanese.json.h>
#include <test/data/bip39_vectors_japanese_trezor.json.h>
#include <test/data/bip39_vectors_korean.json.h>
#include <test/data/bip39_vectors_portuguese.json.h>
#include <test/data/bip39_vectors_spanish.json.h>

#include <key.h>
#include <wallet/mnemonic.h>
#include <key_io.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <span>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mnemonic_tests, BasicTestingSetup)

static const char* mnemonic_1 = "deer clever bitter bonus unable menu satoshi chaos dwarf inmate robot drama exist nuclear raise";
static const char* mnemonic_2 = "zoologie ficeler xénon voyelle village viande vignette sécréter séduire torpille remède abolir";

BOOST_AUTO_TEST_CASE(mnemonic_test)
{
    SecureString words = mnemonic_1;
    const std::string expect_seed = "1da563986981b82c17a76160934f4b532eac77e14b632c6adcf31ba4166913e063ce158164c512cdce0672cbc9256dd81e7be23a8d8eb331de1a497493c382b1";

    std::vector<uint8_t, secure_allocator<uint8_t>> vSeed;
    SecureString password;
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(words, password, vSeed));

    BOOST_CHECK_EQUAL(HexStr(vSeed), expect_seed);
}

BOOST_AUTO_TEST_CASE(mnemonic_test_fails)
{
    int nLanguage = -1;
    std::string sError;
    std::vector<uint8_t, secure_allocator<uint8_t>> vEntropy;
    SecureString sWords = "legals winner thank year wave sausage worth useful legal winner thank yellow";
    BOOST_CHECK_MESSAGE(3 == mnemonic::Decode(nLanguage, sWords, vEntropy, sError), "Decode: " << sError);

    sWords = "winner legal thank year wave sausage worth useful legal winner thank yellow";
    BOOST_CHECK_MESSAGE(5 == mnemonic::Decode(nLanguage, sWords, vEntropy, sError), "Decode: " << sError);
}

BOOST_AUTO_TEST_CASE(mnemonic_addchecksum)
{
    std::string sError;
    SecureString sWordsIn = "abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab";
    SecureString sWordsOut;

    BOOST_CHECK_MESSAGE(0 == mnemonic::AddChecksum(-1, sWordsIn, sWordsOut, sError), "AddChecksum: " << sError);
    BOOST_CHECK_EQUAL(sWordsOut, "abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb");

    // Must fail: 10 words do not pack to a BIP39 entropy length
    SecureString sWordsInFail = "abandon baby cabbage dad eager fabric gadget habit ice kangaroo";
    BOOST_CHECK_MESSAGE(4 == mnemonic::AddChecksum(-1, sWordsInFail, sWordsOut, sError), "AddChecksum: " << sError);

    SecureString sWordsInFrench = "zoologie ficeler xénon voyelle village viande vignette sécréter séduire torpille remède";
    BOOST_CHECK_EQUAL(0, mnemonic::AddChecksum(-1, sWordsInFrench, sWordsOut, sError));
    BOOST_CHECK_EQUAL(sWordsOut, mnemonic_2);
}

BOOST_AUTO_TEST_CASE(mnemonic_entropy_range)
{
    std::string sError;
    SecureString words;
    std::vector<uint8_t, secure_allocator<uint8_t>> short_entropy(15, 0x11);
    BOOST_CHECK_EQUAL(2, mnemonic::Encode(mnemonic::WLL_ENGLISH, short_entropy, words, sError));

    std::vector<uint8_t, secure_allocator<uint8_t>> long_entropy(36, 0x11);
    BOOST_CHECK_EQUAL(2, mnemonic::Encode(mnemonic::WLL_ENGLISH, long_entropy, words, sError));

    std::vector<uint8_t, secure_allocator<uint8_t>> ok_entropy(16, 0x11);
    BOOST_CHECK_EQUAL(0, mnemonic::Encode(mnemonic::WLL_ENGLISH, ok_entropy, words, sError));
}

BOOST_AUTO_TEST_CASE(mnemonic_entropy_bytes_for_wordcount)
{
    BOOST_CHECK_EQUAL(16, mnemonic::EntropyBytesForWordCount(12));
    BOOST_CHECK_EQUAL(20, mnemonic::EntropyBytesForWordCount(15));
    BOOST_CHECK_EQUAL(24, mnemonic::EntropyBytesForWordCount(18));
    BOOST_CHECK_EQUAL(28, mnemonic::EntropyBytesForWordCount(21));
    BOOST_CHECK_EQUAL(32, mnemonic::EntropyBytesForWordCount(24));
    BOOST_CHECK_EQUAL(0, mnemonic::EntropyBytesForWordCount(13));
    BOOST_CHECK_EQUAL(0, mnemonic::EntropyBytesForWordCount(0));
    BOOST_CHECK_EQUAL(0, mnemonic::EntropyBytesForWordCount(27));
}

BOOST_AUTO_TEST_CASE(mnemonic_unknown_word_error_surfaces_token)
{
    // Failed Decode must surface the bad token to the caller (UI/RPC). Logging must not
    // include the token; that secrecy property is covered by wallet_bip39.py.
    const std::string bad_token = "notawordzzzz";
    SecureString sWords = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ";
    sWords += bad_token;
    int nLanguage = -1;
    std::string sError;
    std::vector<uint8_t, secure_allocator<uint8_t>> vEntropy;
    BOOST_CHECK_EQUAL(3, mnemonic::Decode(nLanguage, sWords, vEntropy, sError));
    BOOST_CHECK(sError.find(bad_token) != std::string::npos);
}

static void RunVectorTests(int language, UniValue& tests)
{
    std::string sError;
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        assert(test.size() > 2);

        SecureString sEntropy = test[0].get_str().c_str();
        SecureString sWords = test[1].get_str().c_str();
        std::string sSeed;
        SecureString sPassphrase;
        if (test.size() > 3) {
            sPassphrase = test[2].get_str().c_str();
            sSeed = test[3].get_str().c_str();
        } else {
            sPassphrase = "TREZOR";
            sSeed = test[2].get_str();
        }

        std::vector<uint8_t> entropy_in = ParseHex(std::string_view{sEntropy});
        std::vector<uint8_t, secure_allocator<uint8_t>> vEntropy(entropy_in.begin(), entropy_in.end());
        std::vector<uint8_t, secure_allocator<uint8_t>> vEntropyTest;

        SecureString sWordsTest;
        BOOST_CHECK_MESSAGE(0 == mnemonic::Encode(language, vEntropy, sWordsTest, sError), "Encode: " << sError);
        BOOST_CHECK(sWords == sWordsTest);

        // Round-trip with the known language (avoids Chinese S/T glyph-overlap auto-detect ambiguity).
        int n_language = language;
        BOOST_CHECK_MESSAGE(0 == mnemonic::Decode(n_language, sWords, vEntropyTest, sError), "Decode: " << sError);
        BOOST_CHECK(vEntropy == vEntropyTest);

        // Auto-detect: Chinese S/T share some glyphs, so accept either Chinese dialect there.
        int detected_language = -1;
        BOOST_CHECK_MESSAGE(0 == mnemonic::Decode(detected_language, sWords, vEntropyTest, sError), "Decode auto: " << sError);
        if (language == mnemonic::WLL_CHINESE_S || language == mnemonic::WLL_CHINESE_T) {
            BOOST_CHECK(detected_language == mnemonic::WLL_CHINESE_S || detected_language == mnemonic::WLL_CHINESE_T);
        } else {
            BOOST_CHECK_EQUAL(detected_language, language);
        }
        BOOST_CHECK(vEntropy == vEntropyTest);

        std::vector<uint8_t> vSeed = ParseHex(sSeed);
        std::vector<uint8_t, secure_allocator<uint8_t>> seed_check(vSeed.begin(), vSeed.end());
        std::vector<uint8_t, secure_allocator<uint8_t>> vSeedTest;

        BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(sWords, sPassphrase, vSeedTest));
        BOOST_CHECK(seed_check == vSeedTest);

        if (test.size() > 4) {
            const std::string sExtKey = test[4].get_str();
            CExtKey ekTest;
            ekTest.SetSeed(std::as_bytes(std::span{vSeed}));
            BOOST_CHECK_EQUAL(EncodeExtKey(ekTest), sExtKey);
        }
    }
}

BOOST_AUTO_TEST_CASE(mnemonic_test_json)
{
    UniValue tests_english = read_json(json_tests::bip39_vectors_english);
    RunVectorTests(mnemonic::WLL_ENGLISH, tests_english);

    UniValue tests_french = read_json(json_tests::bip39_vectors_french);
    RunVectorTests(mnemonic::WLL_FRENCH, tests_french);

    UniValue tests_japanese = read_json(json_tests::bip39_vectors_japanese);
    RunVectorTests(mnemonic::WLL_JAPANESE, tests_japanese);

    UniValue tests_japanese_trezor = read_json(json_tests::bip39_vectors_japanese_trezor);
    RunVectorTests(mnemonic::WLL_JAPANESE, tests_japanese_trezor);

    UniValue tests_spanish = read_json(json_tests::bip39_vectors_spanish);
    RunVectorTests(mnemonic::WLL_SPANISH, tests_spanish);

    UniValue tests_chinese_s = read_json(json_tests::bip39_vectors_chinese_simplified);
    RunVectorTests(mnemonic::WLL_CHINESE_S, tests_chinese_s);

    UniValue tests_chinese_t = read_json(json_tests::bip39_vectors_chinese_traditional);
    RunVectorTests(mnemonic::WLL_CHINESE_T, tests_chinese_t);

    UniValue tests_italian = read_json(json_tests::bip39_vectors_italian);
    RunVectorTests(mnemonic::WLL_ITALIAN, tests_italian);

    UniValue tests_korean = read_json(json_tests::bip39_vectors_korean);
    RunVectorTests(mnemonic::WLL_KOREAN, tests_korean);

    UniValue tests_czech = read_json(json_tests::bip39_vectors_czech);
    RunVectorTests(mnemonic::WLL_CZECH, tests_czech);

    UniValue tests_portuguese = read_json(json_tests::bip39_vectors_portuguese);
    RunVectorTests(mnemonic::WLL_PORTUGUESE, tests_portuguese);
}

BOOST_AUTO_TEST_CASE(mnemonic_chinese_st_same_entropy_different_seed)
{
    // BIP39 shortcoming: same entropy + different wordlists → different seeds.
    const std::vector<uint8_t> entropy_in = ParseHex("00000000000000000000000000000000");
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy(entropy_in.begin(), entropy_in.end());
    std::string sError;
    SecureString words_s, words_t;
    BOOST_REQUIRE_EQUAL(0, mnemonic::Encode(mnemonic::WLL_CHINESE_S, entropy, words_s, sError));
    BOOST_REQUIRE_EQUAL(0, mnemonic::Encode(mnemonic::WLL_CHINESE_T, entropy, words_t, sError));

    SecureString passphrase = "TREZOR";
    std::vector<uint8_t, secure_allocator<uint8_t>> seed_s, seed_t;
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words_s, passphrase, seed_s));
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words_t, passphrase, seed_t));
    // All-zero entropy uses glyphs shared by both lists, so Encode may yield the same sentence
    // (and thus the same seed). Use an entropy whose Trezor vectors differ between S and T.
    const std::vector<uint8_t> entropy_diff_in = ParseHex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy_diff(entropy_diff_in.begin(), entropy_diff_in.end());
    BOOST_REQUIRE_EQUAL(0, mnemonic::Encode(mnemonic::WLL_CHINESE_S, entropy_diff, words_s, sError));
    BOOST_REQUIRE_EQUAL(0, mnemonic::Encode(mnemonic::WLL_CHINESE_T, entropy_diff, words_t, sError));
    BOOST_CHECK(words_s != words_t);
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words_s, passphrase, seed_s));
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words_t, passphrase, seed_t));
    BOOST_CHECK(seed_s != seed_t);
}

BOOST_AUTO_TEST_CASE(mnemonic_detect_language_smoke)
{
    struct Case {
        int language;
        const char* phrase;
    };
    // First Trezor 12-word mnemonic per language (unique enough for DetectLanguage).
    const Case cases[] = {
        {mnemonic::WLL_ENGLISH, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
        {mnemonic::WLL_FRENCH, "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille"},
        {mnemonic::WLL_SPANISH, "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abierto"},
        {mnemonic::WLL_ITALIAN, "abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abete"},
        {mnemonic::WLL_CZECH, "abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace agrese"},
        {mnemonic::WLL_PORTUGUESE, "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abater"},
        // Distinct traditional glyphs vs simplified (7f7f… entropy).
        {mnemonic::WLL_CHINESE_S, "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 卿"},
        {mnemonic::WLL_CHINESE_T, "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 卿"},
        {mnemonic::WLL_KOREAN, "가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가능"},
        // DetectLanguage splits on ASCII space; Decode NFKD-normalizes U+3000 first.
        {mnemonic::WLL_JAPANESE, "あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あおぞら"},
    };
    for (const Case& c : cases) {
        SecureString phrase = c.phrase;
        BOOST_CHECK_MESSAGE(mnemonic::DetectLanguage(phrase) == c.language,
                            "DetectLanguage failed for language " << c.language);
    }
}

BOOST_AUTO_TEST_CASE(mnemonic_reject_empty)
{
    // Empty and whitespace-only input must fail Decode and ToSeed (not produce a seed).
    const char* empties[] = {"", "   ", " \t\n\r "};
    for (const char* raw : empties) {
        SecureString phrase = raw;
        int lang = -1;
        std::string sError;
        std::vector<uint8_t, secure_allocator<uint8_t>> entropy;
        BOOST_CHECK(0 != mnemonic::Decode(lang, phrase, entropy, sError));
        BOOST_CHECK_EQUAL(sError, "Empty mnemonic");

        std::vector<uint8_t, secure_allocator<uint8_t>> seed;
        BOOST_CHECK(0 != mnemonic::ToSeed(phrase, SecureString{}, seed));
    }
}

BOOST_AUTO_TEST_CASE(mnemonic_empty_passphrase_explicit)
{
    // Explicit empty passphrase (EN abandon…about) matches known Trezor empty-pass seed.
    SecureString words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    SecureString empty;
    std::vector<uint8_t, secure_allocator<uint8_t>> vSeed;
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(words, empty, vSeed));
    BOOST_CHECK_EQUAL(HexStr(vSeed),
                      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");

    // Japanese: empty passphrase vs TREZOR must differ (BIP39 salt includes passphrase).
    SecureString jp = "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら";
    std::vector<uint8_t, secure_allocator<uint8_t>> seed_empty, seed_trezor;
    SecureString trezor = "TREZOR";
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(jp, empty, seed_empty));
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(jp, trezor, seed_trezor));
    BOOST_CHECK(seed_empty != seed_trezor);
}

BOOST_AUTO_TEST_CASE(mnemonic_passphrase_preserves_edge_spaces)
{
    // BIP39 passphrase is NFKD-normalized but NOT trimmed; edged spaces change the seed.
    SecureString words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    SecureString pass_plain = "x";
    SecureString pass_edged = " x ";
    std::vector<uint8_t, secure_allocator<uint8_t>> seed_plain, seed_edged;
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(words, pass_plain, seed_plain));
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(words, pass_edged, seed_edged));
    BOOST_CHECK(seed_plain != seed_edged);
}

BOOST_AUTO_TEST_CASE(mnemonic_preserves_embedded_nul)
{
    SecureString words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    SecureString passphrase = "TREZOR";
    std::vector<uint8_t, secure_allocator<uint8_t>> seed_prefix, seed_suffix, seed_different;
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words, passphrase, seed_prefix));

    passphrase.push_back('\0');
    passphrase += "suffix";
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words, passphrase, seed_suffix));
    // Python hashlib.pbkdf2_hmac('sha512', words.encode(),
    //     b'mnemonicTREZOR\x00suffix', 2048), with NFKD-normalized inputs.
    BOOST_CHECK_EQUAL(HexStr(seed_suffix),
                      "e0c9d21b39722e90b5e3f2efaa9e76a98d0e21fe4bac31fe537c06519ef32cf5b5db559248381bd0f968fc63fcf828200d2c5b5ad08fc0e4aa873b8b16ce1b33");
    BOOST_CHECK(seed_prefix != seed_suffix);

    passphrase.resize(7); // Keep TREZOR and the embedded NUL.
    passphrase += "different";
    BOOST_REQUIRE_EQUAL(0, mnemonic::ToSeed(words, passphrase, seed_different));
    BOOST_CHECK(seed_different != seed_suffix);

    // Invalid words after a NUL must not be silently discarded during import.
    words.push_back('\0');
    words += "suffix";
    int language = -1;
    std::string error;
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy;
    BOOST_CHECK(0 != mnemonic::Decode(language, words, entropy, error));
}

BOOST_AUTO_TEST_CASE(mnemonic_nfkd_passphrase_and_french_words)
{
    // Passphrase NFKD: precomposed Ę vs decomposed must match EN vector seed for uoĘtdjw.
    SecureString words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    SecureString pass_precomposed = "uo\u0118tdjw"; // U+0118 LATIN CAPITAL LETTER E WITH OGONEK
    SecureString pass_decomposed = "uoE\u0328tdjw"; // E + combining ogonek
    std::vector<uint8_t, secure_allocator<uint8_t>> seed_a, seed_b;
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(words, pass_precomposed, seed_a));
    BOOST_CHECK_EQUAL(0, mnemonic::ToSeed(words, pass_decomposed, seed_b));
    BOOST_CHECK(seed_a == seed_b);
    BOOST_CHECK_EQUAL(HexStr(seed_a),
                      "e9f15a138bc5818ceff9269af8084bb8545a40aee01730278ad7069f76c044afe0063bee883ae1d25938dd4a708536c24c9dcc186287f6f91511308fc32bb554");

    // French mnemonic with combining accents still Decodes / seeds.
    SecureString fr = mnemonic_2;
    int lang = -1;
    std::string sError;
    std::vector<uint8_t, secure_allocator<uint8_t>> entropy;
    BOOST_CHECK_EQUAL(0, mnemonic::Decode(lang, fr, entropy, sError));
    BOOST_CHECK_EQUAL(lang, mnemonic::WLL_FRENCH);
}

BOOST_AUTO_TEST_CASE(mnemonic_wordlist_identity)
{
    struct Expect {
        int language;
        const char* first;
        const char* last;
    };
    // First/last words from official BIP-0039/*.txt (2048 words each).
    const Expect expects[] = {
        {mnemonic::WLL_ENGLISH, "abandon", "zoo"},
        {mnemonic::WLL_FRENCH, "abaisser", "zoologie"},
        {mnemonic::WLL_JAPANESE, "あいこくしん", "われる"},
        {mnemonic::WLL_SPANISH, "ábaco", "zurdo"},
        {mnemonic::WLL_CHINESE_S, "的", "歇"},
        {mnemonic::WLL_CHINESE_T, "的", "歇"},
        {mnemonic::WLL_ITALIAN, "abaco", "zuppa"},
        {mnemonic::WLL_KOREAN, "가격", "힘껏"},
        {mnemonic::WLL_CZECH, "abdikace", "zvyk"},
        {mnemonic::WLL_PORTUGUESE, "abacate", "zumbido"},
    };

    for (const Expect& e : expects) {
        BOOST_REQUIRE(mnemonic::HaveLanguage(e.language));
        std::string sError;
        SecureString first, last, overflow;
        BOOST_CHECK_EQUAL(0, mnemonic::GetWord(e.language, 0, first, sError));
        BOOST_CHECK_EQUAL(std::string(first.c_str()), e.first);
        BOOST_CHECK_EQUAL(0, mnemonic::GetWord(e.language, 2047, last, sError));
        BOOST_CHECK_EQUAL(std::string(last.c_str()), e.last);
        BOOST_CHECK(0 != mnemonic::GetWord(e.language, 2048, overflow, sError));
    }
}

BOOST_AUTO_TEST_SUITE_END()
