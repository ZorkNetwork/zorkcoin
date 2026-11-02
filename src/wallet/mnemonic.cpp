// Copyright (c) 2014-2015 The ShadowCoin developers
// Copyright (c) 2017-2026 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#define ENABLE_BIP39_ENGLISH 1
#define ENABLE_BIP39_FRENCH 1
#define ENABLE_BIP39_JAPANESE 1
#define ENABLE_BIP39_SPANISH 1
#define ENABLE_BIP39_CHINESE_S 1
#define ENABLE_BIP39_CHINESE_T 1
#define ENABLE_BIP39_ITALIAN 1
#define ENABLE_BIP39_KOREAN 1
#define ENABLE_BIP39_CZECH 1
#define ENABLE_BIP39_PORTUGUESE 1

#include <wallet/mnemonic.h>

#include <crypto/hmac_sha512.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/log.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <unilib/uninorms.h>
#include <unilib/utf8.h>

#include <cstring>
#include <stdexcept>

#ifdef ENABLE_BIP39_ENGLISH
#include <wallet/wordlists/english.h>
#else
unsigned char *english_txt = nullptr;
uint32_t english_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_FRENCH
#include <wallet/wordlists/french.h>
#else
unsigned char *french_txt = nullptr;
uint32_t french_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_JAPANESE
#include <wallet/wordlists/japanese.h>
#else
unsigned char *japanese_txt = nullptr;
uint32_t japanese_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_SPANISH
#include <wallet/wordlists/spanish.h>
#else
unsigned char *spanish_txt = nullptr;
uint32_t spanish_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_CHINESE_S
#include <wallet/wordlists/chinese_simplified.h>
#else
unsigned char *chinese_simplified_txt = nullptr;
uint32_t chinese_simplified_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_CHINESE_T
#include <wallet/wordlists/chinese_traditional.h>
#else
unsigned char *chinese_traditional_txt = nullptr;
uint32_t chinese_traditional_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_ITALIAN
#include <wallet/wordlists/italian.h>
#else
unsigned char *italian_txt = nullptr;
uint32_t italian_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_KOREAN
#include <wallet/wordlists/korean.h>
#else
unsigned char *korean_txt = nullptr;
uint32_t korean_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_CZECH
#include <wallet/wordlists/czech.h>
#else
unsigned char *czech_txt = nullptr;
uint32_t czech_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_PORTUGUESE
#include <wallet/wordlists/portuguese.h>
#else
unsigned char *portuguese_txt = nullptr;
uint32_t portuguese_txt_len = 0;
#endif

namespace mnemonic {

namespace {
template <typename... Args>
int errorN(int n, util::ConstevalFormatString<sizeof...(Args)> fmt, const Args&... args)
{
    LogError("%s\n", tfm::format(fmt, args...));
    return n;
}

template <typename... Args>
int errorN(int n, std::string& s, const char* func, util::ConstevalFormatString<sizeof...(Args)> fmt, const Args&... args)
{
    s = tfm::format(fmt, args...);
    LogError("%s\n", std::string(func) + ": " + s);
    return n;
}
} // namespace


static const unsigned char *mnLanguages[] =
{
    nullptr,
    english_txt,
    french_txt,
    japanese_txt,
    spanish_txt,
    chinese_simplified_txt,
    chinese_traditional_txt,
    italian_txt,
    korean_txt,
    czech_txt,
    portuguese_txt,
};

static const uint32_t mnLanguageLens[] =
{
    0,
    english_txt_len,
    french_txt_len,
    japanese_txt_len,
    spanish_txt_len,
    chinese_simplified_txt_len,
    chinese_traditional_txt_len,
    italian_txt_len,
    korean_txt_len,
    czech_txt_len,
    portuguese_txt_len,
};

const char *mnLanguagesDesc[WLL_MAX] =
{
    nullptr,
    "English",
    "French",
    "Japanese",
    "Spanish",
    "Chinese Simplified",
    "Chinese Traditional",
    "Italian",
    "Korean",
    "Czech",
    "Portuguese",
};

const char *mnLanguagesTag[WLL_MAX] =
{
    nullptr,
    "english",
    "french",
    "japanese",
    "spanish",
    "chinese_s",
    "chinese_t",
    "italian",
    "korean",
    "czech",
    "portuguese",
};

static SecureString &LTrimWhitespace(SecureString &s)
{
    SecureString::iterator i;
    for (i = s.begin(); i != s.end(); ++i) {
        if (!IsSpace(*i)) {
            break;
        }
    }
    if (i != s.begin()) {
        s.erase(s.begin(), i);
    }
    return s;
}

static SecureString &RTrimWhitespace(SecureString &s)
{
    SecureString::reverse_iterator i;
    for (i = s.rbegin(); i != s.rend(); ++i) {
        if (!IsSpace(*i)) {
            break;
        }
    }
    if (i != s.rbegin()) {
        s.erase(i.base(), s.end());
    }
    return s;
}

SecureString &TrimWhitespace(SecureString &s)
{
    LTrimWhitespace(s);
    RTrimWhitespace(s);
    return s;
}

static void NormaliseUnicode(SecureString &str)
{
    if (str.size() < 1) {
        return;
    }
    U32String u32;
    ufal::unilib::utf8::decode(str.data(), str.size(), u32);
    ufal::unilib::uninorms::nfkd(u32);
    ufal::unilib::utf8::encode(u32, str);
}

static void NormaliseInput(SecureString &str)
{
    TrimWhitespace(str);
    NormaliseUnicode(str);
}

/** BIP39 passphrase: NFKD only — do not trim leading/trailing spaces (Trezor-style). */
static void NormalisePassphrase(SecureString &str)
{
    NormaliseUnicode(str);
}

static void ReplaceStrInPlace(SecureString &subject, const std::string search, const std::string replace)
{
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != SecureString::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}

int GetWord(int o, const char *pwl, int max, SecureString &sWord)
{
    sWord = "";
    char *pt = (char*)pwl;
    while (o > 0) {
        if (*pt == '\n') {
            o--;
        }
        pt++;
        if (pt >= pwl + max) {
            return 1;
        }
    }

    while (pt < (pwl + max)) {
        if (*pt == '\n') {
            return 0;
        }
        sWord += *pt;
        pt++;
    }

    return 1;
}

int GetWordOffset(const char *p, size_t word_len, const char *pwl, int max, int &o)
{
    // List must end with \n
    const char *pt = pwl;
    int i = 0;
    int c = 0;
    int f = 1;
    while (pt < (pwl + max)) {
        if (*pt == '\n') {
            if (f && c == static_cast<int>(word_len)) { // found
                o = i;
                return 0;
            }
            i++;
            c = 0;
            f = 1;
        } else {
            if (c >= static_cast<int>(word_len)) {
                f = 0;
            } else
            if (f && *(p + c) != *pt) {
                f = 0;
            }
            c++;
        }
        pt++;
    }
    return 1;
}

/** Split phrase on ASCII space without copying into an insecure stack buffer. */
template <typename Fn>
static void ForEachMnemonicWord(const SecureString& sWordList, Fn&& fn)
{
    const char* base = sWordList.data();
    const size_t n = sWordList.size();
    size_t i = 0;
    while (i < n) {
        while (i < n && base[i] == ' ') {
            ++i;
        }
        if (i >= n) {
            break;
        }
        const size_t start = i;
        while (i < n && base[i] != ' ') {
            ++i;
        }
        if (!fn(base + start, i - start)) {
            return;
        }
    }
}

int GetWordOffsets(int nLanguage, const SecureString &sWordList, std::vector<int, secure_allocator<int>> &vWordInts, std::string &sError)
{
    if (nLanguage < 1 || nLanguage >= WLL_MAX || !HaveLanguage(nLanguage)) {
        return errorN(1, sError, __func__, "Unknown language");
    }
    const char *pwl = (const char*) mnLanguages[nLanguage];
    int m = mnLanguageLens[nLanguage];
    if (sWordList.size() >= 4096) {
        return errorN(1, sError, __func__, "Word string is too long.");
    }

    int rv = 0;
    ForEachMnemonicWord(sWordList, [&](const char* word, size_t word_len) {
        int ofs;
        if (0 != GetWordOffset(word, word_len, pwl, m, ofs)) {
            // Return the token to the caller for UI/RPC errors, but never log it.
            sError = strprintf("Unknown word: %.*s", static_cast<int>(word_len), word);
            LogError("%s: Unknown word\n", __func__);
            rv = 3;
            return false;
        }
        vWordInts.push_back(ofs);
        return true;
    });
    return rv;
}

int CountLanguageWords(const char *pwl, int max) {
    // List must end with \n
    int num_words = 0;
    const char *pt = pwl;
    while (pt < (pwl + max)) {
        if (*pt == '\n') {
            num_words++;
        }
        pt++;
    }
    return num_words;
}

int GetLanguageOffset(std::string sIn)
{
    int nLanguage = -1;
    sIn = ToLower(sIn);

    for (size_t k = 1; k < WLL_MAX; ++k) {
        if (sIn != mnLanguagesTag[k]) {
            continue;
        }
        nLanguage = k;
        break;
    }

    if (nLanguage < 1 || nLanguage >= WLL_MAX || !HaveLanguage(nLanguage)) {
        throw std::runtime_error("Unknown language.");
    }

    return nLanguage;
}

int DetectLanguage(const SecureString &sWordList)
{
    // Try detect the language
    // Tolerate spelling mistakes, will be reported in other functions
    if (sWordList.size() >= 2048) {
        return errorN(-1, "%s: Word List too long.", __func__);
    }

    for (int l = 1; l < WLL_MAX; ++l) {
        const char *pwl = (const char*) mnLanguages[l];
        if (!pwl) {
            continue;
        }
        int m = mnLanguageLens[l];

        // The Chinese dialects have many words in common, match full phrase
        int maxTries = (l == WLL_CHINESE_S || l == WLL_CHINESE_T) ? 24 : 8;

        int nHit = 0;
        int nMiss = 0;
        ForEachMnemonicWord(sWordList, [&](const char* word, size_t word_len) {
            int ofs;
            if (0 == GetWordOffset(word, word_len, pwl, m, ofs)) {
                nHit++;
            } else {
                nMiss++;
            }
            if (!maxTries--) {
                return false;
            }
            return true;
        });

        // Chinese dialects overlap too much to tolerate failures
        if ((l == WLL_CHINESE_S || l == WLL_CHINESE_T) &&
            nMiss > 0) {
            continue;
        }

        if (nHit > nMiss && nMiss < 2) { // tolerate max 2 failures
            return l;
        }
    }

    return 0;
}

int Encode(int nLanguage, const std::vector<uint8_t, secure_allocator<uint8_t>> &vEntropy, SecureString &sWordList, std::string &sError)
{

    sWordList = "";

    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        sError = "Unknown language.";
        return errorN(1, "%s: %s", __func__, sError.c_str());
    }

    // BIP39 allows 128-256 bits of entropy (16-32 bytes).
    if (vEntropy.size() < 16 || vEntropy.size() > 32 || (vEntropy.size() % 4) != 0) {
        sError = "Entropy bytes out of range.";
        return errorN(2, "%s: %s", __func__, sError.c_str());
    }

    // Checksum is first ENT/32 bits of SHA256(entropy).
    uint8_t hash[32];
    CSHA256().Write(vEntropy.data(), vEntropy.size()).Finalize((uint8_t*)hash);

    int nCsSize = vEntropy.size() / 4; // checksum bits = ENT/32

    std::vector<uint8_t, secure_allocator<uint8_t>> vIn = vEntropy;

    int ncb = nCsSize/8;
    int r = nCsSize % 8;
    if (r != 0) {
        ncb++;
    }
    std::vector<uint8_t, secure_allocator<uint8_t>> vTmp(32);
    memcpy(&vTmp[0], &hash, ncb);
    memset(&vTmp[ncb], 0, 32-ncb);
    memory_cleanse(hash, sizeof(hash));

    vIn.insert(vIn.end(), vTmp.begin(), vTmp.end());

    std::vector<int, secure_allocator<int>> vWord;

    int nBits = vEntropy.size() * 8 + nCsSize;

    int i = 0;
    while (i < nBits) {
        int o = 0;
        int s = i / 8;
        int r = i % 8;

        uint8_t b1 = vIn[s];
        uint8_t b2 = vIn[s+1];

        o = (b1 << r) & 0xFF;
        o = o << (11 - 8);

        if (r > 5) {
            uint8_t b3 = vIn[s+2];
            o |= (b2 << (r-5));
            o |= (b3 >> (8-(r-5)));
        } else {
            o |= (int(b2)) >> ((8 - (11 - 8))-r);
        }

        o = o & 0x7FF;

        vWord.push_back(o);
        i += 11;
    }

    const char *pwl = (const char*) mnLanguages[nLanguage];
    int m = mnLanguageLens[nLanguage];

    for (size_t k = 0; k < vWord.size(); ++k) {
        int o = vWord[k];

        SecureString sWord;
        if (0 != GetWord(o, pwl, m, sWord)) {
            sError = strprintf("Word extract failed %d, language %d.", o, nLanguage);
            return errorN(3, "%s: %s", __func__, sError.c_str());
        }

        if (sWordList != "") {
            sWordList += " ";
        }
        sWordList += sWord;
    }

    if (nLanguage == WLL_JAPANESE) {
        ReplaceStrInPlace(sWordList, " ", "\u3000");
    }

    return 0;
}

int Decode(int &nLanguage, const SecureString &sWordListIn, std::vector<uint8_t, secure_allocator<uint8_t>> &vEntropy, std::string &sError, bool fIgnoreChecksum)
{

    SecureString sWordList = sWordListIn;
    NormaliseInput(sWordList);

    // Zero words after trim/NFKD (including whitespace-only input).
    if (sWordList.empty()) {
        sError = "Empty mnemonic";
        return errorN(1, "%s: %s", __func__, sError.c_str());
    }

    if (nLanguage == -1) {
        nLanguage = DetectLanguage(sWordList);
    }

    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        sError = "Unknown language";
        return errorN(1, "%s: %s", __func__, sError.c_str());
    }

    if (sWordList.size() >= 2048) {
        sError = "Word List too long.";
        return errorN(2, "%s: %s", __func__, sError.c_str());
    }

    if (strstr(sWordList.c_str(), "  ") != nullptr) {
        sError = "Multiple spaces between words";
        return errorN(4, "%s: %s", __func__, sError.c_str());
    }

    std::vector<int, secure_allocator<int>> vWordInts;
    int rv = GetWordOffsets(nLanguage, sWordList, vWordInts, sError);
    if (0 != rv) {
        return rv;
    }

    if (!fIgnoreChecksum &&
        vWordInts.size() % 3 != 0) {
        sError = "No. of words must be divisible by 3";
        return errorN(4, "%s: %s", __func__, sError.c_str());
    }

    int nBits = vWordInts.size() * 11;
    int nBytes = nBits/8 + (nBits % 8 == 0 ? 0 : 1);
    vEntropy.resize(nBytes);

    memset(vEntropy.data(), 0, nBytes);

    int i = 0;
    size_t wl = vWordInts.size();
    size_t el = vEntropy.size();
    for (size_t k = 0; k < wl; ++k) {
        int o = vWordInts[k];

        int s = i / 8;
        int r = i % 8;

        vEntropy[s] |= (o >> (r+3)) & 0x7FF;

        if (s < int(el)-1) {
            if (r > 5) {
                vEntropy[s+1] |= (uint8_t) ((o >> (r-5))) & 0x7FF;
                if (s < int(el)-2) {
                    vEntropy[s+2] |= (uint8_t) (o << (8-(r-5))) & 0x7FF;
                }
            } else {
                vEntropy[s+1] |= (uint8_t) (o << (5-r)) & 0x7FF;
            }
        }
        i += 11;
    }

    if (fIgnoreChecksum) {
        return 0;
    }

    // Checksum
    int nLenChecksum = nBits / 32;
    int nLenEntropy = nBits - nLenChecksum;

    int nBytesEntropy = nLenEntropy / 8;
    int nBytesChecksum = nLenChecksum / 8 + (nLenChecksum % 8 == 0 ? 0 : 1);

    std::vector<uint8_t, secure_allocator<uint8_t>> vCS, vCSTest;

    vCS.resize(nBytesChecksum);
    memcpy(vCS.data(), &vEntropy[nBytesEntropy], nBytesChecksum);

    vEntropy.resize(nBytesEntropy);

    uint8_t hash[32];
    CSHA256().Write(vEntropy.data(), vEntropy.size()).Finalize((uint8_t*)hash);

    vCSTest.resize(nBytesChecksum);
    memcpy(vCSTest.data(), &hash, nBytesChecksum);
    memory_cleanse(hash, sizeof(hash));

    int r = nLenChecksum % 8;
    if (r > 0) {
        vCSTest[nBytesChecksum-1] &= (((1<<r)-1) << (8-r));
    }
    if (vCSTest != vCS) {
        sError = "Checksum mismatch.";
        return errorN(5, "%s: %s", __func__, sError.c_str());
    }

    return 0;
};

static int mnemonicKdf(const uint8_t *password, size_t lenPassword,
    const uint8_t *salt, size_t lenSalt, size_t nIterations, uint8_t *out)
{
    /*
    https://tools.ietf.org/html/rfc2898
    5.2 PBKDF2

    F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
    where
        U_1 = PRF (P, S || INT (i)) ,
        U_2 = PRF (P, U_1) ,
        ...
        U_c = PRF (P, U_{c-1}) .
    */

    // Output length is always 64bytes, only 1 block

    if (nIterations < 1) {
        return 1;
    }

    uint8_t r[64];

    const unsigned char one_be[4] = {0, 0, 0, 1};
    CHMAC_SHA512 ctx(password, lenPassword);
    CHMAC_SHA512 ctx_state = ctx;
    ctx.Write(salt, lenSalt);
    ctx.Write(one_be, 4);
    ctx.Finalize(r);
    memcpy(out, r, 64);

    for (size_t k = 1; k < nIterations; ++k) {
        ctx= ctx_state;
        ctx.Write(r, 64);
        ctx.Finalize(r);

        for (size_t i = 0; i < 64; ++i) {
            out[i] ^= r[i];
        }
    }
    memory_cleanse(r, sizeof(r));

    return 0;
};

int ToSeed(const SecureString &sMnemonic, const SecureString &sPasswordIn, std::vector<uint8_t, secure_allocator<uint8_t>> &vSeed)
{

    vSeed.resize(64);

    SecureString sWordList = sMnemonic, sPassword = sPasswordIn;
    NormaliseInput(sWordList);
    // Passphrase: NFKD only (BIP39/Trezor). Do not TrimWhitespace — edged spaces are significant.
    NormalisePassphrase(sPassword);

    if (sWordList.empty()) {
        return errorN(1, "%s: Empty mnemonic.", __func__);
    }

    if (strstr(sWordList.c_str(), "  ") != nullptr) {
        return errorN(1, "%s: Multiple spaces between words.", __func__);
    }

    int nIterations = 2048;

    SecureString sSalt = SecureString("mnemonic") + sPassword;

    if (0 != mnemonicKdf((uint8_t*)sWordList.data(), sWordList.size(),
        (uint8_t*)sSalt.data(), sSalt.size(), nIterations, &vSeed[0])) {
        return errorN(1, "%s: mnemonicKdf failed.", __func__);
    }

    return 0;
};

int AddChecksum(int nLanguage, const SecureString &sWordListIn, SecureString &sWordListOut, std::string &sError)
{
    SecureString sWordList = sWordListIn;
    NormaliseInput(sWordList);

    sWordListOut = "";
    if (nLanguage == -1) {
        nLanguage = DetectLanguage(sWordList); // Needed here for Encode; Decode will complain if in error
    }

    int rv;
    std::vector<uint8_t, secure_allocator<uint8_t>> vEntropy;
    if (0 != (rv = Decode(nLanguage, sWordList, vEntropy, sError, true))) {
        return rv;
    }
    // Incomplete phrases are only usable when packed entropy is a BIP39 length.
    if (vEntropy.size() < 16 || vEntropy.size() > 32 || (vEntropy.size() % 4) != 0) {
        sError = "No. of words must be divisible by 3";
        return errorN(4, "%s: %s", __func__, sError.c_str());
    }
    if (0 != (rv = Encode(nLanguage, vEntropy, sWordListOut, sError))) {
        return rv;
    }
    if (0 != (rv = Decode(nLanguage, sWordListOut, vEntropy, sError))) {
        return rv;
    }

    return 0;
};

int GetWord(int nLanguage, int nWord, SecureString &sWord, std::string &sError)
{
    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        sError = "Unknown language.";
        return errorN(1, "%s: %s", __func__, sError.c_str());
    }

    const char *pwl = (const char*) mnLanguages[nLanguage];
    int m = mnLanguageLens[nLanguage];

    if (0 != GetWord(nWord, pwl, m, sWord)) {
        sError = strprintf("Word extract failed %d, language %d.", nWord, nLanguage);
        return errorN(3, "%s: %s", __func__, sError.c_str());
    }

    return 0;
};

std::string GetLanguage(int nLanguage)
{
    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        return "Unknown";
    }

    return mnLanguagesDesc[nLanguage];
};

std::string ListEnabledLanguages(std::string separator)
{
    std::string enabled_languages;
    for (size_t k = 1; k < WLL_MAX; ++k) {
        if (!HaveLanguage(k)) {
            continue;
        }
        if (enabled_languages.size()) {
            enabled_languages += separator;
        }
        enabled_languages += mnLanguagesTag[k];
    }
    return enabled_languages;
};

bool HaveLanguage(int nLanguage){
    return mnLanguages[nLanguage];
}

size_t EntropyBytesForWordCount(int wordcount)
{
    switch (wordcount) {
    case 12: return 16;
    case 15: return 20;
    case 18: return 24;
    case 21: return 28;
    case 24: return 32;
    default: return 0;
    }
}

} // namespace mnemonic
