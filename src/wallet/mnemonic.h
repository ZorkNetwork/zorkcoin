// Copyright (c) 2014-2015 The ShadowCoin developers
// Copyright (c) 2017-2026 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MNEMONIC_H
#define BITCOIN_WALLET_MNEMONIC_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <support/allocators/secure.h>

namespace mnemonic {

enum WordListLanguages
{
    WLL_ENGLISH         = 1,
    WLL_FRENCH          = 2,
    WLL_JAPANESE        = 3,
    WLL_SPANISH         = 4,
    WLL_CHINESE_S       = 5,
    WLL_CHINESE_T       = 6,
    WLL_ITALIAN         = 7,
    WLL_KOREAN          = 8,
    WLL_CZECH           = 9,
    WLL_PORTUGUESE      = 10,

    WLL_MAX
};

extern const char *mnLanguagesDesc[WLL_MAX];
extern const char *mnLanguagesTag[WLL_MAX];

int GetWord(int o, const char *pwl, int max, SecureString &sWord);
int GetWordOffset(const char *p, size_t word_len, const char *pwl, int max, int &o);

int GetLanguageOffset(std::string sIn);
int DetectLanguage(const SecureString &sWordList);
int Encode(int nLanguage, const std::vector<uint8_t, secure_allocator<uint8_t>> &vEntropy, SecureString &sWordList, std::string &sError);
int Decode(int &nLanguage, const SecureString &sWordListIn, std::vector<uint8_t, secure_allocator<uint8_t>> &vEntropy, std::string &sError, bool fIgnoreChecksum=false);
int ToSeed(const SecureString &sMnemonic, const SecureString &sPasswordIn, std::vector<uint8_t, secure_allocator<uint8_t>> &vSeed);
int AddChecksum(int nLanguageIn, const SecureString &sWordListIn, SecureString &sWordListOut, std::string &sError);
int GetWord(int nLanguage, int nWord, SecureString &sWord, std::string &sError);
std::string GetLanguage(int nLanguage);
std::string ListEnabledLanguages(std::string separator);
bool HaveLanguage(int nLanguage);

/** BIP39 entropy length for a supported word count (12/15/18/21/24 → 16..32). Returns 0 if unsupported. */
size_t EntropyBytesForWordCount(int wordcount);

} // namespace mnemonic

#endif // BITCOIN_WALLET_MNEMONIC_H
