// This file is part of UniLib <http://github.com/ufal/unilib/>.
//
// Copyright 2014 Institute of Formal and Applied Linguistics, Faculty of
// Mathematics and Physics, Charles University in Prague, Czech Republic.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// UniLib version: 3.1.2-devel
// Unicode version: 8.0.0

#ifndef BITCOIN_UNILIB_UNINORMS_H
#define BITCOIN_UNILIB_UNINORMS_H

#include <cstdint>
#include <string>
#include <support/allocators/secure.h>

typedef std::basic_string<char32_t, std::char_traits<char32_t>, secure_allocator<char32_t>> U32String;

namespace ufal {
namespace unilib {

class uninorms {
 public:
  static void nfc(U32String& str);
  static void nfd(U32String& str);
  static void nfkc(U32String& str);
  static void nfkd(U32String& str);

 private:
  static void compose(U32String& str);
  static void decompose(U32String& str, bool kanonical);

  static const char32_t CHARS = 0x110000;

  struct Hangul {
    // Hangul decomposition and composition
    static const char32_t SBase = 0xAC00, LBase = 0x1100, VBase = 0x1161, TBase = 0x11A7;
    static const char32_t LCount = 19, VCount = 21, TCount = 28, NCount = VCount * TCount, SCount = LCount * NCount;
  };

  static const uint8_t ccc_index[CHARS >> 8];
  static const uint8_t ccc_block[][256];

  static const uint8_t composition_index[CHARS >> 8];
  static const uint16_t composition_block[][257];
  static const char32_t composition_data[];

  static const uint8_t decomposition_index[CHARS >> 8];
  static const uint16_t decomposition_block[][257];
  static const char32_t decomposition_data[];
};

} // namespace unilib
} // namespace ufal

#endif // BITCOIN_UNILIB_UNINORMS_H
