// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_KASPA_MERKLE_H
#define BITCOIN_AUXPOW_KASPA_MERKLE_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace auxpow {

uint256 KaspaMerkleHash(const uint256& left, const uint256& right);
uint256 KaspaCalcMerkleRoot(const std::vector<uint256>& leaves);

/** Walk merkle branch for leaf at index (Kaspa MerkleBranchHash). */
uint256 KaspaComputeMerkleRootFromBranch(const uint256& leaf, const std::vector<uint256>& branch, uint32_t index);

bool CheckKaspaTxMerkleBranch(const uint256& leaf,
                              const std::vector<uint256>& branch,
                              uint32_t index,
                              const uint256& expected_root,
                              std::string* err = nullptr);

} // namespace auxpow

#endif // BITCOIN_AUXPOW_KASPA_MERKLE_H
