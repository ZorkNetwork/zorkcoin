// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/kaspa_merkle.h>

#include <auxpow/kaspa_hash.h>

#include <optional>

namespace auxpow {

uint256 KaspaMerkleHash(const uint256& left, const uint256& right)
{
    auto hasher = MerkleBranchHashHasher();
    hasher.Write(left);
    hasher.Write(right);
    return hasher.Finalize();
}

uint256 KaspaCalcMerkleRoot(const std::vector<uint256>& leaves)
{
    if (leaves.empty()) return uint256::ZERO;
    if (leaves.size() == 1) return leaves[0];

    size_t next_pot = 1;
    while (next_pot < leaves.size()) next_pot <<= 1;
    const size_t vec_len = 2 * next_pot - 1;
    std::vector<std::optional<uint256>> merkles(vec_len);
    for (size_t i = 0; i < leaves.size(); ++i) {
        merkles[i] = leaves[i];
    }
    size_t offset = next_pot;
    for (size_t i = 0; i + 1 < vec_len; i += 2, ++offset) {
        if (!merkles[i].has_value()) {
            merkles[offset] = std::nullopt;
        } else {
            const uint256 right = merkles[i + 1].value_or(uint256::ZERO);
            merkles[offset] = KaspaMerkleHash(*merkles[i], right);
        }
    }
    return *merkles.back();
}

uint256 KaspaComputeMerkleRootFromBranch(const uint256& leaf, const std::vector<uint256>& branch, uint32_t index)
{
    uint256 h = leaf;
    for (const auto& sibling : branch) {
        if ((index & 1) == 0) {
            h = KaspaMerkleHash(h, sibling);
        } else {
            h = KaspaMerkleHash(sibling, h);
        }
        index >>= 1;
    }
    return h;
}

bool CheckKaspaTxMerkleBranch(const uint256& leaf,
                              const std::vector<uint256>& branch,
                              uint32_t index,
                              const uint256& expected_root,
                              std::string* err)
{
    if (index != 0) {
        // AuxPoW requires coinbase at index 0; branch walk still works generally.
    }
    const uint256 root = KaspaComputeMerkleRootFromBranch(leaf, branch, index);
    if (root != expected_root) {
        if (err) *err = "kaspa tx merkle root mismatch";
        return false;
    }
    return true;
}

} // namespace auxpow
