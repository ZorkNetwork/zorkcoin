// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <crypto/kheavyhash.h>
#include <hash.h>
#include <tinyformat.h>

#include <cassert>
#include <memory>
#include <span>
#include <sstream>

uint256 CBlockHeader::GetHash() const
{
    HashWriter hw{};
    SerializeHashedFields(hw);
    return hw.GetHash();
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 output;
    std::span<const unsigned char> time{reinterpret_cast<const unsigned char*>(&nTime), sizeof(uint64_t)};
    std::span<const unsigned char> nonce{reinterpret_cast<const unsigned char*>(&nNonce), sizeof(uint64_t)};

    HashWriter pre{};
    GetPrePowBlockHeader().SerializeHashedFields(pre);
    const uint256 prePowHash = pre.GetHash();
    KHeavyHash work{prePowHash};
    work.Write(prePowHash).Write(time).Write(uint256::ZERO).Write(nonce);
    work.Finalize(output);
    return output;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

CTransactionRef CBlock::GetHogEx() const noexcept
{
    if (vtx.size() >= 2 && vtx.back()->IsHogEx()) {
        assert(!vtx.back()->vout.empty());
        return vtx.back();
    }
    return nullptr;
}
