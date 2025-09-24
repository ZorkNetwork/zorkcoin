// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include <crypto/kheavyhash.h>

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 prePowHash;
    uint256 output;
    uint8_t time[8];
    uint8_t nonce[8];

    *(uint64_t*)time = (uint64_t)nTime*1000;  // time presently stored accurate to second only but should be in millisecconds
    *(uint64_t*)nonce = (uint64_t)nNonce;     // nonce presently stored as 32bit only but should be a 64 bit field

    // prePowHash = hash of header with zero timestamp and nonce
    prePowHash = CBlock(*this).GetPrePowBlockHeader().GetHash();

    KHeavyHash work = KHeavyHash(prePowHash);    
    work.Write(prePowHash).Write(time).Write(uint256().ZERO).Write(nonce);
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