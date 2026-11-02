// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <auxpow/check.h>
#include <auxpow/version.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <cassert>
#include <ios>
#include <string>

void initialize_auxpow()
{
    SelectParams(ChainType::REGTEST);
}

FUZZ_TARGET(auxpow, .init = initialize_auxpow)
{
    {
        auxpow::CAuxPow aux;
        bool parsed = false;
        try {
            SpanReader{buffer} >> aux;
            parsed = true;
        } catch (const std::ios_base::failure&) {
        }
        if (parsed) {
            DataStream round{};
            round << aux;
            auxpow::CAuxPow aux2;
            round >> aux2;
        }
    }

    CBlockHeader hdr;
    try {
        SpanReader{buffer} >> hdr;
    } catch (const std::ios_base::failure&) {
        return;
    }
    const uint256 hash = hdr.GetHash();
    if (auxpow::IsAuxPow(hdr.nVersion)) {
        assert(hdr.auxpow.has_value());
        assert(hdr.HasCompleteAuxPow());
        DataStream out{};
        out << hdr;
        assert(out.size() > 88);
        CBlockHeader mutated = hdr;
        mutated.auxpow->nChainIndex ^= 1;
        assert(mutated.GetHash() == hash);
        std::string err;
        (void)auxpow::CheckAuxPow(hdr, *hdr.auxpow, Params().GetConsensus(), &err);
    }
    DataStream round{};
    round << hdr;
    CBlockHeader hdr2;
    round >> hdr2;
    assert(hdr2.GetHash() == hash);
}
