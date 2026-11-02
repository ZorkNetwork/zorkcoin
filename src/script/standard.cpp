// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/standard.h>

#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>

#include <cstdint>
#include <span>
#include <vector>

CScript GetScriptForPegin(const mw::Hash& kernel_id)
{
    CScript script;
    script << CScript::EncodeOP_N(MWEB_PEGIN_WITNESS_VERSION);
    script << kernel_id.vec();
    return script;
}

bool IsPegInOutput(const CTxOutput& output)
{
    if (!output.IsMWEB()) {
        std::vector<std::vector<uint8_t>> solutions_data;
        const auto which_type = Solver(output.GetTxOut().scriptPubKey, solutions_data);
        return which_type == TxoutType::WITNESS_MWEB_PEGIN;
    }

    return false;
}
