// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_STANDARD_H
#define BITCOIN_SCRIPT_STANDARD_H

#include <mw/models/crypto/hash.h>
#include <primitives/transaction.h>
#include <script/script.h>

// MWEB: Peg-in script and output helpers (merge hook; see addresstype.h for CTxDestination).
CScript GetScriptForPegin(const mw::Hash& kernel_id);
bool IsPegInOutput(const CTxOutput& output);

#endif // BITCOIN_SCRIPT_STANDARD_H
