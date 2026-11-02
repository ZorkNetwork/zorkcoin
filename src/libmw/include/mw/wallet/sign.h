// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_WALLET_SIGN_H
#define BITCOIN_LIBMW_INCLUDE_MW_WALLET_SIGN_H

#include <mw/common/macros.h>
#include <mw/models/crypto/hash.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/wallet/coin.h>

#include <primitives/transaction.h>
#include <util/result.h>

#include <functional>
#include <map>

MW_NAMESPACE

using SenderKeyGenerator = std::function<util::Result<SecretKey>()>;

struct SignTxResult {
    //! A coin for each output signed, keyed by output ID. Each coin carries
    //! the sender key, address, amount and raw blind of the output.
    std::map<mw::Hash, mw::Coin> coins_by_output_id;
};

//! Signs every unsigned kernel, output and input of tx.mweb_tx, then sets the
//! kernel and stealth offsets and validates the result.
//!
//! Kernels are signed first so peg-in outputs in tx.vout (matched to peg-in
//! kernels by relative order) can be rewritten with the final kernel IDs.
//! Any PrecomputedTransactionData built from tx must be rebuilt afterwards.
//!
//! On failure tx is left unchanged.
util::Result<SignTxResult> SignTx(CMutableTransaction& tx, const SecretKey& rewind_key, const SenderKeyGenerator& generate_sender_key) noexcept;

END_NAMESPACE

#endif // BITCOIN_LIBMW_INCLUDE_MW_WALLET_SIGN_H
