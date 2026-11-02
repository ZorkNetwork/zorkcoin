// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_POLICY_H
#define BITCOIN_MWEB_MWEB_POLICY_H

#include <primitives/transaction_identifier.h>
#include <util/feefrac.h>

#include <optional>
#include <string>

class CTransaction;

namespace MWEB {

class Policy
{
public:
    /// Checks the transaction for violation of any MWEB-specific standard tx policies.
    static bool IsStandardTx(const CTransaction& tx, std::string& reason);

    /// Cheaply checks that an MWEB transaction is within the relay weight/input
    /// limits (much tighter than the consensus limits). Runs in mempool PreChecks
    /// before any MWEB crypto verification, to prevent a cheap-to-relay,
    /// expensive-to-verify DoS.
    static bool CheckWeight(const CTransaction& tx, std::string& reason);

    /// True when the txid/wtxid do not commit to all of the transaction's relay
    /// data: MWEB transactions, HogEx, and transactions with peg-in outputs (whose
    /// MWEB body may have been stripped). A rejection of such a transaction must
    /// not be cached by txid/wtxid, or an invalid variant could censor a valid one.
    static bool HasUncommittedMWEBPayload(const CTransaction& tx);

    /// Replacement fee-rate step for MWEB. Rule 4 charges the incremental relay fee
    /// on L1 vsize only, which an MWEB-only transaction lacks, so replacing one would
    /// cost almost nothing. When the replacement or a transaction it directly replaces
    /// carries MWEB data, the replacement must pay at least 1.5x the replaced
    /// transaction's fee rate. Fee rates are fee over adjusted weight (L1 weight plus
    /// MWEB weight), as the mempool ranks them. Returns an error string on failure.
    static std::optional<std::string> CheckReplacementFeeRate(const FeeFrac& replacement,
                                                              bool replacement_has_mweb,
                                                              const FeeFrac& replaced,
                                                              bool replaced_has_mweb,
                                                              const Txid& replaced_txid);
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_POLICY_H
