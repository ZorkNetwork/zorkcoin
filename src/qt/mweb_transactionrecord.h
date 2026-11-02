// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MWEB_TRANSACTIONRECORD_H
#define BITCOIN_QT_MWEB_TRANSACTIONRECORD_H

//! Qt presentation helpers for WalletTx MWEB metadata (history + details).

#include <consensus/amount.h>
#include <qt/bitcoinunits.h>

#include <QString>

#include <string>
#include <vector>

namespace interfaces {
struct WalletTx;
}

namespace mweb_gui {

/** Wallet residual fee already computed in MakeWalletTx. */
CAmount DisplayFee(const interfaces::WalletTx& wtx);

/** Fold mweb_txin_is_mine into all_from_me / any_from_me. */
void IncludeMWEBInputsInFromMe(const interfaces::WalletTx& wtx, bool& all_from_me, bool& any_from_me);

/**
 * Fold mweb_outs + pegout_is_mine into all_to_me so empty L1 vout is not
 * vacuously “all to me”.
 */
void IncludeMWEBOutputsInToMe(const interfaces::WalletTx& wtx, bool& all_to_me);

/** One history row for an MWEB output or peg-out. */
struct ExtensionRecord {
    enum class Kind { SendToAddress, SendToOther, RecvWithAddress, RecvFromOther };
    Kind kind;
    std::string address;
    CAmount debit{0};
    CAmount credit{0};
    int idx;
};

/**
 * MWEB + pegout history rows, appended after the L1 vout loop.
 * Rows follow CachedTxGetAmounts / AppendMWEBOutputAmounts for coins the wallet can
 * read; unlike the RPC, sent outputs the wallet can't read are not shown.
 */
std::vector<ExtensionRecord> ExtensionRecords(const interfaces::WalletTx& wtx, bool all_from_me, CAmount& nTxFee);

/** Per-out HTML for mweb_outs (credit and debit details paths). */
QString FormatMWEBOutsHtml(const interfaces::WalletTx& wtx, BitcoinUnit unit, bool all_from_me);

} // namespace mweb_gui

#endif // BITCOIN_QT_MWEB_TRANSACTIONRECORD_H
