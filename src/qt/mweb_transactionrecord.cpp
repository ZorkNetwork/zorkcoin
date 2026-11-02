// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mweb_transactionrecord.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>

#include <interfaces/wallet.h>
#include <key_io.h>
#include <mw/models/tx/peg_out_coin.h>

#include <QCoreApplication>
#include <QString>

#include <string>
#include <variant>
#include <vector>

namespace mweb_gui {
namespace {

//! Extension/pegout rows use a high idx namespace so updateStatus %03d sort stays sane.
constexpr int EXT_IDX_BASE = 100000;

class MwebGuiTr
{
    Q_DECLARE_TR_FUNCTIONS(MwebGuiTr)
};

} // namespace

CAmount DisplayFee(const interfaces::WalletTx& wtx)
{
    return wtx.fee;
}

void IncludeMWEBInputsInFromMe(const interfaces::WalletTx& wtx, bool& all_from_me, bool& any_from_me)
{
    if (wtx.is_coinbase) return;
    for (const bool mine : wtx.mweb_txin_is_mine) {
        all_from_me = all_from_me && mine;
        if (mine) any_from_me = true;
    }
}

void IncludeMWEBOutputsInToMe(const interfaces::WalletTx& wtx, bool& all_to_me)
{
    for (const auto& out : wtx.mweb_outs) {
        if (!out.is_mine) {
            all_to_me = false;
            return;
        }
    }
    for (const bool mine : wtx.pegout_is_mine) {
        if (!mine) {
            all_to_me = false;
            return;
        }
    }
}

std::vector<ExtensionRecord> ExtensionRecords(const interfaces::WalletTx& wtx, bool all_from_me, CAmount& nTxFee)
{
    std::vector<ExtensionRecord> records;
    const bool debiting = wtx.debit > 0;
    int next_idx = EXT_IDX_BASE;

    auto fold_fee = [&](CAmount& value) {
        if (nTxFee > 0) {
            value += nTxFee;
            nTxFee = 0;
        }
    };
    auto send = [&](bool has_addr, const CTxDestination& dest, CAmount value) {
        fold_fee(value);
        records.push_back({has_addr ? ExtensionRecord::Kind::SendToAddress : ExtensionRecord::Kind::SendToOther,
                           has_addr ? EncodeDestination(dest) : wtx.comment_to.value_or(""),
                           /*debit=*/-value, /*credit=*/0, next_idx++});
    };
    auto receive = [&](bool has_addr, const CTxDestination& dest, CAmount value) {
        records.push_back({has_addr ? ExtensionRecord::Kind::RecvWithAddress : ExtensionRecord::Kind::RecvFromOther,
                           has_addr ? EncodeDestination(dest) : wtx.from.value_or(""),
                           /*debit=*/0, /*credit=*/value, next_idx++});
    };

    for (const auto& out : wtx.mweb_outs) {
        const bool has_addr = !std::get_if<CNoDestination>(&out.address);

        // Mirror AppendMWEBOutputAmounts: when debiting, skip change entirely.
        if (debiting && out.is_change) {
            continue;
        }
        // Sends: skip unknown non-mine (no sender-info address).
        if (debiting && all_from_me && (out.is_mine || has_addr)) {
            send(has_addr, out.address, out.amount);
        }

        // Receives: mine outs (RPC send+receive detail pairs for non-change).
        if (out.is_mine) {
            receive(has_addr, out.address, out.amount);
        }
    }

    for (size_t i = 0; i < wtx.pegouts.size(); ++i) {
        const PegOutCoin& pegout = wtx.pegouts[i];
        const bool mine = i < wtx.pegout_is_mine.size() && wtx.pegout_is_mine[i];
        CTxDestination dest;
        const bool has_addr = ExtractDestination(pegout.GetScriptPubKey(), dest);

        if (debiting) {
            send(has_addr, dest, pegout.GetAmount());
        }
        if (mine) {
            receive(has_addr, dest, pegout.GetAmount());
        }
    }
    return records;
}

QString FormatMWEBOutsHtml(const interfaces::WalletTx& wtx, BitcoinUnit unit, bool all_from_me)
{
    QString strHTML;
    for (const auto& out : wtx.mweb_outs) {
        const bool has_addr = !std::get_if<CNoDestination>(&out.address);

        if (all_from_me && wtx.debit > 0) {
            if (out.is_change) continue;
            if (!out.is_mine && !has_addr) continue;

            if (has_addr) {
                strHTML += "<b>" + MwebGuiTr::tr("To") + ":</b> ";
                strHTML += GUIUtil::HtmlEscape(EncodeDestination(out.address));
                if (out.is_mine) {
                    strHTML += " (" + MwebGuiTr::tr("own address") + ")";
                }
                strHTML += "<br>";
            }
            strHTML += "<b>" + MwebGuiTr::tr("Debit") + ":</b> " +
                       BitcoinUnits::formatHtmlWithUnit(unit, -out.amount) + "<br>";
            if (out.is_mine) {
                strHTML += "<b>" + MwebGuiTr::tr("Credit") + ":</b> " +
                           BitcoinUnits::formatHtmlWithUnit(unit, out.amount) + "<br>";
            }
        } else if (out.is_mine) {
            if (has_addr) {
                strHTML += "<b>" + MwebGuiTr::tr("To") + ":</b> ";
                strHTML += GUIUtil::HtmlEscape(EncodeDestination(out.address)) + "<br>";
            }
            strHTML += "<b>" + MwebGuiTr::tr("Credit") + ":</b> " +
                       BitcoinUnits::formatHtmlWithUnit(unit, out.amount) + "<br>";
        }
    }
    return strHTML;
}

} // namespace mweb_gui
