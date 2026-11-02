// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <key_io.h>
#include <mweb/mweb_rpc_serialization.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/peg_in_coin.h>
#include <mw/models/tx/peg_out_coin.h>
#include <policy/rbf.h>
#include <primitives/transaction_identifier.h>
#include <rpc/util.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/blockchain.h>
#include <util/vector.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

using interfaces::FoundBlock;

namespace wallet {
/**
 * Peg-outs paid by a HogEx that the wallet already lists through their MWEB transaction,
 * counted by script and amount. Only wallet transactions confirmed in the HogEx's block
 * can be paid by it.
 */
static std::map<std::pair<CScript, CAmount>, int> WalletPegoutsPaidByHogEx(const CWallet& wallet, const CWalletTx& hogex)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::map<std::pair<CScript, CAmount>, int> pegouts;
    const auto* hogex_conf = hogex.state<TxStateConfirmed>();
    if (!hogex_conf) return pegouts;
    for (const auto& [_, other_wtx] : wallet.mapWallet) {
        const auto* conf = other_wtx.state<TxStateConfirmed>();
        if (!conf || conf->confirmed_block_hash != hogex_conf->confirmed_block_hash || !other_wtx.GetTx()->HasMWEBTx()) {
            continue;
        }
        for (const PegOutCoin& pegout : other_wtx.GetTx()->mweb_tx.GetPegOuts()) {
            ++pegouts[{pegout.GetScriptPubKey(), pegout.GetAmount()}];
        }
    }
    return pegouts;
}

static void WalletTxToJSON(const CWallet& wallet, const CWalletTx& wtx, UniValue& entry)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    interfaces::Chain& chain = wallet.chain();
    int confirms = wallet.GetTxDepthInMainChain(wtx);
    entry.pushKV("confirmations", confirms);
    if (wtx.IsCoinBase())
        entry.pushKV("generated", true);
    if (auto* conf = wtx.state<TxStateConfirmed>())
    {
        entry.pushKV("blockhash", conf->confirmed_block_hash.GetHex());
        entry.pushKV("blockheight", conf->confirmed_block_height);
        entry.pushKV("blockindex", conf->position_in_block);
        int64_t block_time;
        CHECK_NONFATAL(chain.findBlock(conf->confirmed_block_hash, FoundBlock().time(block_time)));
        entry.pushKV("blocktime", block_time);
    } else {
        entry.pushKV("trusted", CachedTxIsTrusted(wallet, wtx));
    }
    entry.pushKV("txid", wtx.GetHash().GetHex());
    entry.pushKV("wtxid", wtx.GetWitnessHash().GetHex());
    UniValue alternate_wtxids(UniValue::VARR);
    for (const auto& [wtxid, _] : wtx.GetTxs()) {
        if (wtxid == wtx.GetWitnessHash()) continue;
        alternate_wtxids.push_back(wtxid.GetHex());
    }
    entry.pushKV("alternate_wtxids", alternate_wtxids);
    UniValue conflicts(UniValue::VARR);
    for (const Txid& conflict : wallet.GetTxConflicts(wtx))
        conflicts.push_back(conflict.GetHex());
    entry.pushKV("walletconflicts", std::move(conflicts));
    UniValue mempool_conflicts(UniValue::VARR);
    for (const Txid& mempool_conflict : wtx.mempool_conflicts)
        mempool_conflicts.push_back(mempool_conflict.GetHex());
    entry.pushKV("mempoolconflicts", std::move(mempool_conflicts));
    entry.pushKV("time", wtx.GetTxTime());
    entry.pushKV("timereceived", wtx.nTimeReceived);

    // Add opt-in RBF status
    if (chain.rpcEnableDeprecated("bip125")) {
        std::string rbfStatus = "no";
        if (confirms <= 0) {
            RBFTransactionState rbfState = chain.isRBFOptIn(*wtx.GetTx());
            if (rbfState == RBFTransactionState::UNKNOWN)
                rbfStatus = "unknown";
            else if (rbfState == RBFTransactionState::REPLACEABLE_BIP125)
                rbfStatus = "yes";
        }
        entry.pushKV("bip125-replaceable", rbfStatus);
    }

    if (wtx.m_comment) entry.pushKV("comment", *wtx.m_comment);
    if (wtx.m_comment_to) entry.pushKV("to", *wtx.m_comment_to);
    if (wtx.m_replaces_txid) entry.pushKV("replaces_txid", wtx.m_replaces_txid->ToString());
    if (wtx.m_replaced_by_txid) entry.pushKV("replaced_by_txid", wtx.m_replaced_by_txid->ToString());

    // MWEB hooks
    if (wtx.mweb_wtx_info) {
        UniValue partial_mweb(UniValue::VOBJ);
        if (wtx.mweb_wtx_info->received_coin) {
            UniValue received_entry(UniValue::VOBJ);
            const mw::Coin& received = *wtx.mweb_wtx_info->received_coin;
            received_entry.pushKV("output_id", received.output_id.ToHex());
            received_entry.pushKV("amount", received.amount); // MWEB: satoshis, as in Litecoin
            partial_mweb.pushKV("received", std::move(received_entry));
        }
        if (wtx.mweb_wtx_info->spent_input) {
            UniValue spent_entry(UniValue::VOBJ);
            spent_entry.pushKV("output_id", wtx.mweb_wtx_info->spent_input->ToHex());
            partial_mweb.pushKV("spent", std::move(spent_entry));
        }
        entry.pushKV("partial_mweb", std::move(partial_mweb));
    }
}

struct tallyitem
{
    CAmount nAmount{0};
    int nConf{std::numeric_limits<int>::max()};
    std::vector<Txid> txids;
    tallyitem() = default;
};

static UniValue ListReceived(const CWallet& wallet, const UniValue& params, const bool by_label, const bool include_immature_coinbase) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull())
        nMinDepth = params[0].getInt<int>();

    // Whether to include empty labels
    bool fIncludeEmpty = false;
    if (!params[1].isNull())
        fIncludeEmpty = params[1].get_bool();

    std::optional<CTxDestination> filtered_address{std::nullopt};
    if (!by_label && !params[3].isNull() && !params[3].get_str().empty()) {
        if (!IsValidDestinationString(params[3].get_str())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "address_filter parameter was invalid");
        }
        filtered_address = DecodeDestination(params[3].get_str());
    }

    // Tally
    std::map<CTxDestination, tallyitem> mapTally;
    for (const auto& [_, wtx] : wallet.mapWallet) {

        int nDepth = wallet.GetTxDepthInMainChain(wtx);
        if (nDepth < nMinDepth)
            continue;

        // Coinbase with less than 1 confirmation is no longer in the main chain
        // MWEB: Litecoin lists HogEx outputs before they mature, so only coinbase is filtered.
        if ((wtx.IsCoinBase() && (nDepth < 1))
            || (wtx.IsCoinBase() && wallet.IsTxImmatureCoinBase(wtx) && !include_immature_coinbase)) {
            continue;
        }

        // MWEB: skip HogEx outputs whose MWEB transaction is listed instead, as in Litecoin.
        std::map<std::pair<CScript, CAmount>, int> listed_pegouts;
        if (wtx.GetTx()->IsHogEx()) listed_pegouts = WalletPegoutsPaidByHogEx(wallet, wtx);
        for (const CTxOut& txout : wtx.GetTx()->vout) {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            if (filtered_address && !(filtered_address == address)) {
                continue;
            }

            if (!wallet.IsMine(address))
                continue;

            if (auto it{listed_pegouts.find({txout.scriptPubKey, txout.nValue})}; it != listed_pegouts.end() && it->second > 0) {
                --it->second;
                continue;
            }

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
        }

        for (const auto& [address, coin] : WalletTxMWEBReceived(wallet, wtx)) {
            const CTxDestination dest = address;
            if (filtered_address && !(filtered_address == dest)) {
                continue;
            }
            tallyitem& item = mapTally[dest];
            item.nAmount += coin.amount;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
        }

        if (wtx.GetTx()->HasMWEBTx()) {
            for (const PegOutCoin& pegout : wtx.GetTx()->mweb_tx.GetPegOuts()) {
                CTxDestination address;
                if (!ExtractDestination(pegout.GetScriptPubKey(), address)) {
                    continue;
                }
                if (filtered_address && !(filtered_address == address)) {
                    continue;
                }
                if (!wallet.IsMine(address)) {
                    continue;
                }
                tallyitem& item = mapTally[address];
                item.nAmount += pegout.GetAmount();
                item.nConf = std::min(item.nConf, nDepth);
                item.txids.push_back(wtx.GetHash());
            }
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> label_tally;

    const auto& func = [&](const CTxDestination& address, const std::string& label, bool is_change,
                            const std::optional<AddressPurpose>& purpose) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        if (is_change) return; // no change addresses

        // Entries in mapTally are only ever added for wallet.IsMine() addresses (see the tally
        // loop above), so it's only addresses missing from mapTally that need the IsMine() check.
        auto it = mapTally.find(address);
        if (it == mapTally.end()) {
            if (!fIncludeEmpty) return;
            if (!wallet.IsMine(address)) return; // exclude addresses not owned by the wallet (e.g. "send" purpose)
        }

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (by_label) {
            tallyitem& _item = label_tally[label];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
        } else {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("address",       EncodeDestination(address));
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label", label);
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end()) {
                for (const Txid& _item : (*it).second.txids) {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.pushKV("txids", std::move(transactions));
            ret.push_back(std::move(obj));
        }
    };

    if (filtered_address) {
        const auto& entry = wallet.FindAddressBookEntry(*filtered_address, /*allow_change=*/false);
        if (entry) func(*filtered_address, entry->GetLabel(), entry->IsChange(), entry->purpose);
    } else {
        // No filtered addr, walk-through the addressbook entry
        wallet.ForEachAddrBookEntry(func);
    }

    if (by_label) {
        for (const auto& entry : label_tally) {
            CAmount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label",         entry.first);
            ret.push_back(std::move(obj));
        }
    }

    return ret;
}

RPCMethod listreceivedbyaddress()
{
    return RPCMethod{
        "listreceivedbyaddress",
        "List balances by receiving address.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to include addresses that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "(DEPRECATED) No longer used"},
                    {"address_filter", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If present and non-empty, only return information on this address."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "address", "The receiving address"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received by the address"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                            {RPCResult::Type::ARR, "txids", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The ids of transactions received with the address"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleCli("listreceivedbyaddress", "6 true true \"\" true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true, \"" + EXAMPLE_ADDRESS[0] + "\", true")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const bool include_immature_coinbase{request.params[4].isNull() ? false : request.params[4].get_bool()};

    LOCK(pwallet->cs_wallet);

    return ListReceived(*pwallet, request.params, false, include_immature_coinbase);
},
    };
}

RPCMethod listreceivedbylabel()
{
    return RPCMethod{
        "listreceivedbylabel",
        "List received transactions by label.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to include labels that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "(DEPRECATED) No longer used"},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount received by addresses with this label"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbylabel", "")
            + HelpExampleCli("listreceivedbylabel", "6 true")
            + HelpExampleRpc("listreceivedbylabel", "6, true, true, true")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const bool include_immature_coinbase{request.params[3].isNull() ? false : request.params[3].get_bool()};

    LOCK(pwallet->cs_wallet);

    return ListReceived(*pwallet, request.params, true, include_immature_coinbase);
},
    };
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest)) {
        entry.pushKV("address", EncodeDestination(dest));
    }
}

/**
 * List transactions based on the given criteria.
 *
 * @param  wallet         The wallet.
 * @param  wtx            The wallet transaction.
 * @param  nMinDepth      The minimum confirmation depth.
 * @param  fLong          Whether to include the JSON version of the transaction.
 * @param  ret            The vector into which the result is stored.
 * @param  filter_label   Optional label string to filter incoming transactions.
 */
template <class Vec>
static void ListTransactions(const CWallet& wallet, const CWalletTx& wtx, int nMinDepth, bool fLong,
                             Vec& ret, const std::optional<std::string>& filter_label,
                             bool include_change = false)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CAmount nFee;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    CachedTxGetAmounts(wallet, wtx, listReceived, listSent, nFee, include_change);

    // Sent
    if (!filter_label.has_value())
    {
        for (const COutputEntry& s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            MaybePushAddress(entry, s.destination);
            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-s.amount));
            const auto* address_book_entry = wallet.FindAddressBookEntry(s.destination);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }
            if (!s.mweb_out) {
                entry.pushKV("vout", s.vout);
            } else if (!s.mweb_out->IsZero()) { // MWEB: peg-outs have neither key, as in Litecoin
                entry.pushKV("mweb_out", s.mweb_out->ToHex());
            }
            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(wallet, wtx, entry);
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(std::move(entry));
        }
    }

    // Received
    if (listReceived.size() > 0 && wallet.GetTxDepthInMainChain(wtx) >= nMinDepth) {
        for (const COutputEntry& r : listReceived)
        {
            std::string label;
            const auto* address_book_entry = wallet.FindAddressBookEntry(r.destination);
            if (address_book_entry) {
                label = address_book_entry->GetLabel();
            }
            if (filter_label.has_value() && label != filter_label.value()) {
                continue;
            }
            UniValue entry(UniValue::VOBJ);
            MaybePushAddress(entry, r.destination);
            if (r.vout >= 0) {
                PushParentDescriptors(wallet, wtx.GetTx()->vout.at(r.vout).scriptPubKey, entry);
            }
            if (wtx.IsCoinBase() || wtx.GetTx()->IsHogEx()) // MWEB: HogEx categories as in Litecoin
            {
                if (wallet.GetTxDepthInMainChain(wtx) < 1)
                    entry.pushKV("category", "orphan");
                else if (wallet.IsTxImmatureCoinBase(wtx))
                    entry.pushKV("category", "immature");
                else if (wtx.IsCoinBase())
                    entry.pushKV("category", "generate");
                else
                    entry.pushKV("category", "hogex");
            }
            else
            {
                entry.pushKV("category", "receive");
            }
            entry.pushKV("amount", ValueFromAmount(r.amount));
            if (address_book_entry) {
                entry.pushKV("label", label);
            }
            if (r.mweb_out) {
                entry.pushKV("mweb_out", r.mweb_out->ToHex());
            } else {
                entry.pushKV("vout", r.vout);
            }
            entry.pushKV("abandoned", wtx.isAbandoned());
            if (fLong)
                WalletTxToJSON(wallet, wtx, entry);
            ret.push_back(std::move(entry));
        }
    }
}


static std::vector<RPCResult> TransactionDescriptionString()
{
    return{{RPCResult::Type::NUM, "confirmations", "The number of confirmations for the transaction. Negative confirmations means the\n"
               "transaction conflicted that many blocks ago."},
           {RPCResult::Type::BOOL, "generated", /*optional=*/true, "Only present if the transaction's only input is a coinbase one."},
           {RPCResult::Type::BOOL, "trusted", /*optional=*/true, "Whether we consider the transaction to be trusted and safe to spend from.\n"
                "Only present when the transaction has 0 confirmations (or negative confirmations, if conflicted)."},
           {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash containing the transaction."},
           {RPCResult::Type::NUM, "blockheight", /*optional=*/true, "The block height containing the transaction."},
           {RPCResult::Type::NUM, "blockindex", /*optional=*/true, "The index of the transaction in the block that includes it."},
           {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME_MS + "."},
           {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           {RPCResult::Type::STR_HEX, "wtxid", "The hash of serialized transaction, including witness data."},
           {RPCResult::Type::ARR, "alternate_wtxids", "The wtxids of transactions with different witness data but the same txid.",
           {
               {RPCResult::Type::STR_HEX, "wtxid", "The witness transaction id."},
           }},
           {RPCResult::Type::ARR, "walletconflicts", "Confirmed transactions that have been detected by the wallet to conflict with this transaction.",
           {
               {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           }},
           {RPCResult::Type::STR_HEX, "replaced_by_txid", /*optional=*/true, "Only if 'category' is 'send'. The txid if this tx was replaced."},
           {RPCResult::Type::STR_HEX, "replaces_txid", /*optional=*/true, "Only if 'category' is 'send'. The txid if this tx replaces another."},
           {RPCResult::Type::ARR, "mempoolconflicts", "Transactions in the mempool that directly conflict with either this transaction or an ancestor transaction",
           {
               {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           }},
           {RPCResult::Type::STR, "to", /*optional=*/true, "If a comment to is associated with the transaction."},
           {RPCResult::Type::NUM_TIME, "time", "The transaction time expressed in " + UNIX_EPOCH_TIME_MS + "."},
           {RPCResult::Type::NUM_TIME, "timereceived", "The time received expressed in " + UNIX_EPOCH_TIME_MS + "."},
           {RPCResult::Type::STR, "comment", /*optional=*/true, "If a comment is associated with the transaction, only present if not empty."},
           {RPCResult::Type::STR, "bip125-replaceable", /*optional=*/true, "(\"yes|no|unknown\") (DEPRECATED) Whether this transaction signals BIP125 replaceability or has an unconfirmed ancestor signaling BIP125 replaceability.\n"
               "May be unknown for unconfirmed transactions not in the mempool because their unconfirmed ancestors are unknown."},
           {RPCResult::Type::ARR, "parent_descs", /*optional=*/true, "Only if 'category' is 'receive'. List of parent descriptors for the output script of this coin.", {
               {RPCResult::Type::STR, "desc", "The descriptor string."},
           }},
           {RPCResult::Type::OBJ, "partial_mweb", /*optional=*/true, "MWEB partial transaction info.",
           {
               {RPCResult::Type::OBJ, "received", /*optional=*/true, "Received MWEB output.",
               {
                   {RPCResult::Type::STR_HEX, "output_id", "MWEB output id."},
                   {RPCResult::Type::NUM, "amount", "The amount in " + CURRENCY_ATOM + "s"},
               }},
               {RPCResult::Type::OBJ, "spent", /*optional=*/true, "Spent MWEB input.",
               {
                   {RPCResult::Type::STR_HEX, "output_id", "MWEB output id."},
               }},
           }},
           };
}

RPCMethod listtransactions()
{
    return RPCMethod{
        "listtransactions",
        "If a label name is provided, this will return only incoming transactions paying to addresses with the specified label.\n"
                "Returns up to 'count' most recent transactions ordered from oldest to newest while skipping the first number of \n"
                "transactions specified in the 'skip' argument. A transaction can have multiple entries in this RPC response. \n"
                "For instance, a wallet transaction that pays three addresses — one wallet-owned and two external — will produce \n"
                "four entries. The payment to the wallet-owned address appears both as a send entry and as a receive entry. \n"
                "As a result, the RPC response will contain one entry in the receive category and three entries in the send category.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, should be a valid label name to return only incoming transactions\n"
                          "with the specified label, or \"*\" to disable filtering and return all transactions."},
                    {"count", RPCArg::Type::NUM, RPCArg::Default{10}, "The number of transactions to return"},
                    {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "The number of transactions to skip"},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "(DEPRECATED) No longer used"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                        {
                            {RPCResult::Type::STR, "address",  /*optional=*/true, "The zorkcoin address of the transaction (not returned if the output does not have an address, e.g. OP_RETURN null data)."},
                            {RPCResult::Type::STR, "category", "The transaction category.\n"
                                "\"send\"                  Transactions sent.\n"
                                "\"receive\"               Non-coinbase transactions received.\n"
                                "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                "\"hogex\"                 Mature peg-out (HogEx) outputs received.\n"
                                "\"immature\"              Coinbase or HogEx transactions received that are not yet mature.\n"
                                "\"orphan\"                Orphaned coinbase or HogEx transactions received."},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                "for all other categories"},
                            {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                            {RPCResult::Type::NUM, "vout", /*optional=*/true, "the vout value (omitted for MWEB extension outputs)"},
                            {RPCResult::Type::STR_HEX, "mweb_out", /*optional=*/true, "MWEB output id (present instead of vout for extension outputs)"},
                            {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                 "'send' category of transactions."},
                        },
                        TransactionDescriptionString()),
                        {
                            {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                        })},
                    }
                },
                RPCExamples{
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::optional<std::string> filter_label;
    if (!request.params[0].isNull() && request.params[0].get_str() != "*") {
        filter_label.emplace(LabelFromValue(request.params[0]));
        if (filter_label.value().empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Label argument must be a valid label name or \"*\".");
        }
    }
    int nCount = 10;
    if (!request.params[1].isNull())
        nCount = request.params[1].getInt<int>();
    int nFrom = 0;
    if (!request.params[2].isNull())
        nFrom = request.params[2].getInt<int>();

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    std::vector<UniValue> ret;
    {
        LOCK(pwallet->cs_wallet);

        const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

        // iterate backwards until we have nCount items to return:
        for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
        {
            CWalletTx *const pwtx = (*it).second;
            ListTransactions(*pwallet, *pwtx, 0, true, ret, filter_label);
            if ((int)ret.size() >= (nCount+nFrom)) break;
        }
    }

    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    auto txs_rev_it{std::make_move_iterator(ret.rend())};
    UniValue result{UniValue::VARR};
    result.push_backV(txs_rev_it - nFrom - nCount, txs_rev_it - nFrom); // Return oldest to newest
    return result;
},
    };
}

// MWEB: listwallettransactions, Litecoin's GUI transaction list (wallet/txlist.cpp, wallet/txrecord.cpp).
namespace {
struct WalletTxRecord {
    enum class Type { Other, Generated, SendToAddress, SendToOther, RecvWithAddress, RecvFromOther, SendToSelf };
    struct PegoutIndex {
        mw::Hash kernel_id;
        size_t pos;
    };

    const CWalletTx* wtx;
    std::variant<std::monostate, int, mw::Hash, PegoutIndex> index{};
    Type type{Type::Other};
    std::string address{};
    CAmount debit{0};
    CAmount credit{0};
    CAmount fee{0};
    std::string sort_key{};
};

//! An L1 output, or an MWEB output with what the wallet knows about it.
struct TxListOutput {
    std::variant<int, mw::Hash> index;
    CAmount value{0};
    bool mine{false};
    bool change{false};
    bool pegin{false};
    bool pegin_in_tx{false};
    std::optional<CTxDestination> address{};
    bool address_mine{false};
};

std::vector<TxListOutput> TxListOutputs(const CWallet& wallet, const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::vector<TxListOutput> outputs;
    const CTransaction& tx = *wtx.GetTx();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const CTxOut& txout = tx.vout[i];
        TxListOutput out{.index = static_cast<int>(i), .value = txout.nValue, .mine = wallet.IsMine(txout),
                         .change = OutputIsChange(wallet, txout)};
        mw::Hash kernel_id;
        out.pegin = txout.scriptPubKey.IsMWEBPegin(&kernel_id);
        out.pegin_in_tx = out.pegin && tx.HasMWEBTx() && tx.mweb_tx.GetKernelIDs().contains(kernel_id);
        CTxDestination dest;
        if (ExtractDestination(txout.scriptPubKey, dest)) {
            out.address = dest;
            out.address_mine = wallet.IsMine(dest);
        }
        outputs.push_back(std::move(out));
    }
    const auto add_mweb_output = [&](const mw::Hash& output_id, const mw::Coin* coin) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        TxListOutput out{.index = output_id};
        if (coin) {
            out.value = coin->amount;
            out.mine = coin->IsMine();
            out.change = coin->IsMine() && coin->IsChange();
            StealthAddress stealth;
            if (coin->HasAddress()) {
                out.address = *coin->address;
            } else if (wallet.GetMWWallet()->GetStealthAddress(*coin, stealth)) {
                out.address = stealth;
            }
            out.address_mine = out.address && wallet.IsMine(*out.address);
        }
        outputs.push_back(std::move(out));
    };
    if (tx.HasMWEBTx()) {
        for (const Output& output : tx.mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin coin;
            const bool known{wallet.GetCoin(output.GetOutputID(), coin)};
            add_mweb_output(output.GetOutputID(), known ? &coin : nullptr);
        }
    } else if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
        add_mweb_output(wtx.mweb_wtx_info->received_coin->output_id, &*wtx.mweb_wtx_info->received_coin);
    }
    return outputs;
}

std::string EncodeTxListDestination(const std::optional<CTxDestination>& dest)
{
    return dest ? EncodeDestination(*dest) : "";
}

void ListWalletTx(const CWallet& wallet, const CWalletTx& wtx, std::vector<WalletTxRecord>& records) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const CTransaction& tx = *wtx.GetTx();
    const std::vector<TxListOutput> outputs{TxListOutputs(wallet, wtx)};

    struct Pegout {
        WalletTxRecord::PegoutIndex index;
        CAmount amount;
        std::optional<CTxDestination> address;
        bool mine;
    };
    std::vector<Pegout> pegouts;
    if (tx.HasMWEBTx()) {
        for (const Kernel& kernel : tx.mweb_tx.m_transaction->GetKernels()) {
            for (size_t i = 0; i < kernel.GetPegOuts().size(); ++i) {
                const PegOutCoin& pegout = kernel.GetPegOuts()[i];
                CTxDestination dest;
                pegouts.push_back({{kernel.GetKernelID(), i}, pegout.GetAmount(),
                                   ExtractDestination(pegout.GetScriptPubKey(), dest) ? std::optional{dest} : std::nullopt,
                                   wallet.IsMine(pegout.GetScriptPubKey())});
            }
        }
    }

    bool any_input_mine{false};
    bool all_inputs_mine{true};
    CAmount debit{0};
    const auto add_input = [&](bool mine, CAmount value) {
        any_input_mine |= mine;
        all_inputs_mine &= mine;
        if (mine) debit += value;
    };
    for (const CTxIn& txin : tx.vin) {
        add_input(InputIsMine(wallet, txin), wallet.GetDebit(txin));
    }
    const auto add_mweb_input = [&](const mw::Hash& output_id) {
        mw::Coin coin;
        const bool mine{wallet.GetCoin(output_id, coin) && coin.IsMine()};
        add_input(mine, mine ? coin.amount : 0);
    };
    if (tx.HasMWEBTx()) {
        for (const Input& input : tx.mweb_tx.m_transaction->GetInputs()) add_mweb_input(input.GetOutputID());
    } else if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->spent_input) {
        add_mweb_input(*wtx.mweb_wtx_info->spent_input);
    }

    CAmount credit{0};
    CAmount change{0};
    for (const TxListOutput& out : outputs) {
        if (out.mine) credit += out.value;
        if (out.change) change += out.value;
    }
    for (const Pegout& pegout : pegouts) {
        if (pegout.mine) credit += pegout.amount;
    }
    const bool any_output_mine{std::any_of(outputs.begin(), outputs.end(), [](const TxListOutput& o) { return o.mine; }) ||
                               std::any_of(pegouts.begin(), pegouts.end(), [](const Pegout& p) { return p.mine; })};
    if (!any_input_mine && !any_output_mine) return;

    const auto record = [&](auto index, WalletTxRecord::Type type, std::string address) -> WalletTxRecord& {
        return records.emplace_back(WalletTxRecord{.wtx = &wtx, .index = index, .type = type, .address = std::move(address)});
    };
    const CAmount net{credit - debit};
    if (net > 0 || wtx.IsCoinBase() || tx.IsHogEx()) {
        // A HogEx output is listed through its MWEB transaction when the wallet has it.
        auto listed_pegouts = tx.IsHogEx() ? WalletPegoutsPaidByHogEx(wallet, wtx) : std::map<std::pair<CScript, CAmount>, int>{};
        for (const TxListOutput& out : outputs) {
            if (out.pegin || !out.mine) continue;
            if (const int* vout = std::get_if<int>(&out.index); vout && tx.IsHogEx()) {
                const auto it = listed_pegouts.find({tx.vout[*vout].scriptPubKey, out.value});
                if (it != listed_pegouts.end() && it->second > 0) {
                    --it->second;
                    continue;
                }
            }
            using Type = WalletTxRecord::Type;
            const Type type{wtx.IsCoinBase() ? Type::Generated : out.address_mine ? Type::RecvWithAddress : Type::RecvFromOther};
            auto& rec = std::visit([&](const auto& index) -> WalletTxRecord& {
                return record(index, type, out.address_mine ? EncodeTxListDestination(out.address) : wtx.m_from.value_or(""));
            }, out.index);
            rec.credit = out.value;
        }
        for (const Pegout& pegout : pegouts) {
            if (!pegout.mine) continue;
            record(pegout.index, WalletTxRecord::Type::RecvWithAddress, EncodeTxListDestination(pegout.address)).credit = pegout.amount;
        }
    } else if (all_inputs_mine) {
        const bool all_to_me{std::all_of(outputs.begin(), outputs.end(), [](const TxListOutput& o) { return o.pegin_in_tx || o.mine; }) &&
                             std::all_of(pegouts.begin(), pegouts.end(), [](const Pegout& p) { return p.mine; })};
        if (all_to_me) {
            std::string addresses;
            const auto add_address = [&](const std::optional<CTxDestination>& dest) {
                if (!dest) return;
                if (!addresses.empty()) addresses += ", ";
                addresses += EncodeDestination(*dest);
            };
            for (const TxListOutput& out : outputs) {
                if (!out.pegin) add_address(out.address);
            }
            for (const Pegout& pegout : pegouts) add_address(pegout.address);
            WalletTxRecord& rec{record(std::monostate{}, WalletTxRecord::Type::SendToSelf, std::move(addresses))};
            rec.debit = -(debit - change);
            rec.credit = credit - change;
        } else {
            CAmount tx_fee{CachedTxGetFee(wallet, wtx)};
            const auto add_fee = [&](WalletTxRecord& rec) {
                if (tx_fee > 0) {
                    rec.fee = -tx_fee;
                    tx_fee = 0;
                }
            };
            for (const TxListOutput& out : outputs) {
                // Change, and a peg-in this transaction's own MWEB data spends, are not sends.
                if (out.pegin_in_tx || out.mine) continue;
                using Type = WalletTxRecord::Type;
                auto& rec = std::visit([&](const auto& index) -> WalletTxRecord& {
                    return out.address ? record(index, Type::SendToAddress, EncodeDestination(*out.address))
                                       : record(index, Type::SendToOther, wtx.m_comment_to.value_or(""));
                }, out.index);
                rec.debit = -out.value;
                add_fee(rec);
            }
            for (const Pegout& pegout : pegouts) {
                if (pegout.mine) continue;
                WalletTxRecord& rec{record(pegout.index, WalletTxRecord::Type::SendToAddress, EncodeTxListDestination(pegout.address))};
                rec.debit = -pegout.amount;
                add_fee(rec);
            }
        }
    } else {
        // Mixed debit transaction, can't break down payees
        record(std::monostate{}, WalletTxRecord::Type::Other, "").debit = net;
    }
}

std::string WalletTxRecordSortKey(const CWallet& wallet, const WalletTxRecord& rec) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    // Standard outputs first, then MWEB outputs, then peg-outs.
    std::string idx{strprintf("0%03d", 0)};
    if (const int* vout = std::get_if<int>(&rec.index)) {
        idx = strprintf("0%03d", *vout);
    } else if (const mw::Hash* output_id = std::get_if<mw::Hash>(&rec.index)) {
        idx = "1" + output_id->ToHex();
    } else if (const auto* pegout = std::get_if<WalletTxRecord::PegoutIndex>(&rec.index)) {
        idx = "2" + pegout->kernel_id.ToHex() + strprintf("%03d", pegout->pos);
    }
    const auto* conf = rec.wtx->state<TxStateConfirmed>();
    return strprintf("%010d-%01d-%010u-%s", conf ? conf->confirmed_block_height : std::numeric_limits<int>::max(),
                     rec.wtx->IsCoinBase() ? 1 : 0, rec.wtx->nTimeReceived, idx);
}

UniValue WalletTxRecordToJSON(const CWallet& wallet, const WalletTxRecord& rec) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    using Type = WalletTxRecord::Type;
    static const std::map<Type, std::string> type_names{
        {Type::Other, "Other"}, {Type::Generated, "Generated"}, {Type::SendToAddress, "SendToAddress"},
        {Type::SendToOther, "SendToOther"}, {Type::RecvWithAddress, "RecvWithAddress"},
        {Type::RecvFromOther, "RecvFromOther"}, {Type::SendToSelf, "SendToSelf"}};
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("type", type_names.at(rec.type));
    entry.pushKV("amount", ValueFromAmount(rec.credit > 0 ? rec.credit : rec.debit));
    entry.pushKV("net", ValueFromAmount(rec.credit + rec.debit + rec.fee));
    const CTxDestination dest{DecodeDestination(rec.address)};
    if (IsValidDestination(dest)) {
        if (const auto* address_book_entry = wallet.FindAddressBookEntry(dest)) {
            entry.pushKV("label", address_book_entry->GetLabel());
        }
    }
    if (!rec.address.empty()) entry.pushKV("address", rec.address);
    if (const int* vout = std::get_if<int>(&rec.index)) {
        entry.pushKV("vout", *vout);
    } else if (const mw::Hash* output_id = std::get_if<mw::Hash>(&rec.index)) {
        entry.pushKV("mweb_out", output_id->ToHex());
    } else if (const auto* pegout = std::get_if<WalletTxRecord::PegoutIndex>(&rec.index)) {
        entry.pushKV("pegout", strprintf("%s:%u", pegout->kernel_id.ToHex(), pegout->pos));
    }
    if (rec.debit < 0) {
        entry.pushKV("fee", ValueFromAmount(rec.fee));
        entry.pushKV("abandoned", rec.wtx->isAbandoned());
    }
    WalletTxToJSON(wallet, *rec.wtx, entry);
    return entry;
}
} // namespace

RPCMethod listwallettransactions()
{
    return RPCMethod{
        "listwallettransactions",
        "Returns the wallet's transactions as the GUI lists them, newest first: one entry per payment, with\n"
        "MWEB outputs and peg-outs as their own entries.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only list this wallet transaction"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "", Cat<std::vector<RPCResult>>(
                {
                    {RPCResult::Type::STR, "type", "\"SendToAddress\", \"SendToOther\", \"RecvWithAddress\", \"RecvFromOther\",\n"
                        "\"SendToSelf\", \"Generated\" or \"Other\" (a transaction only partly paid by the wallet)"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ", negative for sends"},
                    {RPCResult::Type::STR_AMOUNT, "net", "The amount plus the fee, in " + CURRENCY_UNIT},
                    {RPCResult::Type::STR, "label", /*optional=*/true, "The address's label, if any"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The address; for \"SendToSelf\", every address paid, comma-separated"},
                    {RPCResult::Type::NUM, "vout", /*optional=*/true, "The output index, for L1 outputs"},
                    {RPCResult::Type::STR_HEX, "mweb_out", /*optional=*/true, "The MWEB output id, for MWEB outputs"},
                    {RPCResult::Type::STR, "pegout", /*optional=*/true, "\"<kernel id>:<position>\", for peg-outs"},
                    {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The fee in " + CURRENCY_UNIT + ", negative, on the first send entry; only for sends"},
                    {RPCResult::Type::BOOL, "abandoned", /*optional=*/true, "Whether the transaction was abandoned; only for sends"},
                },
                TransactionDescriptionString())},
            }
        },
        RPCExamples{
            HelpExampleCli("listwallettransactions", "") +
            HelpExampleRpc("listwallettransactions", "")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    std::vector<WalletTxRecord> records;
    if (request.params[0].isNull()) {
        for (const auto& [_, wtx] : pwallet->mapWallet) ListWalletTx(*pwallet, wtx, records);
    } else {
        const CWalletTx* wtx{pwallet->GetWalletTx(Txid::FromUint256(ParseHashV(request.params[0], "txid")))};
        if (!wtx) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
        ListWalletTx(*pwallet, *wtx, records);
    }
    for (WalletTxRecord& rec : records) rec.sort_key = WalletTxRecordSortKey(*pwallet, rec);
    // mapWallet iteration order is salted per load, so ties need a persistent order.
    std::stable_sort(records.begin(), records.end(), [](const WalletTxRecord& a, const WalletTxRecord& b) {
        if (a.sort_key != b.sort_key) return a.sort_key > b.sort_key;
        return a.wtx->nOrderPos > b.wtx->nOrderPos;
    });
    UniValue result(UniValue::VARR);
    for (const WalletTxRecord& rec : records) result.push_back(WalletTxRecordToJSON(*pwallet, rec));
    return result;
},
    };
}

static std::vector<RPCResult> ListSinceBlockTxFields()
{
    return Cat<std::vector<RPCResult>>(
        {
            {RPCResult::Type::STR, "address", /*optional=*/true, "The zorkcoin address of the transaction (not returned if the output does not have an address, e.g. OP_RETURN null data)."},
            {RPCResult::Type::STR, "category", "The transaction category.\n"
                "\"send\"                  Transactions sent.\n"
                "\"receive\"               Non-coinbase transactions received.\n"
                "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                "\"hogex\"                 Mature peg-out (HogEx) outputs received.\n"
                "\"immature\"              Coinbase or HogEx transactions received that are not yet mature.\n"
                "\"orphan\"                Orphaned coinbase or HogEx transactions received."},
            {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                "for all other categories"},
            {RPCResult::Type::NUM, "vout", /*optional=*/true, "the vout value (omitted for MWEB extension outputs)"},
            {RPCResult::Type::STR_HEX, "mweb_out", /*optional=*/true, "MWEB output id (present instead of vout for extension outputs)"},
            {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                 "'send' category of transactions."},
        },
        Cat(
            TransactionDescriptionString(),
            std::vector<RPCResult>{
                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
            }
        )
    );
}

RPCMethod listsinceblock()
{
    return RPCMethod{
        "listsinceblock",
        "Get all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
                "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
                "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n",
                {
                    {"blockhash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, the block hash to list transactions since, otherwise list all transactions."},
                    {"target_confirmations", RPCArg::Type::NUM, RPCArg::Default{1}, "Return the nth block hash from the main chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value"},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "(DEPRECATED) No longer used"},
                    {"include_removed", RPCArg::Type::BOOL, RPCArg::Default{true}, "Show transactions that were removed due to a reorg in the \"removed\" array\n"
                                                                       "(not guaranteed to work on pruned nodes)"},
                    {"include_change", RPCArg::Type::BOOL, RPCArg::Default{false}, "Also add entries for change outputs.\n"},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Return only incoming transactions paying to addresses with the specified label.\n"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "transactions", "",
                        {
                            {RPCResult::Type::OBJ, "", "", ListSinceBlockTxFields()},
                        }},
                        {RPCResult::Type::ARR, "removed", /*optional=*/true, "<structure is the same as \"transactions\" above, only present if include_removed=true>\n"
                            "Note: transactions that were re-added in the active chain will appear as-is in this array, and may thus have a positive confirmation count.",
                        {
                            {RPCResult::Type::OBJ, "", "", ListSinceBlockTxFields(), {.print_elision = std::string{}}},
                        }},
                        {RPCResult::Type::STR_HEX, "lastblock", "The hash of the block (target_confirmations-1) from the best block on the main chain, or the genesis hash if the referenced block does not exist yet. This is typically used to feed back into listsinceblock the next time you call it. So you would generally use a target_confirmations of say 6, so you will be continually re-notified of transactions until they've reached 6 confirmations plus any new ones"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const CWallet& wallet = *pwallet;
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    LOCK(wallet.cs_wallet);

    std::optional<int> height;    // Height of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    std::optional<int> altheight; // Height of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;

    uint256 blockId;
    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        blockId = ParseHashV(request.params[0], "blockhash");
        height = int{};
        altheight = int{};
        if (!wallet.chain().findCommonAncestor(blockId, wallet.GetLastBlockHash(), /*ancestor_out=*/FoundBlock().height(*height), /*block1_out=*/FoundBlock().height(*altheight))) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].getInt<int>();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    bool include_removed = (request.params[3].isNull() || request.params[3].get_bool());
    bool include_change = (!request.params[4].isNull() && request.params[4].get_bool());

    // Only set it if 'label' was provided.
    std::optional<std::string> filter_label;
    if (!request.params[5].isNull()) filter_label.emplace(LabelFromValue(request.params[5]));

    int depth = height ? wallet.GetLastBlockHeight() + 1 - *height : -1;

    UniValue transactions(UniValue::VARR);

    for (const auto& [_, tx] : wallet.mapWallet) {

        if (depth == -1 || abs(wallet.GetTxDepthInMainChain(tx)) < depth) {
            ListTransactions(wallet, tx, 0, true, transactions, filter_label, include_change);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue removed(UniValue::VARR);
    while (include_removed && altheight && *altheight > *height) {
        CBlock block;
        if (!wallet.chain().findBlock(blockId, FoundBlock().data(block)) || block.IsNull()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransactionRef& tx : block.vtx) {
            auto it = wallet.mapWallet.find(tx->GetHash());
            if (it != wallet.mapWallet.end()) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(wallet, it->second, -100000000, true, removed, filter_label, include_change);
            }
        }
        blockId = block.hashPrevBlock;
        --*altheight;
    }

    uint256 lastblock;
    target_confirms = std::min(target_confirms, wallet.GetLastBlockHeight() + 1);
    CHECK_NONFATAL(wallet.chain().findAncestorByHeight(wallet.GetLastBlockHash(), wallet.GetLastBlockHeight() + 1 - target_confirms, FoundBlock().hash(lastblock)));

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", std::move(transactions));
    if (include_removed) ret.pushKV("removed", std::move(removed));
    ret.pushKV("lastblock", lastblock.GetHex());

    return ret;
},
    };
}

RPCMethod gettransaction()
{
    return RPCMethod{
        "gettransaction",
        "Get detailed information about in-wallet transaction <txid>\n",
                {
                    {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "(DEPRECATED) No longer used"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false},
                            "Whether to include a `decoded` field containing the decoded transaction (equivalent to RPC decoderawtransaction)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                    {
                        {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                        {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                     "'send' category of transactions."},
                    },
                    TransactionDescriptionString()),
                    {
                        {RPCResult::Type::ARR, "details", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "address", /*optional=*/true, "The zorkcoin address involved in the transaction."},
                                {RPCResult::Type::STR, "category", "The transaction category.\n"
                                    "\"send\"                  Transactions sent.\n"
                                    "\"receive\"               Non-coinbase transactions received.\n"
                                    "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                    "\"hogex\"                 Mature peg-out (HogEx) outputs received.\n"
                                    "\"immature\"              Coinbase or HogEx transactions received that are not yet mature.\n"
                                    "\"orphan\"                Orphaned coinbase or HogEx transactions received."},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                                {RPCResult::Type::NUM, "vout", /*optional=*/true, "the vout value (omitted for MWEB extension outputs)"},
                                {RPCResult::Type::STR_HEX, "mweb_out", /*optional=*/true, "MWEB output id (present instead of vout for extension outputs)"},
                                {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
                                    "'send' category of transactions."},
                                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                                {RPCResult::Type::ARR, "parent_descs", /*optional=*/true, "Only if 'category' is 'receive'. List of parent descriptors for the output script of this coin.", {
                                    {RPCResult::Type::STR, "desc", "The descriptor string."},
                                }},
                            }},
                        }},
                        {RPCResult::Type::STR_HEX, "hex", "Raw data for transaction"},
                        {RPCResult::Type::OBJ, "decoded", /*optional=*/true, "The decoded transaction (only present when `verbose` is passed)",
                        {
                            TxDoc({.wallet = true}),
                        }},
                        RESULT_LAST_PROCESSED_BLOCK,
                    })
                },
                RPCExamples{
                    HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" false true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};

    bool verbose = request.params[2].isNull() ? false : request.params[2].get_bool();

    UniValue entry(UniValue::VOBJ);
    auto it = pwallet->mapWallet.find(hash);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = it->second;

    CAmount nFee = CachedTxIsFromMe(*pwallet, wtx) ? -CachedTxGetFee(*pwallet, wtx) : 0;

    entry.pushKV("amount", ValueFromAmount(CachedTxGetAmount(*pwallet, wtx)));
    if (CachedTxIsFromMe(*pwallet, wtx))
        entry.pushKV("fee", ValueFromAmount(nFee));

    WalletTxToJSON(*pwallet, wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(*pwallet, wtx, 0, false, details, /*filter_label=*/std::nullopt);
    entry.pushKV("details", std::move(details));

    entry.pushKV("hex", EncodeHexTx(*wtx.GetTx(), MWEB::RPCSerializeWithMWEB()));

    if (verbose) {
        UniValue decoded(UniValue::VOBJ);
        TxToUniv(*wtx.GetTx(),
                /*block_hash=*/uint256(),
                /*entry=*/decoded,
                /*include_hex=*/false,
                /*txundo=*/nullptr,
                /*verbosity=*/TxVerbosity::SHOW_DETAILS,
                /*is_change_func=*/[&pwallet](const CTxOut& txout) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
                                        AssertLockHeld(pwallet->cs_wallet);
                                        return OutputIsChange(*pwallet, txout);
                                    });
        entry.pushKV("decoded", std::move(decoded));
    }

    AppendLastProcessedBlock(entry, *pwallet);
    return entry;
},
    };
}

RPCMethod abandontransaction()
{
    return RPCMethod{
        "abandontransaction",
        "Mark in-wallet transaction <txid> as abandoned\n"
                "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
                "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
                "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
                "It has no effect on transactions which are already abandoned.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};

    if (!pwallet->mapWallet.contains(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return UniValue::VNULL;
},
    };
}

RPCMethod rescanblockchain()
{
    return RPCMethod{
        "rescanblockchain",
        "Rescan the local blockchain for wallet related transactions.\n"
                "Note: Use \"getwalletinfo\" to query the scanning progress.\n"
                "The rescan is significantly faster if block filters are available\n"
                "(using startup option \"-blockfilterindex=1\").\n",
                {
                    {"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "block height where the rescan should start"},
                    {"stop_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "the last block height that should be scanned. If none is provided it will rescan up to the tip at return time of this call."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "start_height", "The block height where the rescan started (the requested height or 0)"},
                        {RPCResult::Type::NUM, "stop_height", "The height of the last rescanned block. May be null in rare cases if there was a reorg and the call didn't scan any blocks because they were already scanned in the background."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("rescanblockchain", "100000 120000")
            + HelpExampleRpc("rescanblockchain", "100000, 120000")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int start_height = 0;
    std::optional<int> stop_height;
    uint256 start_block;

    LOCK(pwallet->m_relock_mutex);
    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);
        int tip_height = pwallet->GetLastBlockHeight();

        if (!request.params[0].isNull()) {
            start_height = request.params[0].getInt<int>();
            if (start_height < 0 || start_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
            }
        }

        if (!request.params[1].isNull()) {
            stop_height = request.params[1].getInt<int>();
            if (*stop_height < 0 || *stop_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid stop_height");
            } else if (*stop_height < start_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height must be greater than start_height");
            }
        }

        // We can't rescan unavailable blocks, stop and throw an error
        if (!pwallet->chain().hasBlocks(pwallet->GetLastBlockHash(), start_height, stop_height)) {
            if (pwallet->chain().havePruned() && pwallet->chain().getPruneHeight() >= start_height) {
                throw JSONRPCError(RPC_MISC_ERROR, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.");
            }
            if (pwallet->chain().hasAssumedValidChain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks likely due to an in-progress assumeutxo background sync. Check logs or getchainstates RPC for assumeutxo background sync progress and try again later.");
            }
            throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks, potentially caused by data corruption. If the issue persists you may want to reindex (see -reindex option).");
        }

        CHECK_NONFATAL(pwallet->chain().findAncestorByHeight(pwallet->GetLastBlockHash(), start_height, FoundBlock().hash(start_block)));
    }

    CWallet::ScanResult result =
        pwallet->ScanForWalletTransactions(start_block, start_height, stop_height, reserver, /*save_progress=*/false);
    switch (result.status) {
    case CWallet::ScanResult::SUCCESS:
        break;
    case CWallet::ScanResult::FAILURE:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
    case CWallet::ScanResult::USER_ABORT:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
    } // no default case, so the compiler can warn about missing cases
    UniValue response(UniValue::VOBJ);
    response.pushKV("start_height", start_height);
    response.pushKV("stop_height", result.last_scanned_height ? *result.last_scanned_height : UniValue());
    return response;
},
    };
}

RPCMethod abortrescan()
{
    return RPCMethod{"abortrescan",
                "Stops current wallet rescan triggered by an RPC call, e.g. by a rescanblockchain call.\n"
                "Note: Use \"getwalletinfo\" to query the scanning progress.\n",
                {},
                RPCResult{RPCResult::Type::BOOL, "", "Whether the abort was successful"},
                RPCExamples{
            "\nImport a private key\n"
            + HelpExampleCli("rescanblockchain", "") +
            "\nAbort the running wallet rescan\n"
            + HelpExampleCli("abortrescan", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("abortrescan", "")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (!pwallet->IsScanning() || pwallet->IsAbortingRescan()) return false;
    pwallet->AbortRescan();
    return true;
},
    };
}
} // namespace wallet
