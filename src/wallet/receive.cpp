// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <key_io.h>
#include <mw/models/tx/input.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/output.h>
#include <mw/models/tx/peg_out_coin.h>
#include <mweb/mweb_wallet.h>
#include <script/standard.h>
#include <util/check.h>
#include <wallet/receive.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

namespace wallet {
namespace {
bool ShouldSkipPeginOutput(const CTransaction& tx, const CTxOut& txout)
{
    mw::Hash kernel_id;
    if (txout.scriptPubKey.IsMWEBPegin(&kernel_id)) {
        if (tx.HasMWEBTx() && tx.mweb_tx.GetKernelIDs().contains(kernel_id)) {
            return true;
        }
    }
    return txout.scriptPubKey.IsMWEBPegin();
}

//! Resolve a stealth destination for a wallet-known MWEB coin (mine or sender-info).
static CTxDestination DestinationForMWEBCoin(const CWallet& wallet, const mw::Coin& coin)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (coin.HasAddress()) {
        return *coin.address;
    }
    StealthAddress stealth;
    if (wallet.GetMWWallet()->GetStealthAddress(coin, stealth)) {
        return stealth;
    }
    return CNoDestination();
}

static void AppendMWEBOutputAmounts(const CWallet& wallet, const CWalletTx& wtx, CAmount nDebit,
                                    bool include_change, std::list<COutputEntry>& listReceived,
                                    std::list<COutputEntry>& listSent)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    auto push_coin = [&](const mw::Coin& coin) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        const bool mine = coin.IsMine();
        if (nDebit > 0) {
            if (mine && coin.IsChange() && !include_change) {
                return;
            }
        } else if (!mine) {
            return;
        }

        COutputEntry entry{DestinationForMWEBCoin(wallet, coin), coin.amount, /*vout=*/-1};
        entry.mweb_out = coin.output_id;
        if (nDebit > 0) {
            listSent.push_back(entry);
        }
        if (mine) {
            listReceived.push_back(entry);
        }
    };

    if (wtx.GetTx()->HasMWEBTx()) {
        for (const Output& output : wtx.GetTx()->mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin coin;
            if (!wallet.GetCoin(output.GetOutputID(), coin)) {
                // MWEB: as in Litecoin, a sent output the wallet can't read is listed without
                // an address and with amount 0.
                if (nDebit > 0) {
                    COutputEntry entry{CNoDestination(), 0, /*vout=*/-1};
                    entry.mweb_out = output.GetOutputID();
                    listSent.push_back(entry);
                }
                continue;
            }
            push_coin(coin);
        }
    } else if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
        push_coin(*wtx.mweb_wtx_info->received_coin);
    }
}

CAmount TxGetMWCredit(const CWallet& wallet, const CTransaction& tx, const std::optional<MWEB::WalletTxInfo>& mweb_wtx_info, bool sent_tx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    CAmount nCredit = 0;
    if (mweb_wtx_info && mweb_wtx_info->received_coin && mweb_wtx_info->received_coin->IsMine()) {
        if (!sent_tx || mweb_wtx_info->received_coin->IsChange()) {
            nCredit += mweb_wtx_info->received_coin->amount;
        }
    }
    if (tx.HasMWEBTx()) {
        for (const Output& output : tx.mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin coin;
            if (!wallet.GetCoin(output.GetOutputID(), coin) || !coin.IsMine()) {
                continue;
            }
            if (sent_tx && !coin.IsChange()) {
                continue;
            }
            if (mweb_wtx_info && mweb_wtx_info->received_coin && mweb_wtx_info->received_coin->output_id == coin.output_id) {
                continue;
            }
            nCredit += coin.amount;
        }
    }
    return nCredit;
}

CAmount TxGetMWDebit(const CWallet& wallet, const CTransaction& tx, const std::optional<MWEB::WalletTxInfo>& mweb_wtx_info)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    CAmount nDebit = 0;
    if (mweb_wtx_info && mweb_wtx_info->spent_input) {
        mw::Coin coin;
        if (wallet.GetCoin(*mweb_wtx_info->spent_input, coin) && coin.IsMine()) {
            nDebit += coin.amount;
        }
    }
    if (tx.HasMWEBTx()) {
        for (const Input& input : tx.mweb_tx.m_transaction->GetInputs()) {
            mw::Coin coin;
            if (!wallet.GetCoin(input.GetOutputID(), coin) || !coin.IsMine()) {
                continue;
            }
            if (mweb_wtx_info && mweb_wtx_info->spent_input && *mweb_wtx_info->spent_input == input.GetOutputID()) {
                continue;
            }
            nDebit += coin.amount;
        }
    }
    return nDebit;
}

CAmount WalletTxGetDebit(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    CAmount nDebit = wallet.GetDebit(*wtx.GetTx());
    nDebit += TxGetMWDebit(wallet, *wtx.GetTx(), wtx.mweb_wtx_info);
    return nDebit;
}

CAmount WalletTxGetCredit(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    const bool sent_tx = WalletTxGetDebit(wallet, wtx) > 0;
    CAmount nCredit = TxGetCredit(wallet, *wtx.GetTx());
    nCredit += TxGetMWCredit(wallet, *wtx.GetTx(), wtx.mweb_wtx_info, sent_tx);
    return nCredit;
}

CAmount WalletTxGetFee(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wtx.IsMWEBPlaceholder() && wtx.mweb_wtx_info->spent_input) {
        // The input debit is known, but the aggregate block reveals no payees
        // or transaction fee. A later full body supplies the real fee.
        return 0;
    }
    const CAmount nDebit = WalletTxGetDebit(wallet, wtx);
    if (nDebit <= 0) {
        return 0;
    }

    CAmount nValueOut = 0;
    for (const CTxOut& txout : wtx.GetTx()->vout) {
        // A historical canonical peg-in may have lost its MWEB body. In that
        // form the bridge is an L1 payment, not an internal transfer whose
        // outputs/fees are accounted below.
        if (!wtx.GetTx()->HasMWEBTx() || !ShouldSkipPeginOutput(*wtx.GetTx(), txout)) {
            nValueOut += txout.nValue;
        }
    }
    const CAmount nL1ValueOut = nValueOut;
    if (wtx.GetTx()->HasMWEBTx()) {
        // Litecoin Core GetFee: Σ GetValue(all MWEB outs) — includes SaveToWallet'd
        // payment coins that are not IsMine — plus pegouts. Do not use change-only credit.
        bool any_opaque_mweb_output{false};
        for (const Output& output : wtx.GetTx()->mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin coin;
            if (wallet.GetCoin(output.GetOutputID(), coin)) {
                nValueOut += coin.amount;
            } else if (!wtx.mweb_wtx_info || !wtx.mweb_wtx_info->received_coin ||
                       wtx.mweb_wtx_info->received_coin->output_id != output.GetOutputID()) {
                any_opaque_mweb_output = true;
            }
        }
        if (any_opaque_mweb_output) {
            CAmount pegin_total = 0;
            for (const PegInCoin& pegin : wtx.GetTx()->mweb_tx.GetPegIns()) {
                pegin_total += pegin.GetAmount();
            }
            const CAmount l1_fee = std::max<CAmount>(0, wallet.GetDebit(*wtx.GetTx()) - nL1ValueOut - pegin_total);
            return l1_fee + wtx.GetTx()->mweb_tx.GetFee().value_or(0);
        }
        if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
            const mw::Coin& received = *wtx.mweb_wtx_info->received_coin;
            bool already = false;
            for (const Output& output : wtx.GetTx()->mweb_tx.m_transaction->GetOutputs()) {
                if (output.GetOutputID() == received.output_id) {
                    already = true;
                    break;
                }
            }
            if (!already) {
                nValueOut += received.amount;
            }
        }
        for (const PegOutCoin& pegout : wtx.GetTx()->mweb_tx.GetPegOuts()) {
            nValueOut += pegout.GetAmount();
        }
    }
    return nDebit - nValueOut;
}

CAmount WalletTxGetAmount(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    const CAmount nDebit = WalletTxGetDebit(wallet, wtx);
    if (nDebit <= 0) {
        return WalletTxGetCredit(wallet, wtx);
    }

    if (wtx.GetTx()->HasMWEBTx() && !wtx.GetTx()->mweb_tx.GetPegIns().empty() &&
        TxGetMWDebit(wallet, *wtx.GetTx(), wtx.mweb_wtx_info) == 0) {
        CAmount sent = 0;
        for (const PegInCoin& pegin : wtx.GetTx()->mweb_tx.GetPegIns()) {
            sent += pegin.GetAmount();
        }
        sent -= TxGetMWCredit(wallet, *wtx.GetTx(), wtx.mweb_wtx_info, /*sent_tx=*/true);
        if (const auto mweb_fee = wtx.GetTx()->mweb_tx.GetFee()) {
            sent -= *mweb_fee;
        }
        return -sent;
    }

    const CAmount nCredit = WalletTxGetCredit(wallet, wtx);
    return (nCredit - nDebit) + WalletTxGetFee(wallet, wtx);
}
} // namespace

std::vector<std::pair<StealthAddress, mw::Coin>> WalletTxMWEBReceived(const CWallet& wallet, const CWalletTx& wtx)
{
    AssertLockHeld(wallet.cs_wallet);
    std::vector<mw::Coin> coins;
    if (wtx.GetTx()->HasMWEBTx()) {
        for (const Output& output : wtx.GetTx()->mweb_tx.m_transaction->GetOutputs()) {
            mw::Coin coin;
            if (wallet.GetCoin(output.GetOutputID(), coin)) coins.push_back(std::move(coin));
        }
    } else if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->received_coin) {
        coins.push_back(*wtx.mweb_wtx_info->received_coin);
    }
    std::vector<std::pair<StealthAddress, mw::Coin>> received;
    for (mw::Coin& coin : coins) {
        StealthAddress address;
        if (coin.IsMine() && wallet.GetMWWallet()->GetStealthAddress(coin, address) && wallet.IsMine(CTxDestination{address})) {
            received.emplace_back(address, std::move(coin));
        }
    }
    return received;
}

bool InputIsMine(const CWallet& wallet, const CTxIn& txin)
{
    AssertLockHeld(wallet.cs_wallet);
    const CWalletTx* prev = wallet.GetWalletTx(txin.prevout.hash);
    if (prev && txin.prevout.n < prev->GetTx()->vout.size()) {
        return wallet.IsMine(prev->GetTx()->vout[txin.prevout.n]);
    }
    return false;
}

bool AllInputsMine(const CWallet& wallet, const CTransaction& tx)
{
    LOCK(wallet.cs_wallet);
    for (const CTxIn& txin : tx.vin) {
        if (!InputIsMine(wallet, txin)) return false;
    }
    return true;
}

CAmount OutputGetCredit(const CWallet& wallet, const CTxOut& txout)
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    LOCK(wallet.cs_wallet);
    return (wallet.IsMine(txout) ? txout.nValue : 0);
}

CAmount TxGetCredit(const CWallet& wallet, const CTransaction& tx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nCredit += OutputGetCredit(wallet, txout);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    if (tx.HasMWEBTx()) {
        for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOuts()) {
            if (wallet.IsMine(pegout.GetScriptPubKey())) {
                nCredit += pegout.GetAmount();
                if (!MoneyRange(nCredit)) {
                    throw std::runtime_error(std::string(__func__) + ": value out of range");
                }
            }
        }
    }
    return nCredit;
}

bool ScriptIsChange(const CWallet& wallet, const CScript& script)
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsMine(script))
    {
        CTxDestination address;
        if (!ExtractDestination(script, address))
            return true;
        if (!wallet.FindAddressBookEntry(address)) {
            return true;
        }
    }
    return false;
}

bool OutputIsChange(const CWallet& wallet, const CTxOut& txout)
{
    return ScriptIsChange(wallet, txout.scriptPubKey);
}

CAmount OutputGetChange(const CWallet& wallet, const CTxOut& txout)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (OutputIsChange(wallet, txout) ? txout.nValue : 0);
}

CAmount TxGetChange(const CWallet& wallet, const CTransaction& tx)
{
    LOCK(wallet.cs_wallet);
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nChange += OutputGetChange(wallet, txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

static CAmount GetCachableAmount(const CWallet& wallet, const CWalletTx& wtx, CWalletTx::AmountType type, bool avoid_reuse)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    auto& amount = wtx.m_amounts[type];
    if (!amount.IsCached(avoid_reuse)) {
        amount.Set(avoid_reuse, type == CWalletTx::DEBIT ? WalletTxGetDebit(wallet, wtx) : WalletTxGetCredit(wallet, wtx));
        wtx.m_is_cache_empty = false;
    }
    return amount.Get(avoid_reuse);
}

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, bool avoid_reuse)
{
    AssertLockHeld(wallet.cs_wallet);

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    // GetBalance can assume transactions in mapWallet won't change
    return GetCachableAmount(wallet, wtx, CWalletTx::CREDIT, avoid_reuse);
}

CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, bool avoid_reuse)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wtx.GetTx()->vin.empty() && !wtx.GetTx()->HasMWEBTx() && !(wtx.mweb_wtx_info && wtx.mweb_wtx_info->spent_input)) {
        return 0;
    }

    return GetCachableAmount(wallet, wtx, CWalletTx::DEBIT, avoid_reuse);
}

CAmount CachedTxGetFee(const CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    return WalletTxGetFee(wallet, wtx);
}

CAmount CachedTxGetAmount(const CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    return WalletTxGetAmount(wallet, wtx);
}

CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx)
{
    if (wtx.fChangeCached)
        return wtx.nChangeCached;
    wtx.nChangeCached = TxGetChange(wallet, *wtx.GetTx());
    wtx.fChangeCached = true;
    return wtx.nChangeCached;
}

void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                  std::list<COutputEntry>& listReceived,
                  std::list<COutputEntry>& listSent, CAmount& nFee,
                  bool include_change)
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();

    LOCK(wallet.cs_wallet);
    const CAmount nDebit = WalletTxGetDebit(wallet, wtx);
    nFee = WalletTxGetFee(wallet, wtx);

    // Sent/received.
    for (unsigned int i = 0; i < wtx.GetTx()->vout.size(); ++i)
    {
        const CTxOut& txout = wtx.GetTx()->vout[i];
        if (ShouldSkipPeginOutput(*wtx.GetTx(), txout)) {
            continue;
        }

        const bool ismine = wallet.IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            if (!include_change && OutputIsChange(wallet, txout))
                continue;
        }
        else if (!ismine)
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            wallet.WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                                    wtx.GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (ismine)
            listReceived.push_back(output);
    }

    AppendMWEBOutputAmounts(wallet, wtx, nDebit, include_change, listReceived, listSent);

    if (wtx.GetTx()->HasMWEBTx()) {
        for (const PegOutCoin& pegout : wtx.GetTx()->mweb_tx.GetPegOuts()) {
            const CScript& script = pegout.GetScriptPubKey();
            const bool ismine = wallet.IsMine(script);
            if (nDebit > 0) {
                if (!include_change && wallet.IsMine(script) && ScriptIsChange(wallet, script)) {
                    continue;
                }
            } else if (!ismine) {
                continue;
            }

            CTxDestination address;
            if (!ExtractDestination(script, address)) {
                address = CNoDestination();
            }

            COutputEntry output = {address, pegout.GetAmount(), -1};
            output.mweb_out = mw::Hash(); // MWEB: Litecoin's peg-out index
            if (nDebit > 0) {
                listSent.push_back(output);
            }
            if (ismine) {
                listReceived.push_back(output);
            }
        }
    }
}

bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    if (!wtx.m_cached_from_me.has_value()) {
        wtx.m_cached_from_me = CachedTxGetDebit(wallet, wtx, /*avoid_reuse=*/false) > 0;
    }
    return wtx.m_cached_from_me.value();
}

// NOLINTNEXTLINE(misc-no-recursion)
bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<Txid>& trusted_parents)
{
    AssertLockHeld(wallet.cs_wallet);

    // This wtx is already trusted
    if (trusted_parents.contains(wtx.GetHash())) return true;

    if (wtx.isConfirmed()) return true;
    if (wtx.isBlockConflicted()) return false;
    // using wtx's cached debit
    if (!wallet.m_spend_zero_conf_change || !CachedTxIsFromMe(wallet, wtx)) return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!wtx.InMempool()) return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : wtx.GetTx()->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = wallet.GetWalletTx(txin.prevout.hash);
        if (parent == nullptr) return false;
        const CTxOut& parentOut = parent->GetTx()->vout[txin.prevout.n];
        // Check that this specific input being spent is trusted
        if (!wallet.IsMine(parentOut)) return false;
        // If we've already trusted this parent, continue
        if (trusted_parents.contains(parent->GetHash())) continue;
        // Recurse to check that the parent is also trusted
        if (!CachedTxIsTrusted(wallet, *parent, trusted_parents)) return false;
        trusted_parents.insert(parent->GetHash());
    }
    return true;
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx)
{
    std::set<Txid> trusted_parents;
    LOCK(wallet.cs_wallet);
    return CachedTxIsTrusted(wallet, wtx, trusted_parents);
}

Balance GetBalance(const CWallet& wallet, const int min_depth, bool avoid_reuse, bool include_nonmempool, bool include_mweb)
{
    Balance ret;
    bool allow_used_addresses = !avoid_reuse || !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    {
        LOCK(wallet.cs_wallet);
        std::set<Txid> trusted_parents;
        for (const auto& [outpoint, txo] : wallet.GetTXOs()) {
            const CWalletTx& wtx = txo.GetWalletTx();

            const bool is_trusted{CachedTxIsTrusted(wallet, wtx, trusted_parents)};
            const int tx_depth{wallet.GetTxDepthInMainChain(wtx)};

            bool nonmempool_spent = false;
            switch (wallet.HowSpent(outpoint)) {
            case CWallet::SpendType::CONFIRMED:
            case CWallet::SpendType::MEMPOOL:
                // treat as spent; ignore
                break;
            case CWallet::SpendType::NONMEMPOOL:
                if (!include_nonmempool) break;
                nonmempool_spent = true;
                [[fallthrough]];
            case CWallet::SpendType::UNSPENT:
                CAmount* bucket = nullptr;

                // Set the amounts in the return object
                if (wallet.IsTxImmatureCoinBase(wtx) && wtx.isConfirmed()) {
                    bucket = &ret.m_mine_immature;
                } else if (is_trusted && tx_depth >= min_depth) {
                    bucket = &ret.m_mine_trusted;
                } else if (!is_trusted && wtx.InMempool()) {
                    bucket = &ret.m_mine_untrusted_pending;
                }
                if (bucket) {
                    // Get the amounts for mine
                    CAmount credit_mine = txo.GetTxOut().nValue;

                    if (!allow_used_addresses && wallet.IsSpentKey(txo.GetTxOut().scriptPubKey)) {
                        bucket = &ret.m_mine_used;
                    }
                    *bucket += credit_mine;
                    if (nonmempool_spent) {
                        ret.m_mine_nonmempool -= credit_mine;
                    }
                }
            }
        }

        if (include_mweb) {
            for (const CWallet::MWEBUnspentEntry& mweb_out : wallet.ListMWEBUnspent(
                    min_depth, std::numeric_limits<int>::max(), /*include_unsafe=*/true,
                    nullptr, 0, MAX_MONEY)) {
                const bool is_trusted{mweb_out.safe};
                const int tx_depth{mweb_out.depth};

                CAmount* bucket = nullptr;
                const CWalletTx* wtx = wallet.GetWalletTx(mweb_out.txid);
                if (!wtx) {
                    continue;
                }
                if (wallet.IsTxImmatureCoinBase(*wtx) && wtx->isConfirmed()) {
                    bucket = &ret.m_mine_immature;
                } else if (is_trusted && tx_depth >= min_depth) {
                    bucket = &ret.m_mine_trusted;
                } else if (!is_trusted && wtx->InMempool()) {
                    bucket = &ret.m_mine_untrusted_pending;
                }
                if (bucket) {
                    *bucket += mweb_out.amount;
                }
            }
        }
    }
    return ret;
}

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet)
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(wallet.cs_wallet);
        std::set<Txid> trusted_parents;
        for (const auto& [outpoint, txo] : wallet.GetTXOs()) {
            const CWalletTx& wtx = txo.GetWalletTx();

            if (!CachedTxIsTrusted(wallet, wtx, trusted_parents)) continue;
            if (wallet.IsTxImmatureCoinBase(wtx)) continue;

            int nDepth = wallet.GetTxDepthInMainChain(wtx);
            if (nDepth < (CachedTxIsFromMe(wallet, wtx) ? 0 : 1)) continue;

            CTxDestination addr;
            Assume(wallet.IsMine(txo.GetTxOut()));
            if(!ExtractDestination(txo.GetTxOut().scriptPubKey, addr)) continue;

            CAmount n = wallet.IsSpent(outpoint) ? 0 : txo.GetTxOut().nValue;
            balances[addr] += n;
        }

        // MWEB: the wallet's MWEB coins, by address, as in Litecoin.
        for (const auto& [_, wtx] : wallet.mapWallet) {
            if (!CachedTxIsTrusted(wallet, wtx, trusted_parents)) continue;
            if (wallet.GetTxDepthInMainChain(wtx) < (CachedTxIsFromMe(wallet, wtx) ? 0 : 1)) continue;
            for (const auto& [address, coin] : WalletTxMWEBReceived(wallet, wtx)) {
                balances[address] += wallet.IsOutputSpentMWEB(coin.output_id, wtx) ? 0 : coin.amount;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > GetAddressGroupings(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : wallet.mapWallet)
    {
        const CWalletTx& wtx = walletEntry.second;

        const auto mweb_received{WalletTxMWEBReceived(wallet, wtx)}; // MWEB
        if (wtx.GetTx()->vin.size() > 0 || wtx.GetTx()->HasMWEBTx()) // MWEB
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (const CTxIn& txin : wtx.GetTx()->vin)
            {
                CTxDestination address;
                if(!InputIsMine(wallet, txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(wallet.mapWallet.at(txin.prevout.hash).GetTx()->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }
            if (wtx.GetTx()->HasMWEBTx()) { // MWEB: inputs spending the wallet's MWEB coins
                for (const Input& input : wtx.GetTx()->mweb_tx.m_transaction->GetInputs()) {
                    mw::Coin coin;
                    StealthAddress address;
                    if (wallet.GetCoin(input.GetOutputID(), coin) && coin.IsMine() && wallet.GetMWWallet()->GetStealthAddress(coin, address)) {
                        grouping.insert(address);
                        any_mine = true;
                    }
                }
            }

            // group change with input addresses
            if (any_mine)
            {
               for (const auto& [address, coin] : mweb_received) { // MWEB
                   if (coin.IsChange()) grouping.insert(address);
               }
               for (const CTxOut& txout : wtx.GetTx()->vout)
                   if (OutputIsChange(wallet, txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : wtx.GetTx()->vout)
            if (wallet.IsMine(txout))
            {
                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
        for (const auto& [address, _] : mweb_received) { // MWEB
            grouping.insert(address);
            groupings.insert(grouping);
            grouping.clear();
        }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (const std::set<CTxDestination>& _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (const CTxDestination& address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (const CTxDestination& element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (const std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}
} // namespace wallet
