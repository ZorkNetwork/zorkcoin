// Copyright (c) 2011 - 2020 The Litecoin Core developers
// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mweb/mweb_transact.h>

#include <addresstype.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <mw/models/tx/peg_out_coin.h>
#include <mw/consensus/weight.h>
#include <mw/wallet/sign.h>
#include <policy/policy.h>
#include <protocol.h>
#include <script/standard.h>
#include <util/translation.h>

#include <map>
#include <algorithm>
#include <optional>

using namespace MWEB;

TxType MWEB::GetTxType(const std::vector<wallet::CRecipient>& recipients, const std::set<wallet::CInputCoin>& input_coins)
{
    assert(!recipients.empty());

    static auto is_btc = [](const wallet::CInputCoin& input) { return !input.IsMWEB(); };
    static auto is_mweb = [](const wallet::CInputCoin& input) { return input.IsMWEB(); };

    const bool any_mweb_dest = std::any_of(recipients.cbegin(), recipients.cend(),
        [](const wallet::CRecipient& r) { return r.IsMWEB(); });
    const bool any_l1_dest = std::any_of(recipients.cbegin(), recipients.cend(),
        [](const wallet::CRecipient& r) { return !r.IsMWEB(); });
    const bool any_btc_in = std::any_of(input_coins.cbegin(), input_coins.cend(), is_btc);
    const bool any_mweb_in = std::any_of(input_coins.cbegin(), input_coins.cend(), is_mweb);

    // Pure stealth destination(s): peg-in if any L1 inputs, else MWEB-to-MWEB.
    if (any_mweb_dest && !any_l1_dest) {
        return any_btc_in ? TxType::PEGIN : TxType::MWEB_TO_MWEB;
    }

    // Any MWEB inputs with L1 (and optional stealth) destinations: peg-out path
    // so L1 recipient vouts are cleared and emitted as kernel pegouts (AddMWEBTx
    // still builds stealth receivers when present).
    if (any_mweb_in) {
        return TxType::PEGOUT;
    }

    // Stealth destination(s) funded only from L1 inputs.
    if (any_mweb_dest) {
        return TxType::PEGIN;
    }

    return TxType::BTC_TO_BTC;
}

bool MWEB::ContainsPegIn(const TxType& mweb_type, const std::set<wallet::CInputCoin>& input_coins)
{
    if (mweb_type == MWEB::TxType::PEGIN) {
        return true;
    }

    if (mweb_type == MWEB::TxType::PEGOUT) {
        return std::any_of(
            input_coins.cbegin(), input_coins.cend(),
            [](const wallet::CInputCoin& coin) { return !coin.IsMWEB(); });
    }

    return false;
}

bool MWEB::IsChangeOnMWEB(const wallet::CWallet& wallet, const MWEB::TxType& mweb_type, const std::vector<wallet::CRecipient>& recipients, const CTxDestination& dest_change)
{
    // A peg-in pays transparent change as an L1 output, as in Litecoin.
    if (mweb_type == MWEB::TxType::PEGIN) {
        return std::holds_alternative<CNoDestination>(dest_change) || std::holds_alternative<StealthAddress>(dest_change);
    }
    // Otherwise a transparent change destination gets the change as a kernel peg-out.
    return mweb_type != MWEB::TxType::BTC_TO_BTC;
}

CScript MWEB::GetPegoutChangeScript(const CTxDestination& dest_change)
{
    if (std::holds_alternative<CNoDestination>(dest_change) || std::holds_alternative<StealthAddress>(dest_change)) {
        return {};
    }
    return GetScriptForDestination(dest_change);
}

uint64_t MWEB::CalcMWEBWeight(const MWEB::TxType& mweb_type, const bool change_on_mweb, const std::vector<wallet::CRecipient>& recipients)
{
    return CalcMWEBWeight(mweb_type, change_on_mweb, recipients, CScript{});
}

uint64_t MWEB::CalcMWEBWeight(const MWEB::TxType& mweb_type, bool change_on_mweb, const std::vector<wallet::CRecipient>& recipients, const CScript& pegout_change_script)
{
    if (mweb_type == MWEB::TxType::BTC_TO_BTC) {
        return 0;
    }

    uint64_t mweb_weight = 0;
    std::vector<PegOutCoin> pegouts;

    for (const wallet::CRecipient& recipient : recipients) {
        if (recipient.IsMWEB()) {
            mweb_weight += mw::STANDARD_OUTPUT_WEIGHT;
        } else if (mweb_type == MWEB::TxType::PEGOUT) {
            // Peg-out path: L1 destinations are kernel pegouts (vout cleared).
            // Peg-in path may also list L1 payees; those stay as ordinary vouts.
            pegouts.emplace_back(recipient.nAmount, GetScriptForDestination(recipient.dest));
        }
    }

    if (change_on_mweb) {
        if (pegout_change_script.empty()) {
            mweb_weight += mw::STANDARD_OUTPUT_WEIGHT;
        } else {
            pegouts.emplace_back(0, pegout_change_script);
        }
    }

    // One kernel with stealth excess; pegout script bytes accumulate per pegout.
    mweb_weight += Weight::CalcKernelWeight(/*has_stealth_excess=*/true, pegouts);

    return mweb_weight;
}

static int64_t PegOutVSize(const CScript& script)
{
    const int64_t pegout_weight = (int64_t)::GetSerializeSize(CTxOut(0, script)) * WITNESS_SCALE_FACTOR;
    return GetVirtualTransactionSize(pegout_weight, 0, 0);
}

int64_t MWEB::CalcPegOutBytes(const TxType& mweb_type, const std::vector<wallet::CRecipient>& recipients)
{
    return CalcPegOutBytes(mweb_type, recipients, CScript{});
}

int64_t MWEB::CalcPegOutBytes(const TxType& mweb_type, const std::vector<wallet::CRecipient>& recipients, const CScript& pegout_change_script)
{
    if (mweb_type == MWEB::TxType::BTC_TO_BTC) {
        return 0;
    }

    int64_t total_vsize = pegout_change_script.empty() ? 0 : PegOutVSize(pegout_change_script);
    if (mweb_type != MWEB::TxType::PEGOUT) {
        return total_vsize;
    }
    for (const wallet::CRecipient& recipient : recipients) {
        if (recipient.IsMWEB()) continue;
        total_vsize += PegOutVSize(GetScriptForDestination(recipient.dest));
    }
    return total_vsize;
}

/** Whether the recipient is paid from the MWEB side: a stealth output, or a peg-out on the peg-out path. */
static bool PaidFromMWEB(const InProcessTx& new_tx, const wallet::CRecipient& recipient)
{
    return recipient.IsMWEB() || new_tx.mweb_type == TxType::PEGOUT;
}

/**
 * The part of the fee each recipient pays. The fee is shared equally by the subtract-fee
 * recipients. The first of them also pays the remainder, taking transparent outputs first,
 * then stealth outputs, then peg-outs.
 */
static std::vector<CAmount> FeeShares(const InProcessTx& new_tx)
{
    const auto& recipients = new_tx.recipients;
    const CAmount num_payers = std::count_if(recipients.cbegin(), recipients.cend(),
        [](const wallet::CRecipient& r) { return r.fSubtractFeeFromAmount; });
    std::vector<CAmount> shares(recipients.size(), 0);
    if (num_payers == 0) return shares;

    const auto rank = [&new_tx](const wallet::CRecipient& r) {
        return !PaidFromMWEB(new_tx, r) ? 0 : r.IsMWEB() ? 1 : 2;
    };
    std::optional<size_t> first;
    for (size_t i = 0; i < recipients.size(); ++i) {
        if (!recipients[i].fSubtractFeeFromAmount) continue;
        shares[i] = new_tx.total_fee / num_payers;
        if (!first || rank(recipients[i]) < rank(recipients[*first])) first = i;
    }
    shares[*first] += new_tx.total_fee % num_payers;
    return shares;
}

void Transact::AddMWEBTx(InProcessTx& new_tx)
{
    std::vector<mw::Recipient> receivers;
    std::vector<PegOutCoin> pegouts;
    const std::vector<CAmount> fee_shares = FeeShares(new_tx);

    // On the peg-in path the transparent recipients keep their outputs, in recipient
    // order around the peg-in and change outputs.
    std::vector<CTxOut*> l1_outputs;
    if (new_tx.mweb_type != TxType::PEGOUT) {
        const CScript placeholder = GetScriptForPegin(mw::Hash());
        for (size_t i = 0; i < new_tx.tx.vout.size(); ++i) {
            if (static_cast<int>(i) == new_tx.change_position || new_tx.tx.vout[i].scriptPubKey == placeholder) continue;
            l1_outputs.push_back(&new_tx.tx.vout[i]);
        }
    }
    size_t next_l1_output{0};
    CAmount l1_payments{0};

    for (size_t i = 0; i < new_tx.recipients.size(); ++i) {
        const wallet::CRecipient& recipient = new_tx.recipients[i];
        const CAmount recipient_amount = recipient.nAmount - fee_shares[i];

        if (recipient_amount < 0) {
            throw CreateTxError(_("The transaction amount is too small to pay the fee"));
        }

        if (std::holds_alternative<StealthAddress>(recipient.dest)) {
            receivers.push_back(mw::Recipient{recipient_amount, std::get<StealthAddress>(recipient.dest)});
        } else if (new_tx.mweb_type == TxType::PEGOUT) {
            // Ordinary L1 vouts on the peg-in path stay in tx.vout; only the
            // peg-out path emits them as kernel pegouts (vout was cleared).
            PegOutCoin pegout_recipient(
                recipient_amount,
                GetScriptForDestination(recipient.dest)
            );
            if (fee_shares[i] > 0 && IsDust(CTxOut(pegout_recipient.GetAmount(), pegout_recipient.GetScriptPubKey()), m_wallet.chain().relayDustFee())) {
                throw CreateTxError(_("The transaction amount is too small to send after the fee has been deducted"));
            }
            pegouts.push_back(std::move(pegout_recipient));
        } else {
            CTxOut& txout = *l1_outputs.at(next_l1_output++);
            txout.nValue = recipient_amount;
            if (fee_shares[i] > 0 && IsDust(txout, m_wallet.chain().relayDustFee())) {
                throw CreateTxError(_("The transaction amount is too small to send after the fee has been deducted"));
            }
            l1_payments += txout.nValue;
        }
    }

    CAmount btc_change = 0;
    if (new_tx.change_position != -1) {
        assert(new_tx.tx.vout.size() > (size_t)new_tx.change_position);
        btc_change = new_tx.tx.vout[new_tx.change_position].nValue;
    }

    std::optional<CAmount> pegin_amount = std::nullopt;
    CAmount pegin_change_fee{0};
    CAmount btc_input_amount = std::accumulate(
        new_tx.selected_coins.cbegin(), new_tx.selected_coins.cend(), CAmount(0),
        [](CAmount amt, const wallet::CInputCoin& input) { return amt + (input.IsMWEB() ? 0 : input.GetAmount()); }
    );
    if (btc_input_amount > 0) {
        const CAmount btc_fee = new_tx.total_fee - new_tx.mweb_fee;
        if (new_tx.mweb_type == TxType::PEGIN && !new_tx.change_on_mweb) {
            // A peg-in with transparent change (as in Litecoin) pegs in what the MWEB side
            // pays. The change output gets the rest; without one, the kernel fee does.
            CAmount mweb_paid = new_tx.mweb_fee;
            for (const mw::Recipient& receiver : receivers) mweb_paid += receiver.amount;
            for (const auto& coin : new_tx.selected_coins) {
                if (coin.IsMWEB()) mweb_paid -= coin.GetAmount();
            }
            const CAmount l1_left = btc_input_amount - (btc_fee + l1_payments + mweb_paid);
            if (mweb_paid <= 0 && l1_left > 0) {
                throw CreateTxError(_("The selected MWEB coins exceed the MWEB payments; their change needs an MWEB change address"));
            }
            if (l1_left < 0) {
                throw CreateTxError(_("The transaction amount is too small to pay the fee"));
            }
            if (btc_change > 0) {
                CTxOut& change_output = new_tx.tx.vout[new_tx.change_position];
                change_output.nValue = l1_left;
                if (IsDust(change_output, m_wallet.chain().relayDustFee())) {
                    throw CreateTxError(_("The transaction amount is too small to pay the fee"));
                }
                btc_change = l1_left;
            } else {
                pegin_change_fee = l1_left;
            }
        }
        pegin_amount = (btc_input_amount - (btc_fee + btc_change + l1_payments));
        if (*pegin_amount < 0) {
            throw CreateTxError(_("The transaction amount is too small to pay the fee"));
        }
        if (IsDust(CTxOut(*pegin_amount, GetScriptForPegin(mw::Hash())), m_wallet.chain().relayDustFee())) {
            throw CreateTxError(_("The transaction amount is too small to send after the fee has been deducted"));
        }
    }

    CAmount kernel_fee = new_tx.mweb_fee + pegin_change_fee;
    if (new_tx.change_on_mweb) {
        const CAmount change_amount = CalcChangeAmount(new_tx, pegin_amount, btc_change);
        if (!new_tx.pegout_change_script.empty()) {
            if (change_amount > 0 && change_amount >= new_tx.min_pegout_change) {
                pegouts.emplace_back(change_amount, new_tx.pegout_change_script);
            } else {
                kernel_fee += change_amount;
            }
        } else if (change_amount > 0) {
            receivers.push_back(mw::Recipient{change_amount, GetChangeAddress(new_tx)});
        }
    }

    mw::MutableTx mweb_tx;
    CAmount input_total{0};
    for (const auto& coin : new_tx.selected_coins) {
        if (!coin.IsMWEB()) {
            continue;
        }
        const mw::Coin& mweb_coin = coin.GetMWEBCoin();
        if (new_tx.sign && !mweb_coin.HasSpendMaterial()) {
            if (m_wallet.IsLocked()) {
                throw CreateTxError(_("Error: Please enter the wallet passphrase with walletpassphrase first."));
            }
            throw CreateTxError(_("MWEB coin is missing spend material and cannot be spent"));
        }
        mw::MutableInput input = mw::MutableInput::FromCoin(mweb_coin);
        if (new_tx.sign) {
            input.spend_key = *mweb_coin.spend_key;
        }
        mweb_tx.inputs.push_back(std::move(input));
        input_total += mweb_coin.amount;
    }

    CAmount output_total{0};
    for (const mw::Recipient& receiver : receivers) {
        mw::MutableOutput output;
        output.amount = receiver.amount;
        output.address = receiver.address;
        mweb_tx.outputs.push_back(std::move(output));
        output_total += receiver.amount;
    }

    mw::MutableKernel kernel;
    kernel.fee = kernel_fee;
    if (pegin_amount) {
        kernel.pegin = *pegin_amount;
    }
    kernel.SetPegOuts(pegouts);
    mweb_tx.kernels.push_back(std::move(kernel));

    if (input_total + pegin_amount.value_or(0) != output_total + mweb_tx.GetTotalPegoutAmount() + kernel_fee) {
        throw CreateTxError(Untranslated("Total amount mismatch"));
    }

    new_tx.tx.mweb_tx = std::move(mweb_tx);

    // The peg-in output keeps its placeholder script until the kernel is signed.
    if (pegin_amount) {
        const CScript placeholder = GetScriptForPegin(mw::Hash());
        for (CTxOut& txout : new_tx.tx.vout) {
            if (txout.scriptPubKey == placeholder) {
                txout.nValue = *pegin_amount;
                break;
            }
        }
    }

    if (!new_tx.sign) {
        return;
    }

    const SecretKey rewind_key = WITH_LOCK(m_wallet.cs_wallet, return m_wallet.GetMWEBRewindKeyForSigning());
    const mw::SenderKeyGenerator generate_sender_key = [this]() -> util::Result<SecretKey> {
        LOCK(m_wallet.cs_wallet);
        return m_wallet.GetMWWallet()->GenerateSenderKey();
    };
    util::Result<mw::SignTxResult> signed_tx = mw::SignTx(new_tx.tx, rewind_key, generate_sender_key);
    if (!signed_tx) {
        throw CreateTxError(util::ErrorString(signed_tx));
    }

    std::vector<mw::Coin> output_coins;
    for (const auto& [output_id, output_coin] : signed_tx->coins_by_output_id) {
        output_coins.push_back(output_coin);
    }
    if (!output_coins.empty() && !m_wallet.GetMWWallet()->SaveToWallet(output_coins)) {
        throw CreateTxError(Untranslated("Failed to persist MWEB output metadata"));
    }

    m_wallet.GetMWWallet()->RewindOutputs(CTransaction(new_tx.tx));
}

CAmount Transact::CalcChangeAmount(const InProcessTx& new_tx, const std::optional<CAmount>& pegin_amount, const CAmount& btc_change)
{
    const std::vector<CAmount> fee_shares = FeeShares(new_tx);
    CAmount recipient_amount{0};
    for (size_t i = 0; i < new_tx.recipients.size(); ++i) {
        if (!PaidFromMWEB(new_tx, new_tx.recipients[i])) continue;
        recipient_amount += new_tx.recipients[i].nAmount - fee_shares[i];
    }

    CAmount mweb_input_amount = std::accumulate(
        new_tx.selected_coins.cbegin(), new_tx.selected_coins.cend(), CAmount(0),
        [](CAmount amt, const wallet::CInputCoin& input) { return amt + (input.IsMWEB() ? input.GetAmount() : 0); }
    );

    CAmount change_amount = (pegin_amount.value_or(0) + mweb_input_amount) - (recipient_amount + new_tx.mweb_fee + btc_change);
    if (change_amount < 0) {
        // Recoverable when the caller can re-select with a higher fee budget.
        throw CreateTxError(_("Transaction fee and change calculation failed"),
                            CreateTxErrorKind::InsufficientFeeBudget);
    }
    return change_amount;
}

StealthAddress Transact::GetChangeAddress(const InProcessTx& new_tx)
{
    if (const StealthAddress* change_dest = std::get_if<StealthAddress>(&new_tx.change_addr)) {
        return *change_dest;
    }

    // Change routes to the active account regardless of which accounts funded
    // the inputs; if the active account can't produce a change address, fall back
    // to the account contributing the largest input amount that can
    // (doc/mweb/descriptors.md "Change and peg-in routing").
    StealthAddress change_address;
    {
        LOCK(m_wallet.cs_wallet);
        bool have_address = false;
        if (wallet::DescriptorScriptPubKeyMan* active_spk = m_wallet.GetExternalMWEBScriptPubKeyMan()) {
            have_address = m_wallet.GetMWEBChangeAddress(*active_spk, change_address);
        }
        if (!have_address) {
            std::map<wallet::DescriptorScriptPubKeyMan*, CAmount> contributions;
            for (const wallet::CInputCoin& input : new_tx.selected_coins) {
                if (!input.IsMWEB()) {
                    continue;
                }
                if (wallet::DescriptorScriptPubKeyMan* coin_account = m_wallet.GetMWEBAccountForCoin(input.GetMWEBCoin())) {
                    contributions[coin_account] += input.GetAmount();
                }
            }
            CAmount best_amount{-1};
            for (const auto& [account_spk, amount] : contributions) {
                StealthAddress candidate;
                if (amount > best_amount && m_wallet.GetMWEBChangeAddress(*account_spk, candidate)) {
                    change_address = candidate;
                    best_amount = amount;
                    have_address = true;
                }
            }
        }
        if (!have_address) {
            throw CreateTxError(_("Failed to retrieve change stealth address"));
        }
    }

    return change_address;
}
