// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletmodeltransaction.h>

#include <addresstype.h>
#include <key_io.h>
#include <policy/policy.h>
#include <script/standard.h>

#include <optional>

WalletModelTransaction::WalletModelTransaction(const QList<SendCoinsRecipient>& _recipients)
    : recipients(_recipients)
{
}

QList<SendCoinsRecipient> WalletModelTransaction::getRecipients() const
{
    return recipients;
}

CTransactionRef& WalletModelTransaction::getWtx()
{
    return wtx;
}

void WalletModelTransaction::setWtx(const CTransactionRef& newTx)
{
    wtx = newTx;
}

void WalletModelTransaction::setMWEBDraft(const mw::MutableTx& mweb_tx)
{
    // Keeps none of the secrets of a signed draft, such as the inputs' spend keys.
    mweb_draft = mw::MutableTx{};
    signed_pegin_kernel_ids.clear();
    for (const mw::MutableInput& signed_input : mweb_tx.inputs) {
        mw::MutableInput& input = mweb_draft.inputs.emplace_back(signed_input.output_id);
        input.commitment = signed_input.commitment;
        input.output_pubkey = signed_input.output_pubkey;
        input.amount = signed_input.amount;
    }
    for (const mw::MutableOutput& signed_output : mweb_tx.outputs) {
        mw::MutableOutput& output = mweb_draft.outputs.emplace_back();
        output.amount = signed_output.amount;
        output.address = signed_output.address;
        output.subtract_fee_from_amount = signed_output.subtract_fee_from_amount;
    }
    for (const mw::MutableKernel& signed_kernel : mweb_tx.kernels) {
        mw::MutableKernel& kernel = mweb_draft.kernels.emplace_back();
        kernel.fee = signed_kernel.fee;
        kernel.pegin = signed_kernel.pegin;
        kernel.pegouts = signed_kernel.pegouts;
        kernel.lock_height = signed_kernel.lock_height;
        kernel.extradata = signed_kernel.extradata;
        if (const std::optional<mw::Hash> kernel_id = signed_kernel.GetKernelID(); kernel_id && signed_kernel.pegin) {
            signed_pegin_kernel_ids.push_back(*kernel_id);
        }
    }
}

CMutableTransaction WalletModelTransaction::getUnsignedTx() const
{
    CMutableTransaction mtx{*wtx};
    mtx.mweb_tx = mweb_draft;
    // The signer pays the peg-in to the ID of the kernel it signs.
    for (const mw::Hash& kernel_id : signed_pegin_kernel_ids) {
        for (CTxOut& txout : mtx.vout) {
            if (txout.scriptPubKey == GetScriptForPegin(kernel_id)) txout.scriptPubKey = GetScriptForPegin(mw::Hash());
        }
    }
    return mtx;
}

unsigned int WalletModelTransaction::getTransactionSize()
{
    return wtx ? GetVirtualTransactionSize(*wtx) : 0;
}

CAmount WalletModelTransaction::getTransactionFee() const
{
    return fee;
}

void WalletModelTransaction::setTransactionFee(const CAmount& newFee)
{
    fee = newFee;
}

void WalletModelTransaction::reassignAmounts(int nChangePosRet)
{
    const CTransaction* walletTransaction = wtx.get();
    int i = 0;
    for (QList<SendCoinsRecipient>::iterator it = recipients.begin(); it != recipients.end(); ++it)
    {
        SendCoinsRecipient& rcp = (*it);
        {
            if (i == nChangePosRet)
                i++;
            rcp.amount = walletTransaction->vout[i].nValue;
            i++;
        }
    }
}

void WalletModelTransaction::reassignMWEBAmounts(const mw::MutableTx& mweb_tx, std::optional<size_t> mweb_change_index, int nChangePosRet)
{
    const CTransaction* walletTransaction = wtx.get();
    std::vector<bool> vout_used(walletTransaction->vout.size(), false);
    if (nChangePosRet >= 0 && static_cast<size_t>(nChangePosRet) < vout_used.size()) {
        vout_used[nChangePosRet] = true;
    }
    std::vector<bool> output_used(mweb_tx.outputs.size(), false);
    if (mweb_change_index && *mweb_change_index < output_used.size()) {
        output_used[*mweb_change_index] = true;
    }
    std::vector<PegOutCoin> pegouts;
    for (const auto& kernel : mweb_tx.kernels) {
        const std::vector<PegOutCoin> kernel_pegouts = kernel.GetPegOuts();
        pegouts.insert(pegouts.end(), kernel_pegouts.begin(), kernel_pegouts.end());
    }
    std::vector<bool> pegout_used(pegouts.size(), false);

    // Duplicate recipient addresses are rejected before the transaction is built, so each
    // recipient matches one output: stealth outputs by address, transparent outputs and
    // peg-outs by script.
    for (SendCoinsRecipient& rcp : recipients) {
        const CTxDestination dest = DecodeDestination(rcp.address.toStdString());
        if (const StealthAddress* address = std::get_if<StealthAddress>(&dest)) {
            for (size_t i = 0; i < mweb_tx.outputs.size(); ++i) {
                const mw::MutableOutput& output = mweb_tx.outputs[i];
                if (!output_used[i] && output.address == *address && output.amount) {
                    rcp.amount = *output.amount;
                    output_used[i] = true;
                    break;
                }
            }
            continue;
        }

        const CScript script = GetScriptForDestination(dest);
        bool found = false;
        for (size_t i = 0; i < walletTransaction->vout.size() && !found; ++i) {
            if (!vout_used[i] && walletTransaction->vout[i].scriptPubKey == script) {
                rcp.amount = walletTransaction->vout[i].nValue;
                vout_used[i] = true;
                found = true;
            }
        }
        for (size_t i = 0; i < pegouts.size() && !found; ++i) {
            if (!pegout_used[i] && pegouts[i].GetScriptPubKey() == script) {
                rcp.amount = pegouts[i].GetAmount();
                pegout_used[i] = true;
                found = true;
            }
        }
    }
}

CAmount WalletModelTransaction::getTotalTransactionAmount() const
{
    CAmount totalTransactionAmount = 0;
    for (const SendCoinsRecipient &rcp : recipients)
    {
        totalTransactionAmount += rcp.amount;
    }
    return totalTransactionAmount;
}
