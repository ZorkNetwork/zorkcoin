// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <mw/models/tx/kernel.h>
#include <mw/models/tx/transaction.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <serialize.h>
#include <tinyformat.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <set>
#include <span>
#include <stdexcept>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : version{CTransaction::CURRENT_VERSION}, nLockTime{0} {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime}, mweb_tx(tx.mweb_tx.ToMutable()), m_hogEx(tx.m_hogEx), m_had_attached_mweb(tx.HadAttachedMWEB()) {}

Txid CMutableTransaction::GetHash() const
{
    if (IsMWEBOnly()) {
        const MWEB::Tx finalized{mweb_tx};
        if (!finalized.IsNull()) {
            const auto& kernels = finalized.m_transaction->GetKernels();
            if (!kernels.empty()) {
                return Txid::FromUint256(uint256(kernels.front().GetHash().vec()));
            }
        }
    }

    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS_NO_MWEB(*this)).GetHash());
}

bool CTransaction::ComputeHasWitness() const
{
    return std::any_of(vin.begin(), vin.end(), [](const auto& input) {
        return !input.scriptWitness.IsNull();
    });
}

Txid CTransaction::ComputeHash() const
{
    if (IsMWEBOnly()) {
        const auto& kernels = mweb_tx.m_transaction->GetKernels();
        if (!kernels.empty()) {
            return Txid::FromUint256(uint256(kernels.front().GetHash().vec()));
        }
    }

    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS_NO_MWEB(*this)).GetHash());
}

Wtxid CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return Wtxid::FromUint256(hash.ToUint256());
    }

    return Wtxid::FromUint256((HashWriter{} << TX_WITH_WITNESS(TX_NO_MWEB(*this))).GetHash());
}

CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime}, mweb_tx(tx.mweb_tx), m_hogEx(tx.m_hogEx), m_had_attached_mweb{tx.m_had_attached_mweb || (!tx.mweb_tx.IsNull() && !tx.mweb_tx.IsFinal())}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), version{tx.version}, nLockTime{tx.nLockTime}, mweb_tx(tx.mweb_tx), m_hogEx(tx.m_hogEx), m_had_attached_mweb{tx.m_had_attached_mweb || (!tx.mweb_tx.IsNull() && !tx.mweb_tx.IsFinal())}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int CTransaction::ComputeTotalSize() const
{
    return ::GetSerializeSize(TX_WITH_WITNESS(*this));
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%u, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        version,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";

    if (!mweb_tx.IsNull()) {
        str += "    " + mweb_tx.ToString() + "\n";
    }

    return str;
}

std::vector<CTxInput> CTransaction::GetInputs() const noexcept
{
    std::vector<CTxInput> inputs;

    inputs.reserve(vin.size());
    for (const CTxIn& txin : vin) {
        inputs.emplace_back(txin);
    }

    for (const mw::Hash& spent_id : mweb_tx.GetSpentIDs()) {
        inputs.emplace_back(spent_id);
    }

    return inputs;
}

CTxOutput CTransaction::GetOutput(const size_t index) const noexcept
{
    assert(vout.size() > index);
    return CTxOutput{COutPoint{GetHash(), static_cast<uint32_t>(index)}, vout[index]};
}

CTxOutput CTransaction::GetOutput(const OutputIndex& idx) const noexcept
{
    if (std::holds_alternative<mw::Hash>(idx)) {
        return CTxOutput{std::get<mw::Hash>(idx)};
    }

    const COutPoint& outpoint = std::get<COutPoint>(idx);
    assert(vout.size() > outpoint.n);
    return CTxOutput{outpoint, vout[outpoint.n]};
}

std::vector<CTxOutput> CTransaction::GetOutputs() const noexcept
{
    std::vector<CTxOutput> outputs;

    outputs.reserve(vout.size());
    for (size_t n = 0; n < vout.size(); n++) {
        outputs.emplace_back(COutPoint{GetHash(), static_cast<uint32_t>(n)}, vout[n]);
    }

    for (const mw::Hash& output_id : mweb_tx.GetOutputIDs()) {
        outputs.emplace_back(output_id);
    }

    return outputs;
}
