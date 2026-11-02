// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include <attributes.h>
#include <consensus/amount.h>
#include <mw/models/crypto/hash.h>
#include <mw/models/tx/mutable_tx.h>
#include <mweb/mweb_models.h>
#include <primitives/transaction_identifier.h> // IWYU pragma: export
#include <script/script.h>
#include <serialize.h>

#include <algorithm>
#include <cassert>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

// MWEB: Serialization flag to omit extension-block data from (de)serialization.
static const int SERIALIZE_NO_MWEB = 0x20000000;

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    Txid hash;
    uint32_t n;

    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint(): n(NULL_INDEX) { }
    COutPoint(const Txid& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }

    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.hash, obj.n); }

    void SetNull() { hash.SetNull(); n = NULL_INDEX; }
    bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return std::tie(a.hash, a.n) < std::tie(b.hash, b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

    /**
     * Setting nSequence to this value for every input in a transaction
     * disables nLockTime/IsFinalTx().
     * It fails OP_CHECKLOCKTIMEVERIFY/CheckLockTime() for any input that has
     * it set (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static constexpr uint32_t SEQUENCE_FINAL{0xffffffff};
    /**
     * This is the maximum sequence number that enables both nLockTime and
     * OP_CHECKLOCKTIMEVERIFY (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static constexpr uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};

    // Below flags apply in the context of BIP 68. BIP 68 requires the tx
    // version to be set to 2, or higher.
    /**
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time.
     * It skips SequenceLocks() for any input that has it set (BIP 68).
     * It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
     * it set (BIP 112).
     */
    static constexpr uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG{1U << 31};

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG{1 << 22};

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_MASK{0x0000ffff};

    /**
     * In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static constexpr int SEQUENCE_LOCKTIME_GRANULARITY{9};

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    std::string ToString() const;
};

using OutputIndex = std::variant<COutPoint, mw::Hash>; // MWEB

/// MWEB: A generic transaction input (canonical CTxIn or MWEB output ID).
class CTxInput
{
public:
    CTxInput(mw::Hash output_id)
        : m_input(std::move(output_id)) {}
    CTxInput(CTxIn txin)
        : m_input(std::move(txin)) {}

    bool IsMWEB() const noexcept { return std::holds_alternative<mw::Hash>(m_input); }
    OutputIndex GetIndex() const noexcept
    {
        return IsMWEB() ? OutputIndex{ToMWEB()} : OutputIndex{GetTxIn().prevout};
    }

    std::string ToString() const
    {
        return IsMWEB() ? ToMWEB().ToHex() : GetTxIn().ToString();
    }

    const mw::Hash& ToMWEB() const noexcept
    {
        assert(IsMWEB());
        return std::get<mw::Hash>(m_input);
    }

    const CTxIn& GetTxIn() const noexcept
    {
        assert(!IsMWEB());
        return std::get<CTxIn>(m_input);
    }

private:
    std::variant<CTxIn, mw::Hash> m_input;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    std::string ToString() const;
};

/// MWEB: A generic transaction output (canonical CTxOut or MWEB output ID).
class CTxOutput
{
public:
    CTxOutput() = default;
    CTxOutput(mw::Hash output_id)
        : m_idx(std::move(output_id)), m_txout(std::nullopt) {}
    CTxOutput(OutputIndex idx, CTxOut txout)
        : m_idx(std::move(idx)), m_txout(std::move(txout)) {}

    bool IsMWEB() const noexcept { return std::holds_alternative<mw::Hash>(m_idx); }

    const OutputIndex& GetIndex() const noexcept { return m_idx; }

    std::string ToString() const
    {
        return IsMWEB() ? ToMWEB().ToHex() : GetTxOut().ToString();
    }

    const mw::Hash& ToMWEB() const noexcept
    {
        assert(IsMWEB());
        return std::get<mw::Hash>(m_idx);
    }

    const CTxOut& GetTxOut() const noexcept
    {
        assert(!IsMWEB() && m_txout.has_value());
        return *m_txout;
    }

    const CScript& GetScriptPubKey() const noexcept
    {
        assert(!IsMWEB());
        return GetTxOut().scriptPubKey;
    }

private:
    OutputIndex m_idx;
    std::optional<CTxOut> m_txout;
};

struct CMutableTransaction;

struct TransactionSerParams {
    const bool allow_witness;
    const bool allow_mweb; // MWEB
    SER_PARAMS_OPFUNC
};
inline constexpr TransactionSerParams TX_WITH_WITNESS{.allow_witness = true, .allow_mweb = true};
inline constexpr TransactionSerParams TX_NO_WITNESS{.allow_witness = false, .allow_mweb = true};
inline constexpr TransactionSerParams TX_NO_MWEB{.allow_witness = true, .allow_mweb = false};
inline constexpr TransactionSerParams TX_NO_WITNESS_NO_MWEB{.allow_witness = false, .allow_mweb = false};

/**
 * Basic transaction serialization format:
 * - uint32_t version
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - uint32_t version
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CScriptWitness scriptWitness; (deserialized into CTxIn)
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
void UnserializeTransaction(TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;
    const bool fAllowMWEB = params.allow_mweb; // MWEB

    s >> tx.version;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    tx.mweb_tx.SetNull(); // MWEB
    tx.m_hogEx = false; // MWEB
    tx.m_had_attached_mweb = false; // MWEB
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if ((flags & 8) && fAllowMWEB) { // MWEB
        flags ^= 8;

        s >> tx.mweb_tx;
        // Sticky only when a present payload cannot survive Finalized() (e.g.
        // feature-0 inputs). Final payloads use HasMWEBTx(); intentional strip
        // of those must not leave a sticky bit that fails CheckBlock.
        tx.m_had_attached_mweb = !tx.mweb_tx.IsNull() && !tx.mweb_tx.IsFinal();
        if (tx.mweb_tx.IsNull()) {
            if (tx.vout.empty()) {
                throw std::ios_base::failure("Missing HogEx output");
            }

            tx.m_hogEx = true;
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
void SerializeTransaction(const TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;
    const bool fAllowMWEB = params.allow_mweb; // MWEB

    s << tx.version;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (fAllowMWEB) { // MWEB
        if (tx.m_hogEx || !tx.mweb_tx.IsNull()) {
            flags |= 8;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    if (flags & 8) { // MWEB
        s << tx.mweb_tx;
    }
    s << tx.nLockTime;
}

template<typename TxType>
inline CAmount CalculateOutputValue(const TxType& tx)
{
    return std::accumulate(tx.vout.cbegin(), tx.vout.cend(), CAmount{0}, [](CAmount sum, const auto& txout) { return sum + txout.nValue; });
}

struct EqualsOptions {
    bool include_script_sig{true};
    bool include_witness_data{true};
};


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    // Default transaction version.
    static constexpr uint32_t CURRENT_VERSION{2};

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t version;
    const uint32_t nLockTime;
    const MWEB::Tx mweb_tx; // MWEB

    /** Memory only. */
    const bool m_hogEx; // MWEB
    /** Memory only. True if a non-null MWEB payload was present before Finalized() drop. */
    const bool m_had_attached_mweb; // MWEB

private:
    /** Memory only. */
    const bool m_has_witness;
    const Txid hash;
    const Wtxid m_witness_hash;

    Txid ComputeHash() const;
    Wtxid ComputeWitnessHash() const;

    bool ComputeHasWitness() const;

public:
    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction& tx);
    explicit CTransaction(CMutableTransaction&& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, const TransactionSerParams& params, Stream& s) : CTransaction(CMutableTransaction(deserialize, params, s)) {}
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const Txid& GetHash() const LIFETIMEBOUND { return hash; }
    const Wtxid& GetWitnessHash() const LIFETIMEBOUND { return m_witness_hash; };

    // Return sum of txouts.
    CAmount GetValueOut() const;

    /**
     * Calculate the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int ComputeTotalSize() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    bool Equals(const CTransaction& other, const EqualsOptions opts = {}) const
    {
        return nLockTime == other.nLockTime &&
            version == other.version &&
            vout == other.vout &&
            std::ranges::equal(vin, other.vin, [&opts](const CTxIn& self, const CTxIn& other) {
                return self.prevout == other.prevout &&
                    self.nSequence == other.nSequence &&
                    (opts.include_script_sig ? self.scriptSig == other.scriptSig : true) &&
                    (opts.include_witness_data ? self.scriptWitness.stack == other.scriptWitness.stack : true);
            });
    }

    std::string ToString() const;

    bool HasWitness() const { return m_has_witness; }

    // MWEB
    bool HasMWEBTx() const noexcept { return !mweb_tx.IsNull(); }
    bool IsHogEx() const noexcept { return m_hogEx; }
    bool HadAttachedMWEB() const noexcept { return m_had_attached_mweb; }
    bool IsMWEBOnly() const noexcept { return HasMWEBTx() && vin.empty() && vout.empty(); }

    std::vector<CTxInput> GetInputs() const noexcept;
    CTxOutput GetOutput(size_t index) const noexcept;
    CTxOutput GetOutput(const OutputIndex& idx) const noexcept;
    std::vector<CTxOutput> GetOutputs() const noexcept;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t version;
    uint32_t nLockTime;
    mw::MutableTx mweb_tx; // MWEB

    /** Memory only. */
    bool m_hogEx = false; // MWEB
    /** Memory only. True if a non-null MWEB payload was present before Finalized() drop. */
    bool m_had_attached_mweb = false; // MWEB

    explicit CMutableTransaction();
    explicit CMutableTransaction(const CTransaction& tx);

    /** Drop attached MWEB and clear the non-final sticky bit (canonical vtx / BIP152). */
    void ClearAttachedMWEB()
    {
        mweb_tx.SetNull();
        m_had_attached_mweb = false;
    }

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, const TransactionSerParams& params, Stream& s) {
        UnserializeTransaction(*this, s, params);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    Txid GetHash() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }

    // MWEB
    bool HasMWEBTx() const noexcept { return !mweb_tx.IsNull(); }
    bool HadAttachedMWEB() const noexcept { return m_had_attached_mweb; }
    bool IsMWEBOnly() const noexcept { return HasMWEBTx() && vin.empty() && vout.empty(); }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

namespace std {
/** Disable default std::hash for CTransactionRef to prevent accidentally
 *  comparing by pointer. Use CTransactionRefHash or provide a custom
 *  hasher. */
template <>
struct hash<CTransactionRef> {
    hash() = delete;
    // Belt-and-suspenders, already implied by the above.
    size_t operator()(const CTransactionRef&) const = delete;
};
} // namespace std

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
