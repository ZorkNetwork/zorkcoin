
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_TRANSACTION_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_TRANSACTION_H
#include <mw/common/macros.h>
#include <mw/common/traits.h>
#include <mw/consensus/weight.h>
#include <mw/crypto/hasher.h>
#include <mw/exceptions/validation_exception.h>
#include <mw/models/crypto/hash.h>
#include <mw/models/crypto/big_integer.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/tx/tx_body.h>

#include <memory>
#include <numeric>
#include <optional>
#include <vector>

MW_NAMESPACE

////////////////////////////////////////
// TRANSACTION - Represents a transaction or merged transactions before they've been included in a block.
////////////////////////////////////////
class Transaction :
    public Traits::IPrintable,
    public Traits::ISerializable,
    public Traits::IHashable
{
public:
    using CPtr = std::shared_ptr<const Transaction>;

    //
    // Constructors
    //
    Transaction(BlindingFactor kernel_offset, BlindingFactor stealth_offset, TxBody body)
        : m_kernelOffset(std::move(kernel_offset)), m_stealthOffset(std::move(stealth_offset)), m_body(std::move(body))
    {
        m_hash = Hashed(*this);
    }
    Transaction(const Transaction& transaction) = default;
    Transaction(Transaction&& transaction) noexcept = default;
    Transaction() = default;

    //
    // Factory
    //
    static mw::Transaction::CPtr Create(
        BlindingFactor kernel_offset,
        BlindingFactor owner_offset,
        std::vector<Input> inputs,
        std::vector<Output> outputs,
        std::vector<Kernel> kernels
    );

    //
    // Destructor
    //
    virtual ~Transaction() = default;

    //
    // Operators
    //
    Transaction& operator=(const Transaction& transaction) = default;
    Transaction& operator=(Transaction&& transaction) noexcept = default;
    bool operator<(const Transaction& transaction) const noexcept { return GetHash() < transaction.GetHash(); }
    bool operator==(const Transaction& transaction) const noexcept { return GetHash() == transaction.GetHash(); }
    bool operator!=(const Transaction& transaction) const noexcept { return GetHash() != transaction.GetHash(); }

    //
    // Getters
    //
    const BlindingFactor& GetKernelOffset() const noexcept { return m_kernelOffset; }
    const BlindingFactor& GetStealthOffset() const noexcept { return m_stealthOffset; }
    const TxBody& GetBody() const noexcept { return m_body; }
    const std::vector<Input>& GetInputs() const noexcept { return m_body.GetInputs(); }
    const std::vector<Output>& GetOutputs() const noexcept { return m_body.GetOutputs(); }
    const std::vector<Kernel>& GetKernels() const noexcept { return m_body.GetKernels(); }
    std::optional<CAmount> GetTotalFee() const noexcept { return m_body.GetTotalFee(); }
    int32_t GetLockHeight() const noexcept { return m_body.GetLockHeight(); }
    uint64_t CalcWeight() const noexcept { return (uint64_t)Weight::Calculate(m_body); }

    std::vector<Commitment> GetKernelCommits() const noexcept { return m_body.GetKernelCommits(); }
    std::vector<Commitment> GetInputCommits() const noexcept { return m_body.GetInputCommits(); }
    std::vector<Commitment> GetOutputCommits() const noexcept { return m_body.GetOutputCommits(); }
    std::vector<PegInCoin> GetPegIns() const noexcept { return m_body.GetPegIns(); }
    std::optional<CAmount> GetPegInAmount() const noexcept { return m_body.GetPegInAmount(); }
    std::vector<PegOutCoin> GetPegOuts() const noexcept { return m_body.GetPegOuts(); }
    std::optional<CAmount> GetSupplyChange() const noexcept { return m_body.GetSupplyChange(); }

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(Transaction, obj)
    {
        READWRITE(obj.m_kernelOffset);
        READWRITE(obj.m_stealthOffset);
        READWRITE(obj.m_body);
        // Cast keeps the call non-dependent so IWYU charges Hashed to this header, not to every deserializing TU.
        SER_READ(obj, obj.m_hash = Hashed(static_cast<const Traits::ISerializable&>(obj)));

        if (ser_action.ForRead()) {
            if (obj.m_body.GetKernels().empty()) {
                throw std::ios_base::failure("Transaction requires at least one kernel");
            }
        }
    }

    template <typename Stream>
    Transaction(deserialize_type, Stream& s)
        : m_kernelOffset{}, m_stealthOffset{}, m_body{}, m_hash{}
    {
        Unserialize(s);
    }

    //
    // Traits
    //
    std::string Format() const final { return "Tx(" + GetHash().Format() + ")"; }
    const mw::Hash& GetHash() const noexcept final { return m_hash; }

    bool IsStandard() const noexcept;
    //! Cheap structural checks only (no cryptography).
    void ValidateStructure() const;
    //! Expensive body crypto + kernel-sum + stealth-sum.
    void VerifyCrypto() const;
    //! ValidateStructure() then VerifyCrypto().
    void Validate() const;
    //! Runs Validate() and reports the first consensus error instead of throwing.
    [[nodiscard]] std::optional<EConsensusError> GetValidationError() const noexcept;

    std::string Print() const
    {
        auto print_kernel = [](const Kernel& kernel) -> std::string {
            const auto pegout_amount = kernel.GetPegOutAmount();
            return StringUtil::Format(
                "kern(kernel_id:{}, commit:{}, pegin: {}, pegout: {}, fee: {})",
                kernel.GetKernelID(),
                kernel.GetCommitment(),
                kernel.GetPegIn(),
                pegout_amount ? StringUtil::Format("{}", *pegout_amount) : "INVALID",
                kernel.GetFee()
            );
        };
        std::string kernels_str = std::accumulate(
            GetKernels().begin(), GetKernels().end(), std::string{},
            [&print_kernel](std::string str, const Kernel& kern) {
                return str.empty() ? print_kernel(kern) : std::move(str) + ", " + print_kernel(kern);
            }
        );

        return StringUtil::Format(
            "tx(hash:{}, offset:{}, kernels:[{}], inputs:{}, outputs:{})",
            GetHash(),
            GetKernelOffset().ToHex(),
            kernels_str,
            GetInputs(),
            GetOutputs()
        );
    }

private:
    // The kernel "offset" k2 excess is k1G after splitting the key k = k1 + k2.
    BlindingFactor m_kernelOffset;

    BlindingFactor m_stealthOffset;

    // The transaction body.
    TxBody m_body;

    mw::Hash m_hash;
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_TX_TRANSACTION_H
