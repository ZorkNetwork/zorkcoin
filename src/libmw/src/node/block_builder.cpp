#include <mw/node/block_builder.h>
#include <mw/consensus/params.h>
#include <mw/consensus/weight.h>

#include <unordered_set>
#include <numeric>

MW_NAMESPACE

bool BlockBuilder::AddTransaction(const Transaction::CPtr& pTransaction, const std::vector<PegInCoin>& pegins)
{
    // Check weight (m_max_weight defaults to consensus; mine-test may raise slightly)
    uint64_t weight = Weight::Calculate(pTransaction->GetBody());
    if ((weight + m_weight) > m_max_weight) {
        LOG_ERROR("Exceeds max block weight");
        return false;
    }

    // Verify pegin amount matches
    const auto actual_amount = pTransaction->GetPegInAmount();
    if (!actual_amount) {
        LOG_ERROR("Invalid pegin amount");
        return false;
    }

    const CAmount expected_amount = std::accumulate(pegins.cbegin(), pegins.cend(), (CAmount)0,
        [](const CAmount sum, const PegInCoin& pegin) { return sum + pegin.GetAmount(); }
    );
    if (*actual_amount != expected_amount) {
        LOG_ERROR("Mismatched pegin amount");
        return false;
    }

    // Verify pegin kernels are unique
    std::unordered_set<mw::Hash> pegin_ids;
    for (const PegInCoin& pegin : pegins) {
        if (pegin_ids.contains(pegin.GetKernelID())) {
            LOG_ERROR("Duplicate pegin kernels");
            return false;
        }

        pegin_ids.insert(pegin.GetKernelID());
    }

    // Verify pegin outputs are included
    std::vector<PegInCoin> pegin_coins = pTransaction->GetPegIns();
    if (pegin_coins.size() != pegins.size()) {
        LOG_ERROR("Mismatched pegin count");
        return false;
    }

    for (const PegInCoin& pegin : pegin_coins) {
        if (!pegin_ids.contains(pegin.GetKernelID())) {
            LOG_ERROR_F("Pegin kernel {} not found", pegin.GetKernelID());
            return false;
        }
    }

    // Validate transaction
    try {
        pTransaction->Validate();
    } catch (std::exception& e) {
        LOG_ERROR_F("Failed to validate transaction {}. Error: {}", pTransaction, e.what());
        return false;
    }

    // Kernel IDs must remain unique in the aggregate block body.
    for (const Kernel& kernel : pTransaction->GetKernels()) {
        if (m_stagedKernels.contains(kernel.GetKernelID())) {
            LOG_ERROR_F("Kernel {} already staged", kernel.GetKernelID());
            return false;
        }
    }

    // Individually valid transactions can still form unrepresentable group
    // identities when aggregated. Extend the validated sums using only the
    // candidate so template construction remains linear in the body size.
    KernelSumValidator::SumState kernel_sums;
    StealthSumValidator::SumState stealth_sums;
    try {
        kernel_sums = KernelSumValidator::ValidateAndAdd(*pTransaction, m_kernelSums);
        stealth_sums = StealthSumValidator::ValidateAndAdd(
            pTransaction->GetStealthOffset(),
            pTransaction->GetBody(),
            m_stealthSums
        );
    } catch (const std::exception& e) {
        LOG_ERROR_F("Transaction is incompatible with staged MWEB transactions. Error: {}", e.what());
        return false;
    }

    // Make sure all inputs are available.
    for (const Input& input : pTransaction->GetInputs()) {
        if (m_stagedInputs.contains(input.GetOutputID())) {
            LOG_ERROR_F("Input {} already staged", input.GetOutputID());
            return false;
        }

        if (!m_pCoinsView->HasCoin(input.GetOutputID()) && !m_stagedOutputs.contains(input.GetOutputID())) {
            LOG_ERROR_F("Input {} not found on chain", input.GetOutputID());
            return false;
        }
    }

    // Make sure no duplicate outputs already on chain.
    for (const Output& output : pTransaction->GetOutputs()) {
        if (m_pCoinsView->HasCoin(output.GetOutputID())) {
            LOG_ERROR_F("Output {} already on chain", output.GetOutputID());
            return false;
        }

        if (m_stagedOutputs.contains(output.GetOutputID())) {
            LOG_ERROR_F("Output {} already staged", output.GetOutputID());
            return false;
        }
    }

    m_stagedTxs.push_back(pTransaction);
    m_weight += weight;

    for (const Input& input : pTransaction->GetInputs()) {
        auto inserted = m_stagedInputs.insert(input.GetOutputID());
        assert(inserted.second);
    }

    for (const Output& output : pTransaction->GetOutputs()) {
        auto inserted = m_stagedOutputs.insert(output.GetOutputID());
        assert(inserted.second);
    }

    for (const Kernel& kernel : pTransaction->GetKernels()) {
        auto inserted = m_stagedKernels.insert(kernel.GetKernelID());
        assert(inserted.second);
    }

    m_kernelSums = std::move(kernel_sums);
    m_stealthSums = std::move(stealth_sums);

    return true;
}

BlockBuilder::Checkpoint BlockBuilder::GetCheckpoint() const
{
    return Checkpoint{m_stagedTxs.size(), m_weight, m_kernelSums, m_stealthSums};
}

void BlockBuilder::Rollback(const Checkpoint& checkpoint)
{
    assert(checkpoint.num_txs <= m_stagedTxs.size());
    for (size_t i = checkpoint.num_txs; i < m_stagedTxs.size(); ++i) {
        for (const Input& input : m_stagedTxs[i]->GetInputs()) {
            m_stagedInputs.erase(input.GetOutputID());
        }
        for (const Output& output : m_stagedTxs[i]->GetOutputs()) {
            m_stagedOutputs.erase(output.GetOutputID());
        }
        for (const Kernel& kernel : m_stagedTxs[i]->GetKernels()) {
            m_stagedKernels.erase(kernel.GetKernelID());
        }
    }
    m_stagedTxs.resize(checkpoint.num_txs);
    m_weight = checkpoint.weight;
    m_kernelSums = checkpoint.kernel_sums;
    m_stealthSums = checkpoint.stealth_sums;
}

mw::Block::Ptr BlockBuilder::BuildBlock() const
{
    return mw::CoinsViewCache(m_pCoinsView).BuildNextBlock(m_height, m_stagedTxs);
}

END_NAMESPACE
