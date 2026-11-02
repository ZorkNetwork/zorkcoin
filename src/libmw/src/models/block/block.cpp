#include <mw/models/block/block.h>

#include <mw/consensus/params.h>
#include <mw/consensus/stealth_sum_validator.h>
#include <mw/mmr/mmr.h>

bool mw::Block::HasValidKernelMMR() const
{
    if (m_pHeader->GetNumKernels() != m_body.GetKernels().size()) {
        return false;
    }

    MemMMR kernel_mmr;
    std::for_each(
        GetKernels().cbegin(), GetKernels().cend(),
        [&kernel_mmr](const Kernel& kernel) { kernel_mmr.Add(kernel); }
    );
    return m_pHeader->GetKernelRoot() == kernel_mmr.Root();
}

void mw::Block::Validate(int32_t kernel_lock_height_grandfather) const
{
    if (m_pHeader->GetNumKernels() != m_body.GetKernels().size()) {
        ThrowValidation(EConsensusError::MMR_MISMATCH);
    }

    m_body.Validate();

    if (GetHeight() > kernel_lock_height_grandfather && m_body.GetLockHeight() > GetHeight()) {
        ThrowValidation(EConsensusError::LOCK_HEIGHT);
    }

    StealthSumValidator::Validate(m_pHeader->GetStealthOffset(), m_body);

    if (!HasValidKernelMMR()) {
        ThrowValidation(EConsensusError::MMR_MISMATCH);
    }
}
