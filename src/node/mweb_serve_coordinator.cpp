// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_serve_coordinator.h>

#include <validation.h>

namespace node {

namespace {
MWEBServeCoordinator g_coordinator;
} // namespace

MWEBServeCoordinator& GetMWEBServeCoordinator()
{
    return g_coordinator;
}

std::shared_ptr<MWEBServeCoordinatorJob> MWEBServeCoordinator::AttachOrCreate(const uint256& block_hash)
{
    LOCK(m_mutex);
    auto it = m_jobs.find(block_hash);
    if (it != m_jobs.end() && !it->second->failed && !it->second->cancelled) {
        return it->second;
    }
    auto job = std::make_shared<MWEBServeCoordinatorJob>();
    job->block_hash = block_hash;
    m_jobs[block_hash] = job;
    return job;
}

void MWEBServeCoordinator::CancelNotOnActiveChain(const ChainstateManager& chainman)
{
    AssertLockHeld(cs_main);
    LOCK(m_mutex);
    for (auto& [hash, job] : m_jobs) {
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex || !chainman.ActiveChain().Contains(*pindex)) {
            job->cancelled = true;
            job->failed = true;
        }
    }
}

void MWEBServeCoordinator::PruneCompleted()
{
    LOCK(m_mutex);
    std::erase_if(m_jobs, [](const auto& entry) {
        const auto& job = entry.second;
        return job->snapshot != nullptr || job->failed || job->cancelled;
    });
}

size_t MWEBServeCoordinator::ActiveCount() const
{
    LOCK(m_mutex);
    return m_jobs.size();
}

bool MWEBServeCoordinator::HasActive(const uint256& block_hash) const
{
    LOCK(m_mutex);
    const auto it = m_jobs.find(block_hash);
    return it != m_jobs.end() && !it->second->failed && !it->second->cancelled && !it->second->snapshot;
}

} // namespace node
