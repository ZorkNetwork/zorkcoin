// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mweb_serve_step_budget.h>

namespace node {

MWEBWorkBudget::MWEBWorkBudget(size_t max_bytes, size_t max_leaf_ops)
    : m_materialize_budget{max_leaf_ops, max_bytes}
{
}

bool MWEBWorkBudget::ConsumeReplayBlock() noexcept
{
    if (!m_replay_block_allowed) return false;
    m_replay_block_allowed = false;
    return true;
}

} // namespace node
