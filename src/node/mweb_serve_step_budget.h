// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MWEB_SERVE_STEP_BUDGET_H
#define BITCOIN_NODE_MWEB_SERVE_STEP_BUDGET_H

#include <mw/node/coins_view_materialize.h>

#include <cstddef>

namespace node {

/** Wraps libmw MaterializeBudget with replay-block accounting (I11). */
class MWEBWorkBudget {
public:
    explicit MWEBWorkBudget(size_t max_bytes = 65536, size_t max_leaf_ops = 64);

    bool StepAllowed() const noexcept { return m_replay_block_allowed || m_materialize_budget.max_bytes > 0 || m_materialize_budget.max_leaf_ops > 0; }

    bool ConsumeReplayBlock() noexcept;
    mw::MaterializeBudget MaterializeBudget() const noexcept { return m_materialize_budget; }

    size_t max_bytes() const noexcept { return m_materialize_budget.max_bytes; }
    size_t max_leaf_ops() const noexcept { return m_materialize_budget.max_leaf_ops; }

private:
    bool m_replay_block_allowed{true};
    mw::MaterializeBudget m_materialize_budget;
};

} // namespace node

#endif // BITCOIN_NODE_MWEB_SERVE_STEP_BUDGET_H
