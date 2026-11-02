// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/mweb_util.h>

#include <outputtype.h>
#include <policy/feerate.h>
#include <sync.h>
#include <test/util/mweb_setup.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/result.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <optional>
#include <stdexcept>

namespace wallet {
std::map<mw::Hash, CAmount> PegInAndMine(MWEBRegtest100Setup& setup, CWallet& wallet, CAmount amount)
{
    CCoinControl coin_control;
    coin_control.m_mweb_peg_in = true;
    coin_control.m_feerate = CFeeRate{10'000};
    const auto pegin = CreateTransaction(wallet, {{getNewDestination(wallet, OutputType::MWEB), amount, /*subtract_fee=*/false}},
        /*change_pos=*/std::nullopt, coin_control);
    if (!pegin) {
        throw std::runtime_error(util::ErrorString(pegin).original);
    }
    if (pegin->tx->mweb_tx.GetPegIns().empty()) {
        throw std::runtime_error("PegInAndMine: the transaction has no peg-in");
    }
    {
        LOCK(::cs_main);
        const MempoolAcceptResult result = Assert(setup.m_node.chainman)->ProcessTransaction(pegin->tx);
        if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            throw std::runtime_error(strprintf("PegInAndMine: the peg-in was rejected: %s", result.m_state.ToString()));
        }
    }
    setup.MineMWEBEraBlock();
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    std::map<mw::Hash, CAmount> coins;
    LOCK(wallet.cs_wallet);
    for (const auto& entry : wallet.ListMWEBUnspent(/*min_depth=*/1, /*max_depth=*/9999999, /*include_unsafe=*/false, nullptr, 0, MAX_MONEY)) {
        coins.emplace(entry.output_id, entry.amount);
    }
    return coins;
}
} // namespace wallet
