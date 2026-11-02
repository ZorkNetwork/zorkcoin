// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/peerman_args.h>

#include <common/args.h>
#include <net_processing.h>

#include <algorithm>
#include <limits>
#include <string>

namespace node {

void ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options)
{
    if (auto value{argsman.GetBoolArg("-txreconciliation")}) options.reconcile_txs = *value;

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = uint32_t((std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max())));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) options.capture_messages = *value;

    if (auto value{argsman.GetBoolArg("-blocksonly")}) options.ignore_incoming_txs = *value;

    if (auto value{argsman.GetIntArg("-txsendrate")}) {
        options.tx_send_rate = uint32_t(std::clamp<int64_t>(*value, 1, 1000));
    }

    if (auto value{argsman.GetBoolArg("-privatebroadcast")}) options.private_broadcast = *value;

    if (const auto value{argsman.GetArg("-mwebserve")}) {
        const std::string& mode{*value};
        if (mode == "0" || mode == "off") {
            options.mweb_serve = MwebServeMode::OFF;
        } else if (mode == "1" || mode == "force") {
            options.mweb_serve = MwebServeMode::FORCE;
        } else {
            options.mweb_serve = MwebServeMode::AUTO;
        }
    }

    if (auto value{argsman.GetBoolArg("-mwebserveinblocksonly")}) {
        options.mweb_serve_in_blocksonly = *value;
    }

    if (auto value{argsman.GetIntArg("-mwebserveburst")}) {
        options.mweb_serve_burst = static_cast<double>(std::max<int64_t>(1, *value));
    }

    if (auto value{argsman.GetIntArg("-mwebservematerialbudget")}) {
        options.mweb_serve_material_budget = static_cast<size_t>(std::max<int64_t>(1024, *value));
    }

    if (auto value{argsman.GetIntArg("-mwebservematerialleafops")}) {
        options.mweb_serve_material_leaf_ops = static_cast<size_t>(std::max<int64_t>(1, *value));
    }

    if (auto value{argsman.GetIntArg("-mwebservecreditdenydisconnect")}) {
        options.mweb_serve_credit_deny_disconnect = static_cast<int>(std::max<int64_t>(1, *value));
    }
}

} // namespace node

