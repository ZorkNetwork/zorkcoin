// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTINFO_H
#define BITCOIN_DEPLOYMENTINFO_H

#include <consensus/params.h>
#include <optional.h>

#include <string>

/**
 * Map deployment names (bip34, dersig, cltv, csv, segwit) to BuriedDeployment enum.
 * Returns nullopt if the name is not recognized.
 */
Optional<Consensus::BuriedDeployment> GetBuriedDeployment(const std::string& name);

/**
 * Return the deployment name for a BuriedDeployment.
 */
const char* DeploymentName(Consensus::BuriedDeployment dep);

#endif // BITCOIN_DEPLOYMENTINFO_H
