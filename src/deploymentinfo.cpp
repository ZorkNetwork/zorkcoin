// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentinfo.h>

Optional<Consensus::BuriedDeployment> GetBuriedDeployment(const std::string& name)
{
    if (name == "bip34") return Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB;
    if (name == "dersig") return Consensus::BuriedDeployment::DEPLOYMENT_DERSIG;
    if (name == "cltv") return Consensus::BuriedDeployment::DEPLOYMENT_CLTV;
    if (name == "csv") return Consensus::BuriedDeployment::DEPLOYMENT_CSV;
    if (name == "segwit") return Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT;
    return nullopt;
}

const char* DeploymentName(Consensus::BuriedDeployment dep)
{
    switch (dep) {
    case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB: return "bip34";
    case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG: return "dersig";
    case Consensus::BuriedDeployment::DEPLOYMENT_CLTV: return "cltv";
    case Consensus::BuriedDeployment::DEPLOYMENT_CSV: return "csv";
    case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT: return "segwit";
    }
    return "unknown";
}
