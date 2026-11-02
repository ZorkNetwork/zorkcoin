// Copyright (c) 2026 The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_KASPA_TX_H
#define BITCOIN_AUXPOW_KASPA_TX_H

#include <span>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace auxpow {

static constexpr size_t KASPA_SUBNETWORK_ID_SIZE = 20;
inline constexpr unsigned char KASPA_SUBNETWORK_ID_COINBASE[KASPA_SUBNETWORK_ID_SIZE] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

struct KaspaCovenant {
    bool present{false};
    uint16_t authorizing_input{0};
    uint256 covenant_id;
};

struct KaspaTxOutput {
    uint64_t value{0};
    uint16_t script_version{0};
    std::vector<unsigned char> script;
    KaspaCovenant covenant;
};

struct KaspaTransaction {
    uint16_t version{0};
    std::vector<KaspaTxOutput> outputs;
    uint64_t lock_time{0};
    unsigned char subnetwork_id[KASPA_SUBNETWORK_ID_SIZE]{};
    uint64_t gas{0};
    std::vector<unsigned char> payload;
    uint64_t storage_mass{0};
};

bool SerializeKaspaTransaction(const KaspaTransaction& tx, std::vector<unsigned char>& out, std::string* err = nullptr);
bool DeserializeKaspaTransaction(std::span<const unsigned char> in, KaspaTransaction& out, size_t& consumed, std::string* err = nullptr);

uint256 KaspaTransactionHash(const KaspaTransaction& tx);

bool IsKaspaCoinbaseShape(const KaspaTransaction& tx, std::string* err = nullptr);

/** Extract blue_score, subsidy, miner script, extra_data from coinbase payload. */
bool ParseKaspaCoinbasePayload(const std::vector<unsigned char>& payload,
                               uint64_t& blue_score,
                               uint64_t& subsidy,
                               uint16_t& spk_version,
                               std::vector<unsigned char>& spk,
                               std::vector<unsigned char>& extra_data,
                               std::string* err = nullptr);

} // namespace auxpow

#endif // BITCOIN_AUXPOW_KASPA_TX_H
