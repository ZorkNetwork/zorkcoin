// Copyright (c) The Zorkcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/btc_launch_lock.h>

#include <arith_uint256.h>
#include <crypto/common.h>
#include <hash.h>
#include <tinyformat.h>
#include <uint256.h>

#include <string>
#include <vector>

static const std::vector<unsigned char> BTC_LAUNCH_LABEL{'b', 't', 'c'};

CScript BuildBtcLaunchLockScript(std::span<const unsigned char> header80)
{
    assert(header80.size() == BTC_LAUNCH_HEADER_SIZE);
    return CScript() << OP_RETURN << BTC_LAUNCH_LABEL << int64_t{BTC_LAUNCH_TAG}
                     << std::vector<unsigned char>(header80.begin(), header80.end());
}

bool ParseBtcLaunchLockScript(const CScript& script, std::vector<unsigned char>& header80)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;

    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return false;

    if (!script.GetOp(pc, opcode, data) || data != BTC_LAUNCH_LABEL) return false;

    if (!script.GetOp(pc, opcode, data) || data.size() != 1 || data[0] != BTC_LAUNCH_TAG) {
        return false;
    }

    if (!script.GetOp(pc, opcode, data) || data.size() != BTC_LAUNCH_HEADER_SIZE) return false;

    if (pc != script.end()) return false;

    header80 = std::move(data);
    return true;
}

bool CheckBtcLaunchLockHeader(std::span<const unsigned char> header80, uint32_t min_unix_time,
                              uint32_t nbits_floor, BlockValidationState& state)
{
    if (header80.size() != BTC_LAUNCH_HEADER_SIZE) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-header-len",
                             "Bitcoin launch-lock header is not 80 bytes");
    }

    const uint32_t nTime = ReadLE32(header80.data() + 68);
    const uint32_t nBits = ReadLE32(header80.data() + 72);

    if (nTime < min_unix_time) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-time",
                             strprintf("Bitcoin header nTime %u is before launch lock %u", nTime, min_unix_time));
    }

    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 header_target;
    header_target.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || header_target == 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-nbits",
                             "Bitcoin header nBits is not a valid compact target");
    }

    arith_uint256 floor_target;
    floor_target.SetCompact(nbits_floor, &fNegative, &fOverflow);
    if (fNegative || fOverflow || floor_target == 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-floor",
                             "Launch-lock nBits floor is not a valid compact target");
    }

    // Smaller decoded target = more work. Do not compare raw compact integers.
    if (header_target > floor_target) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-nbits",
                             "Bitcoin header target is easier than the launch-lock floor");
    }

    uint256 hash;
    CHash256().Write(header80).Finalize(hash);
    if (UintToArith256(hash) > header_target) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-pow",
                             "SHA256d(Bitcoin header) does not meet the header nBits target");
    }

    return true;
}

std::optional<size_t> GetBtcLaunchLockOutputIndex(const CTransaction& coinbase)
{
    std::optional<size_t> found;
    std::vector<unsigned char> header;
    for (size_t i = 0; i < coinbase.vout.size(); ++i) {
        if (ParseBtcLaunchLockScript(coinbase.vout[i].scriptPubKey, header)) {
            if (found) return std::nullopt;
            found = i;
        }
    }
    return found;
}

bool CheckBtcLaunchLock(const CTransaction& coinbase, const Consensus::BtcLaunchLock& lock,
                        BlockValidationState& state)
{
    if (!lock.enabled) return true;

    std::vector<unsigned char> header;
    int matches = 0;
    const CTxOut* lock_out = nullptr;
    for (const CTxOut& out : coinbase.vout) {
        std::vector<unsigned char> candidate;
        if (!ParseBtcLaunchLockScript(out.scriptPubKey, candidate)) continue;
        ++matches;
        header = std::move(candidate);
        lock_out = &out;
    }

    if (matches == 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-missing",
                             "height-1 coinbase is missing the Bitcoin launch-lock OP_RETURN");
    }
    if (matches > 1) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-duplicate",
                             "height-1 coinbase has more than one Bitcoin launch-lock OP_RETURN");
    }
    if (lock_out->nValue != 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-btc-lock-value",
                             "Bitcoin launch-lock OP_RETURN must have value 0");
    }

    return CheckBtcLaunchLockHeader(header, lock.min_unix_time, lock.nbits_floor, state);
}
