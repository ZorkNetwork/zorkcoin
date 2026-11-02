// Copyright (c) 2011 - 2020 The Litecoin Core developers
// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_TRANSACT_H
#define BITCOIN_MWEB_MWEB_TRANSACT_H

#include <mweb/mweb_models.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/wallet/recipient.h>
#include <policy/fees/block_policy_estimator.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/wallet.h>

#include <optional>
#include <numeric>
#include <set>
#include <stdexcept>
#include <vector>

/**
 * When enabled, the wallet may build consensus-valid but uncommon MWEB send
 * shapes that are privacy-compromising relative to typical single-destination
 * MWEB-to-MWEB usage (they link L1 and/or multiple recipients on-chain):
 *   - multi-recipient txs that include stealth destinations
 *   - mixed L1 peg-in + existing MWEB inputs toward an MWEB destination
 *
 * These are NOT expected/intended everyday UX paths. Disable to restore
 * Litecoin-style rejects with clear errors (never silently rewrite the spend):
 *   cmake -DENABLE_MWEB_UNCOMMON_SENDS=OFF ...
 *   or compile with -DENABLE_MWEB_UNCOMMON_SENDS=0
 */
#ifndef ENABLE_MWEB_UNCOMMON_SENDS
#  define ENABLE_MWEB_UNCOMMON_SENDS 1
#endif

namespace MWEB {

enum class TxType {
    BTC_TO_BTC,
    MWEB_TO_MWEB,
    PEGIN,
    PEGOUT // NOTE: It's possible pegout transactions will also have pegins, but they will still be classified as PEGOUT
};

TxType GetTxType(const std::vector<wallet::CRecipient>& recipients, const std::set<wallet::CInputCoin>& input_coins);
bool ContainsPegIn(const TxType& mweb_type, const std::set<wallet::CInputCoin>& input_coins);
bool IsChangeOnMWEB(const wallet::CWallet& wallet, const TxType& mweb_type, const std::vector<wallet::CRecipient>& recipients, const CTxDestination& dest_change);
/**
 * The script that MWEB-side change is pegged out to when the change destination is transparent,
 * or an empty script when the change is an MWEB output.
 */
CScript GetPegoutChangeScript(const CTxDestination& dest_change);
uint64_t CalcMWEBWeight(const TxType& mweb_type, bool change_on_mweb, const std::vector<wallet::CRecipient>& recipients);
/** As above, with MWEB-side change pegged out to pegout_change_script when it is not empty. */
uint64_t CalcMWEBWeight(const TxType& mweb_type, bool change_on_mweb, const std::vector<wallet::CRecipient>& recipients, const CScript& pegout_change_script);
int64_t CalcPegOutBytes(const TxType& mweb_type, const std::vector<wallet::CRecipient>& recipients);
/** As above, including a change peg-out to pegout_change_script when it is not empty. */
int64_t CalcPegOutBytes(const TxType& mweb_type, const std::vector<wallet::CRecipient>& recipients, const CScript& pegout_change_script);

// MWEB hooks: in-process transaction state used while building MWEB spends
struct InProcessTx {
    CMutableTransaction tx{};
    std::vector<wallet::CRecipient> recipients;
    CAmount recipient_amount{0};

    std::unique_ptr<wallet::ReserveDestination> reserve_dest{nullptr};
    CTxDestination change_addr{};
    int change_position{-1};
    int bytes{0};

    wallet::CCoinControl coin_control;
    FastRandomContext mweb_rng;
    wallet::CoinSelectionParams coin_selection_params{mweb_rng};
    std::vector<wallet::COutputCoin> available_coins{};
    std::set<wallet::CInputCoin> selected_coins{};
    CAmount value_selected{0};
    bool bnb_used{false};

    CAmount fee_needed{0};
    CAmount total_fee{0};
    unsigned int subtract_fee_from_amount{0};

    // MWEB hooks
    uint64_t mweb_weight{0};
    TxType mweb_type{TxType::BTC_TO_BTC};
    bool change_on_mweb{false};
    //! When not empty, MWEB-side change is pegged out to this script instead of paid to an MWEB output.
    CScript pegout_change_script;
    //! Peg-out change below this amount is added to the kernel fee.
    CAmount min_pegout_change{0};
    CAmount mweb_fee{0}; // Portion of the fee paid by an MWEB kernel
    //! When false, tx.mweb_tx is left unsigned for a PSBT and inputs need no spend material.
    bool sign{true};
};

enum class CreateTxErrorKind {
    Generic,
    /** Recoverable: selection budget was short of the fee actually required. */
    InsufficientFeeBudget,
};

class CreateTxError : public std::runtime_error
{
public:
    explicit CreateTxError(const bilingual_str& error, CreateTxErrorKind kind = CreateTxErrorKind::Generic)
        : std::runtime_error(error.original), m_error(error), m_kind(kind) {}

    const bilingual_str& GetError() const { return m_error; }
    CreateTxErrorKind GetKind() const { return m_kind; }
    bool IsInsufficientFeeBudget() const { return m_kind == CreateTxErrorKind::InsufficientFeeBudget; }

private:
    bilingual_str m_error;
    CreateTxErrorKind m_kind;
};

class Transact
{
    const wallet::CWallet& m_wallet;

public:
    explicit Transact(const wallet::CWallet& wallet)
        : m_wallet(wallet) {}

    void AddMWEBTx(InProcessTx& new_tx);

private:
    CAmount CalcChangeAmount(
        const InProcessTx& new_tx,
        const std::optional<CAmount>& pegin_amount,
        const CAmount& btc_change
    );
    StealthAddress GetChangeAddress(const InProcessTx& new_tx);
};

} // namespace MWEB

#endif // BITCOIN_MWEB_MWEB_TRANSACT_H
