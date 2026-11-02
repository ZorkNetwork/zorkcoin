// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETMODELTRANSACTION_H
#define BITCOIN_QT_WALLETMODELTRANSACTION_H

#include <primitives/transaction.h>
#include <qt/sendcoinsrecipient.h>

#include <consensus/amount.h>

#include <optional>
#include <vector>

#include <QObject>

class SendCoinsRecipient;

namespace interfaces {
class Node;
}

/** Data model for a walletmodel transaction. */
class WalletModelTransaction
{
public:
    explicit WalletModelTransaction(const QList<SendCoinsRecipient> &recipients);

    QList<SendCoinsRecipient> getRecipients() const;

    CTransactionRef& getWtx();
    void setWtx(const CTransactionRef&);
    //! MWEB: the MWEB part the wallet funded, which getWtx() lacks when the wallet cannot sign. Only its
    //! unsigned fields are kept.
    void setMWEBDraft(const mw::MutableTx& mweb_tx);
    //! MWEB: getWtx() with its MWEB part as funded, before signing, for building a PSBT.
    CMutableTransaction getUnsignedTx() const;

    unsigned int getTransactionSize();

    void setTransactionFee(const CAmount& newFee);
    CAmount getTransactionFee() const;

    CAmount getTotalTransactionAmount() const;

    void reassignAmounts(int nChangePosRet); // needed for the subtract-fee-from-amount feature
    //! MWEB: reassignAmounts for a transaction with an MWEB part, matching each recipient to its output.
    void reassignMWEBAmounts(const mw::MutableTx& mweb_tx, std::optional<size_t> mweb_change_index, int nChangePosRet);

private:
    QList<SendCoinsRecipient> recipients;
    CTransactionRef wtx;
    mw::MutableTx mweb_draft; // MWEB
    std::vector<mw::Hash> signed_pegin_kernel_ids; // MWEB
    CAmount fee{0};
};

#endif // BITCOIN_QT_WALLETMODELTRANSACTION_H
