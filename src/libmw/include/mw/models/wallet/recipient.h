
#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_RECIPIENT_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_RECIPIENT_H
#include <mw/common/macros.h>
#include <mw/models/wallet/stealth_address.h>
#include <consensus/amount.h>

MW_NAMESPACE

struct Recipient {
    CAmount amount;
    StealthAddress address;
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_WALLET_RECIPIENT_H
