// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H

#include <wallet/scriptpubkeyman.h>

#include <memory>
#include <util/result.h>

struct bilingual_str;

namespace wallet {
class ExternalSignerScriptPubKeyMan : public DescriptorScriptPubKeyMan
{
private:
    using DescriptorScriptPubKeyMan::DescriptorScriptPubKeyMan;

public:
    static std::unique_ptr<ExternalSignerScriptPubKeyMan> LoadFromStorage(WalletStorage& storage, const uint256& id, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys);
    //! @param[in] provider  the keys parsed with the descriptor; an MWEB account takes its scan secret from them
    static std::unique_ptr<ExternalSignerScriptPubKeyMan> CreateNew(WalletStorage& storage, WalletBatch& batch, int64_t keypool_size, std::unique_ptr<Descriptor> desc, const FlatSigningProvider& provider);

  static util::Result<ExternalSigner> GetExternalSigner();

  /**
  * Display address on the device and verify that the returned value matches.
  * @returns nothing or an error message
  */
 util::Result<void> DisplayAddress(const CTxDestination& dest, const ExternalSigner& signer) const;

  //! Display an MWEB address owned by spkm on the device and verify that the returned value matches.
  static util::Result<void> DisplayMWEBAddress(const DescriptorScriptPubKeyMan& spkm, const StealthAddress& address, const ExternalSigner& signer); // MWEB

  //! Sign a PSBT with MWEB components on the signer and merge the result strictly, so the signer
  //! cannot change MWEB data. Inputs whose address descriptor doesn't match the signer are sent
  //! without it. The PSBT is unchanged on failure.
  static std::optional<common::PSBTError> SignMWEBPSBT(ExternalSigner& signer, PartiallySignedTransaction& psbt); // MWEB

  std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, const common::PSBTFillOptions& options, int* n_signed = nullptr) const override;
};
} // namespace wallet
#endif // BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
