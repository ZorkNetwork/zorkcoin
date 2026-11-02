// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_KEY_DERIVATION_H
#define BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_KEY_DERIVATION_H

#include <mw/common/macros.h>
#include <mw/models/crypto/big_integer.h>
#include <mw/models/crypto/blinding_factor.h>
#include <mw/models/crypto/commitment.h>
#include <mw/models/crypto/public_key.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/models/wallet/stealth_address.h>

#include <cstdint>

MW_NAMESPACE

// Key derivation for MWEB stealth outputs (see doc/mweb/stealth-addresses.md).
//
//   a, A   - master scan secret and its pubkey A = a*G
//   b, B   - master spend secret and its pubkey B = b*G
//   bi, Bi - subaddress spend key: bi = b + H(T_address, i, a), Bi = bi*G
//   Ai     - subaddress scan pubkey: Ai = a*Bi
//   ks, Ks - sender signing key and its pubkey Ks = ks*G (published in the output)
//   n      - output nonce n = Hash128(T_nonce, ks)
//   v      - output amount
//   s      - one-time send key s = H(T_send, Ai, Bi, v, n)
//   e      - shared secret e = H(T_derive, s*Ai) = H(T_derive, a*Ke)
//   Ke     - key-exchange pubkey Ke = s*Bi (published in the output)
//   Ko     - one-time output pubkey Ko = H(T_outkey, e)*Bi (published in the output)
//
// Derive* functions compute a value from its preimage. Recover* functions
// reconstruct a value from a published output and require the scan secret.

SecretKey DeriveSubaddressSpendKey(const SecretKey& master_spend_secret, const SecretKey& master_scan_secret, uint32_t index);
//! The master spend secret b = bi - H(T_address, i, a), the inverse of DeriveSubaddressSpendKey.
SecretKey RecoverMasterSpendSecret(const SecretKey& subaddress_spend_key, const SecretKey& master_scan_secret, uint32_t index);
StealthAddress DeriveSubaddress(const PublicKey& master_spend_pubkey, const SecretKey& master_scan_secret, uint32_t index);
BigInt<16> DeriveOutputNonce(const SecretKey& sender_key);
SecretKey DeriveOutputSendKey(const StealthAddress& receiver_address, uint64_t amount, const BigInt<16>& nonce);
SecretKey DeriveSharedSecret(const SecretKey& sender_key, const StealthAddress& receiver_address, uint64_t amount);
PublicKey DeriveOutputKeyExchangePubKey(const StealthAddress& receiver_address, const SecretKey& output_send_key);
PublicKey DeriveOutputPubKey(const StealthAddress& receiver_address, const SecretKey& shared_secret);
SecretKey DeriveOutputSpendKey(const SecretKey& subaddress_spend_key, const SecretKey& shared_secret);
BlindingFactor DeriveOutputRawBlind(const SecretKey& shared_secret);

//! Bulletproof rewind key H(T_rewind, a).
SecretKey DeriveRewindKey(const SecretKey& master_scan_secret);

//! Bulletproof nonce H(T_proof_nonce, rewind_key, commitment) for an output commitment.
SecretKey DeriveProofNonce(const SecretKey& rewind_key, const Commitment& commitment);

//! Sender signing key ks at the given index: H(T_sender, H(T_sender, a), index).
SecretKey DeriveSenderSigningKey(const SecretKey& master_scan_secret, uint64_t index);

uint8_t RecoverViewTag(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret);
SecretKey RecoverSharedSecret(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret);
PublicKey RecoverSubaddressSpendPubKey(const PublicKey& output_pubkey, const SecretKey& shared_secret);
StealthAddress RecoverSubaddress(const PublicKey& output_pubkey, const SecretKey& shared_secret, const SecretKey& master_scan_secret);

END_NAMESPACE

#endif // BITCOIN_LIBMW_INCLUDE_MW_CRYPTO_KEY_DERIVATION_H
