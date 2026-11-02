// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/key_derivation.h>

#include <mw/crypto/blinds.h>
#include <mw/crypto/hasher.h>
#include <mw/crypto/secret_keys.h>
#include <serialize.h>

MW_NAMESPACE

static SecretKey SubaddressOffset(const SecretKey& master_scan_secret, const uint32_t index)
{
    return SecretKey::FromHash(Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(master_scan_secret)
        .hash());
}

static SecretKey OutKeyTweak(const SecretKey& shared_secret)
{
    return SecretKey::FromHash(Hashed(EHashTag::OUT_KEY, shared_secret));
}

SecretKey DeriveSubaddressSpendKey(const SecretKey& master_spend_secret, const SecretKey& master_scan_secret, const uint32_t index)
{
    return SecretKeys::From(master_spend_secret).Add(SubaddressOffset(master_scan_secret, index)).Total();
}

SecretKey RecoverMasterSpendSecret(const SecretKey& subaddress_spend_key, const SecretKey& master_scan_secret, const uint32_t index)
{
    return Blinds::From(subaddress_spend_key).Sub(SubaddressOffset(master_scan_secret, index)).ToKey();
}

StealthAddress DeriveSubaddress(const PublicKey& master_spend_pubkey, const SecretKey& master_scan_secret, const uint32_t index)
{
    const PublicKey Bi = master_spend_pubkey.Add(SubaddressOffset(master_scan_secret, index));
    return StealthAddress(Bi.Mul(master_scan_secret), Bi);
}

BigInt<16> DeriveOutputNonce(const SecretKey& sender_key)
{
    return BigInt<16>(Hashed(EHashTag::NONCE, sender_key).data());
}

SecretKey DeriveOutputSendKey(const StealthAddress& receiver_address, const uint64_t amount, const BigInt<16>& nonce)
{
    return SecretKey::FromHash(Hasher(EHashTag::SEND_KEY)
        .Append(receiver_address.A())
        .Append(receiver_address.B())
        .Append(amount)
        .Append(nonce)
        .hash());
}

SecretKey DeriveSharedSecret(const SecretKey& sender_key, const StealthAddress& receiver_address, const uint64_t amount)
{
    const SecretKey s = DeriveOutputSendKey(receiver_address, amount, DeriveOutputNonce(sender_key));
    return SecretKey::FromHash(Hashed(EHashTag::DERIVE, receiver_address.A().Mul(s)));
}

PublicKey DeriveOutputKeyExchangePubKey(const StealthAddress& receiver_address, const SecretKey& output_send_key)
{
    return receiver_address.B().Mul(output_send_key);
}

PublicKey DeriveOutputPubKey(const StealthAddress& receiver_address, const SecretKey& shared_secret)
{
    return receiver_address.B().Mul(OutKeyTweak(shared_secret));
}

SecretKey DeriveOutputSpendKey(const SecretKey& subaddress_spend_key, const SecretKey& shared_secret)
{
    return SecretKeys::From(subaddress_spend_key).Mul(OutKeyTweak(shared_secret)).Total();
}

BlindingFactor DeriveOutputRawBlind(const SecretKey& shared_secret)
{
    return BlindingFactor(SecretKey::FromHash(Hashed(EHashTag::BLIND, shared_secret)));
}

SecretKey DeriveRewindKey(const SecretKey& master_scan_secret)
{
    return SecretKey::FromHash(Hashed(EHashTag::REWIND_KEY, master_scan_secret));
}

SecretKey DeriveProofNonce(const SecretKey& rewind_key, const Commitment& commitment)
{
    return SecretKey::FromHash(Hasher(EHashTag::PROOF_NONCE)
        .Append(rewind_key)
        .Append(commitment)
        .hash());
}

SecretKey DeriveSenderSigningKey(const SecretKey& master_scan_secret, const uint64_t index)
{
    const SecretKey sender_root = SecretKey::FromHash(Hashed(EHashTag::SENDER_ROOT, master_scan_secret));
    return SecretKey::FromHash(Hasher(EHashTag::SENDER_ROOT)
        .Append(sender_root)
        .Append(index)
        .hash());
}

uint8_t RecoverViewTag(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret)
{
    return Hashed(EHashTag::TAG, key_exchange_pubkey.Mul(master_scan_secret))[0];
}

SecretKey RecoverSharedSecret(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret)
{
    return SecretKey::FromHash(Hashed(EHashTag::DERIVE, key_exchange_pubkey.Mul(master_scan_secret)));
}

PublicKey RecoverSubaddressSpendPubKey(const PublicKey& output_pubkey, const SecretKey& shared_secret)
{
    return output_pubkey.Div(OutKeyTweak(shared_secret));
}

StealthAddress RecoverSubaddress(const PublicKey& output_pubkey, const SecretKey& shared_secret, const SecretKey& master_scan_secret)
{
    const PublicKey Bi = RecoverSubaddressSpendPubKey(output_pubkey, shared_secret);
    return StealthAddress(Bi.Mul(master_scan_secret), Bi);
}

END_NAMESPACE
