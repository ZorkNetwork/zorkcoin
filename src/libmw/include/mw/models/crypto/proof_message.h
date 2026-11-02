
// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_PROOF_MESSAGE_H
#define BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_PROOF_MESSAGE_H
#include <mw/models/crypto/big_integer.h>

class ProofMessage
{
public:
    ProofMessage() = default;
    ProofMessage(BigInt<20> bytes) : m_bytes(std::move(bytes)) { }

    const BigInt<20>& GetBytes() const { return m_bytes; }
    const uint8_t* data() const { return m_bytes.data(); }

private:
    BigInt<20> m_bytes;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_MODELS_CRYPTO_PROOF_MESSAGE_H
