#include <mw/crypto/secret_keys.h>

#include <context.h>
#include <mw/common/lock.h>
#include <mw/exceptions/crypto_exception.h>
#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

static Locked<Context> SECKEY_CONTEXT(std::make_shared<Context>());

SecretKeys SecretKeys::From(const SecretKey& secret_key)
{
    if (secp256k1_ec_seckey_verify(SECKEY_CONTEXT.Read()->Get(), secret_key.data()) == 1) {
        return SecretKeys(secret_key);
    }

    // Keys at or above the group order are reduced modulo the order. Any 256-bit
    // value is below twice the order, so a single subtraction suffices.
    static constexpr std::array<uint8_t, SecretKey::SIZE> ORDER{{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    }};
    SecretKey reduced = secret_key;
    if (std::lexicographical_compare(reduced.data(), reduced.data() + SecretKey::SIZE, ORDER.begin(), ORDER.end())) {
        ThrowCrypto("secp256k1_ec_seckey_verify failed");
    }
    int borrow = 0;
    for (size_t i = SecretKey::SIZE; i-- > 0;) {
        const int diff = int{reduced[i]} - int{ORDER[i]} - borrow;
        borrow = diff < 0 ? 1 : 0;
        reduced[i] = static_cast<uint8_t>(diff + (borrow << 8));
    }
    if (secp256k1_ec_seckey_verify(SECKEY_CONTEXT.Read()->Get(), reduced.data()) != 1) {
        ThrowCrypto("secp256k1_ec_seckey_verify failed");
    }

    return SecretKeys(reduced);
}

SecretKeys& SecretKeys::Add(const SecretKey& secret_key)
{
    const int tweak_result = secp256k1_ec_seckey_tweak_add(
        SECKEY_CONTEXT.Read()->Get(),
        m_key.data(),
        secret_key.data()
    );
    if (tweak_result != 1) {
        ThrowCrypto("secp256k1_ec_seckey_tweak_add failed");
    }

    return *this;
}

SecretKeys& SecretKeys::Mul(const SecretKey& secret_key)
{
    const int tweak_result = secp256k1_ec_seckey_tweak_mul(
        SECKEY_CONTEXT.Read()->Get(),
        m_key.data(),
        secret_key.data()
    );
    if (tweak_result != 1) {
        ThrowCrypto("secp256k1_ec_seckey_tweak_mul failed");
    }

    return *this;
}
