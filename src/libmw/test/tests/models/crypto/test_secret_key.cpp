// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/crypto/secret_key.h>
#include <support/lockedpool.h>

#include <test_framework/test_mweb.h>

BOOST_FIXTURE_TEST_SUITE(TestSecretKey, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(SecretKeyLockedMemory)
{
    const size_t used_before = LockedPoolManager::Instance().stats().used;
    {
        const SecretKey key = SecretKey::Random();
        BOOST_CHECK_GE(LockedPoolManager::Instance().stats().used, used_before + SecretKey::SIZE);

        const SecretKey copy = key; // NOLINT(performance-unnecessary-copy-initialization)
        BOOST_CHECK(copy == key);
        BOOST_CHECK(SecretKey(key.GetBigInt()) == key);
        BOOST_CHECK(SecretKey(key.vec()) == key);
        BOOST_CHECK(SecretKey(key.data()) == key);
        BOOST_CHECK(SecretKey::Deserialize(key.Serialized()) == key);
    }
    BOOST_CHECK_EQUAL(LockedPoolManager::Instance().stats().used, used_before);
}

BOOST_AUTO_TEST_CASE(MovedFromBigIntDestroys)
{
    const SecretKey key = SecretKey::Random();
    BigInt<SecretKey::SIZE> source = key.GetBigInt();
    const BigInt<SecretKey::SIZE> target = std::move(source);
    BOOST_CHECK(SecretKey(target) == key);
}

BOOST_AUTO_TEST_SUITE_END()
