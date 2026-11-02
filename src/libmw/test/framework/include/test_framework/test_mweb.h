
#ifndef BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_TEST_MWEB_H
#define BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_TEST_MWEB_H
#include <mw/models/crypto/big_integer.h>

#include <boost/test/unit_test.hpp>
#include <dbwrapper.h>
#include <mweb/mweb_db.h>
#include <random.h>
#include <span>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

template<size_t NUM_BYTES>
std::vector<uint8_t> RandomBytes()
{
    std::vector<uint8_t> bytes(NUM_BYTES);
    size_t index = 0;
    while (index < NUM_BYTES) {
        size_t num_bytes = std::min(NUM_BYTES - index, (size_t)32);
        GetStrongRandBytes(std::span{bytes.data() + index, num_bytes});
        index += num_bytes;
    }
    return bytes;
}

template<size_t NUM_BYTES>
BigInt<NUM_BYTES> RandomBigInt()
{
    return BigInt<NUM_BYTES>(RandomBytes<NUM_BYTES>());
}

struct MWEBTestingSetup : public BasicTestingSetup {
    explicit MWEBTestingSetup()
        : BasicTestingSetup(ChainType::MAIN)
    {
        m_db = std::make_unique<CDBWrapper>(DBParams{
            .path = m_path_root / "db",
            .cache_bytes = 1 << 15,
        });
        m_mweb_db = std::make_shared<MWEB::DBWrapper>(m_db.get());
    }

    virtual ~MWEBTestingSetup() = default;

    mw::DBWrapper::Ptr GetDB() { return m_mweb_db; }
    fs::path GetDataDir() const { return m_path_root; }

private:
    std::unique_ptr<CDBWrapper> m_db;
    std::shared_ptr<mw::DBWrapper> m_mweb_db;
};
#endif // BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_TEST_MWEB_H
