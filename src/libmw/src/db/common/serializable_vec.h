
#ifndef BITCOIN_LIBMW_SRC_DB_COMMON_SERIALIZABLE_VEC_H
#define BITCOIN_LIBMW_SRC_DB_COMMON_SERIALIZABLE_VEC_H
#include <mw/common/traits.h>

class SerializableVec : public Traits::ISerializable
{
public:
    SerializableVec() = default;
    SerializableVec(std::vector<uint8_t> bytes) : m_bytes(std::move(bytes)) {}

    const std::vector<uint8_t>& Get() const { return m_bytes; }

    IMPL_SERIALIZABLE(SerializableVec, obj)
    {
        READWRITE(obj.m_bytes);
    }

private:
    std::vector<uint8_t> m_bytes;
};
#endif // BITCOIN_LIBMW_SRC_DB_COMMON_SERIALIZABLE_VEC_H
