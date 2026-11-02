#include <mw/crypto/hasher.h>

#include <mw/common/traits.h>

mw::Hash Hashed(const std::vector<uint8_t>& serialized)
{
    Hasher hasher;
    hasher.write((char*)serialized.data(), serialized.size());
    return hasher.hash();
}

mw::Hash Hashed(const Traits::ISerializable& serializable)
{
    return Hashed(serializable.Serialized());
}
