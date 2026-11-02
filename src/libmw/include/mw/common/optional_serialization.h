
#ifndef BITCOIN_LIBMW_INCLUDE_MW_COMMON_OPTIONAL_SERIALIZATION_H
#define BITCOIN_LIBMW_INCLUDE_MW_COMMON_OPTIONAL_SERIALIZATION_H
#include <cstdint>

template <typename I>
class OptionalPtr
{
public:
    explicit OptionalPtr(I& obj) : m_obj(obj) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t is_set = m_obj != nullptr ? 1 : 0;
        ::Serialize(s, is_set);
        if (is_set == 1) {
            ::Serialize(s, m_obj);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t is_set = 0;
        ::Unserialize(s, is_set);
        if (is_set == 1) {
            ::Unserialize(s, m_obj);
        } else {
            m_obj.reset();
        }
    }

private:
    I& m_obj;
};

template <typename I>
OptionalPtr<I> WrapOptionalPtr(I& obj)
{
    return OptionalPtr<I>(obj);
}
#endif // BITCOIN_LIBMW_INCLUDE_MW_COMMON_OPTIONAL_SERIALIZATION_H
