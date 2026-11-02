
#ifndef BITCOIN_LIBMW_SRC_DB_COMMON_DB_TABLE_H
#define BITCOIN_LIBMW_SRC_DB_COMMON_DB_TABLE_H
#include <db_entry.h>

#include <memory>
#include <string>

class DBTable
{
public:
    DBTable(const char prefix)
        : m_prefix(prefix) { }

    std::string BuildKey(const std::string& itemKey) const noexcept { return m_prefix + itemKey; }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of<Traits::ISerializable, T>::value>>
    std::string BuildKey(const DBEntry<T>& item) const noexcept { return BuildKey(item.key); }

    char GetPrefix() const noexcept { return m_prefix; }

private:
    char m_prefix;
};
#endif // BITCOIN_LIBMW_SRC_DB_COMMON_DB_TABLE_H
