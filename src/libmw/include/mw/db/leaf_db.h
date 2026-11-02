
#ifndef BITCOIN_LIBMW_INCLUDE_MW_DB_LEAF_DB_H
#define BITCOIN_LIBMW_INCLUDE_MW_DB_LEAF_DB_H
#include <mw/mmr/leaf.h>
#include <mw/models/crypto/hash.h>
#include <mw/interfaces/db_interface.h>

// Forward Declarations
class Database;

class LeafDB
{
public:
    LeafDB(char prefix, mw::DBWrapper* pDBWrapper, mw::DBBatch* pBatch = nullptr);
    ~LeafDB();

    std::unique_ptr<mmr::Leaf> Get(const mmr::LeafIndex& idx) const;
    void Add(const std::vector<mmr::Leaf>& leaves);
    void Remove(const std::vector<mmr::LeafIndex>& indices);
    void RemoveAll();

private:
    char m_prefix;
    std::unique_ptr<Database> m_pDatabase;
};
#endif // BITCOIN_LIBMW_INCLUDE_MW_DB_LEAF_DB_H
