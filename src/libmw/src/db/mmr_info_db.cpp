#include <mw/db/mmr_info_db.h>
#include <mw/util/string_util.h>
#include <common/database.h>
#include <limits>

static const DBTable MMR_TABLE = { 'M' };
static const uint32_t LATEST_INDEX = std::numeric_limits<uint32_t>::max();

MMRInfoDB::MMRInfoDB(mw::DBWrapper* pDBWrapper, mw::DBBatch* pBatch)
    : m_pDatabase(std::make_unique<Database>(pDBWrapper, pBatch)) { }

MMRInfoDB::~MMRInfoDB() = default;

std::unique_ptr<MMRInfo> MMRInfoDB::GetByIndex(const uint32_t index) const
{
    auto pEntry = m_pDatabase->Get<MMRInfo>(MMR_TABLE, StringUtil::IntegralToString(index));
    return pEntry != nullptr ? std::make_unique<MMRInfo>(*pEntry->item) : nullptr;
}

std::unique_ptr<MMRInfo> MMRInfoDB::GetLatest() const
{
    return GetByIndex(LATEST_INDEX);
}

void MMRInfoDB::Save(const MMRInfo& info)
{
    std::vector<DBEntry<MMRInfo>> entries{
        DBEntry<MMRInfo>(StringUtil::IntegralToString(info.index), info),
        DBEntry<MMRInfo>(StringUtil::IntegralToString(LATEST_INDEX), info)
    };

    m_pDatabase->Put(MMR_TABLE, entries);
}
