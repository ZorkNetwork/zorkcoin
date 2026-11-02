
#ifndef BITCOIN_LIBMW_DEPS_CACHES_INCLUDE_CACHES_CACHE_H
#define BITCOIN_LIBMW_DEPS_CACHES_INCLUDE_CACHES_CACHE_H
#include <caches/internal/cache.hpp>
#include <caches/internal/fifo_cache_policy.hpp>
#include <caches/internal/lru_cache_policy.hpp>

template <typename Key, typename Value>
using FIFOCache = typename caches::fixed_sized_cache<Key, Value, caches::FIFOCachePolicy<Key>>;

template <typename Key, typename Value>
using LRUCache = typename caches::fixed_sized_cache<Key, Value, caches::LRUCachePolicy<Key>>;
#endif // BITCOIN_LIBMW_DEPS_CACHES_INCLUDE_CACHES_CACHE_H
