
#ifndef BITCOIN_LIBMW_INCLUDE_MW_CONSENSUS_PARAMS_H
#define BITCOIN_LIBMW_INCLUDE_MW_CONSENSUS_PARAMS_H
#include <mw/common/macros.h>
#include <cstddef>
#include <cstdint>

MW_NAMESPACE

/// <summary>
/// Consensus parameters
/// Any change to these will cause a hardfork!
/// </summary>
static constexpr size_t BYTES_PER_WEIGHT = 42; // For any 'extra' data added to inputs, outputs, or kernels

// Default mainnet grandfather: kernel lock heights are enforced only when
// block height > this value (Litecoin historical). Per-network overrides live
// in Consensus::Params::mweb_kernel_lock_height_grandfather — never mutate a
// process global from CreateChainParams.
static constexpr int32_t KERNEL_LOCK_HEIGHT_GRANDFATHER_HEIGHT = 3'110'000;

static constexpr size_t BASE_KERNEL_WEIGHT = 2;
static constexpr size_t STEALTH_EXCESS_WEIGHT = 1;
static constexpr size_t KERNEL_WITH_STEALTH_WEIGHT = BASE_KERNEL_WEIGHT + STEALTH_EXCESS_WEIGHT;

static constexpr size_t BASE_OUTPUT_WEIGHT = 17;
static constexpr size_t STANDARD_OUTPUT_FIELDS_WEIGHT = 1;
static constexpr size_t STANDARD_OUTPUT_WEIGHT = BASE_OUTPUT_WEIGHT + STANDARD_OUTPUT_FIELDS_WEIGHT;

static constexpr size_t MAX_NUM_INPUTS = 50'000;
static constexpr size_t INPUT_BYTES = 196;

static constexpr std::size_t MAX_BLOCK_WEIGHT = 200'000; // Nodes won't accept blocks over this weight

/**
 * Theoretical pessimistic MWEB extension-body size (header + CompactSizes +
 * max inputs + ~60 B/weight for non-input components). Not an independent
 * consensus limit: wire-serialized L1+MWEB blocks are capped by
 * MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB (Litecoin-compatible full envelope:
 * MAX_BLOCK_SERIALIZED_SIZE + MAX_BLOCK_BYTES). Mining/assembly uses the
 * separate BIP324 cap (16,777,214).
 */
static constexpr size_t MAX_BLOCK_BYTES = 180 + (3 * 5) +                  // 180 bytes per header and 5 bytes each for input, output, and kernel vec size
                                         (MAX_NUM_INPUTS * INPUT_BYTES) + // 50k inputs at 196 bytes each (ignoring extradata)
                                         (MAX_BLOCK_WEIGHT * 60);     // Ignoring inputs, no tx component is ever more than 60 bytes per unit of weight

END_NAMESPACE
#endif // BITCOIN_LIBMW_INCLUDE_MW_CONSENSUS_PARAMS_H
