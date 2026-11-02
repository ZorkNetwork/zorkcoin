# Copyright (c) 2026 ADGL Enterprises, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

set(LIBMW_SRC_DIR "${CMAKE_SOURCE_DIR}/src")

function(add_libmw)
  set(libmw_sources
    ${LIBMW_SRC_DIR}/libmw/src/common/logger.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/bulletproofs.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/conversion_util.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/hasher.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/key_derivation.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/mu_sig.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/pedersen.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/public_keys.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/schnorr.cpp
    ${LIBMW_SRC_DIR}/libmw/src/crypto/secret_keys.cpp
    ${LIBMW_SRC_DIR}/libmw/src/db/coin_db.cpp
    ${LIBMW_SRC_DIR}/libmw/src/db/leaf_db.cpp
    ${LIBMW_SRC_DIR}/libmw/src/db/mmr_info_db.cpp
    ${LIBMW_SRC_DIR}/libmw/src/file/file.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/i_leaf_set.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/immr.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/index.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/leaf_set.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/leaf_set_cache.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/mem_mmr.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/mmr_util.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/pmmr_cache.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/pmmr.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/prune_list.cpp
    ${LIBMW_SRC_DIR}/libmw/src/mmr/segment.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/block/block.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/crypto/commitment.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/crypto/public_key.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/tx/input.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/tx/kernel.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/tx/output.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/tx/transaction.cpp
    ${LIBMW_SRC_DIR}/libmw/src/models/tx/tx_body.cpp
    ${LIBMW_SRC_DIR}/libmw/src/node/block_builder.cpp
    ${LIBMW_SRC_DIR}/libmw/src/node/block_validator.cpp
    ${LIBMW_SRC_DIR}/libmw/src/node/coins_view_cache.cpp
    ${LIBMW_SRC_DIR}/libmw/src/node/coins_view_db.cpp
    ${LIBMW_SRC_DIR}/libmw/src/node/coins_view_memory.cpp
    ${LIBMW_SRC_DIR}/libmw/src/node/coins_view_materialize.cpp
    ${LIBMW_SRC_DIR}/libmw/src/wallet/tx_builder.cpp
  )

  add_library(libmw STATIC EXCLUDE_FROM_ALL ${libmw_sources})
  target_link_libraries(libmw
    PUBLIC
      blake3
    PRIVATE
      core_interface
      secp256k1
      bitcoin_util
      bitcoin_crypto
      Boost::headers
  )
  target_include_directories(libmw
    PUBLIC
      ${LIBMW_SRC_DIR}/libmw/include
    PRIVATE
      ${LIBMW_SRC_DIR}/libmw/src/crypto
      ${LIBMW_SRC_DIR}/libmw/src/db
      ${LIBMW_SRC_DIR}/libmw/src/db/common
      ${LIBMW_SRC_DIR}/libmw/src/node
  )
  target_include_directories(libmw SYSTEM
    PUBLIC
      ${LIBMW_SRC_DIR}/libmw/deps/caches/include
      ${LIBMW_SRC_DIR}/libmw/deps/caches/include/caches
      ${LIBMW_SRC_DIR}/libmw/deps/mio/include
      ${LIBMW_SRC_DIR}/secp256k1/include
  )
  # MWEB: Expose libmw headers to consensus primitives without circular linking.
  target_link_libraries(core_interface INTERFACE Boost::headers)
  target_include_directories(core_interface INTERFACE
    ${LIBMW_SRC_DIR}/libmw/include
  )
  target_include_directories(core_interface SYSTEM INTERFACE
    ${LIBMW_SRC_DIR}/libmw/deps/caches/include
    ${LIBMW_SRC_DIR}/libmw/deps/mio/include
  )
endfunction()

function(add_mweb_consensus)
  add_library(mweb_consensus STATIC EXCLUDE_FROM_ALL
    ${LIBMW_SRC_DIR}/mweb/mweb_node.cpp
    ${LIBMW_SRC_DIR}/mweb/mweb_policy.cpp
  )
  target_link_libraries(mweb_consensus
    PRIVATE
      core_interface
      libmw
      bitcoin_consensus
  )
endfunction()

function(add_libmw_tests target)
  set(libmw_test_sources
    ${LIBMW_SRC_DIR}/libmw/test/framework/src/tx_builder.cpp
    ${LIBMW_SRC_DIR}/libmw/test/framework/src/models/tx.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_mweb_block_validator.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_mweb_coins_view.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_mweb_secret_keys.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/consensus/test_mweb_incremental_sums.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_mweb_staged_spends.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_mweb_prune_list.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_mweb_compaction_mask.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/consensus/test_aggregation.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/consensus/test_kernel_sum_validator.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/consensus/test_stealth_sum_validator.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/consensus/test_weight.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_add_commitments.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_agg_sig.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_key_derivation.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_keys.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_mweb_public_keys.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/crypto/test_mweb_commitment.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_range_proofs.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_batch_verify_max_outputs.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/crypto/test_blake3.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/db/test_leaf_db.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_index.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_leaf_index.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_leaf_set.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_leaf_set_cache.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_mmr.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_mmr_util.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_prune_list.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/mmr/test_segment.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/block/test_block.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/block/test_header.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/crypto/test_big_integer.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/crypto/test_secret_key.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_input.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_kernel.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_mutable_tx.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_output.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_peg_in_coin.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_peg_out_coin.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_transaction.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_tx_body.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/models/tx/test_utxo.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_block_builder.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_block_validator.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_coins_view.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_mine_chain.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/node/test_reorg.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/wallet/test_keychain.cpp
    ${LIBMW_SRC_DIR}/libmw/test/tests/wallet/test_sign.cpp
  )
  target_sources(${target} PRIVATE ${libmw_test_sources})
  target_include_directories(${target}
    PRIVATE
      ${LIBMW_SRC_DIR}/libmw/test/framework/include
  )
endfunction()
