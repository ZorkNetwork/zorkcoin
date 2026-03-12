# ASERT Test Failure Audit

**Build configuration:** `--with-incompatible-bdb` (per config.status; user reported `--with-compatible-bdb`)
**Git commit:** 2505ab8ea39807549a7cc280bc62cecc38a694a7
**ENABLE_ASERT_REGTEST:** Not defined (regtest has `fPowNoRetargeting = true`)

---

## 1. Unit Test Failures

### 1.1 miner_tests/CreateNewBlock_validity

| Field | Value |
|-------|-------|
| **Test** | `miner_tests/CreateNewBlock_validity` |
| **Type** | Unit (Boost) |
| **File** | `src/test/miner_tests.cpp` line 244 |
| **Symptom** | `ProcessNewBlock` fails with "proof of work failed" for blocks 1–110 |

**Root cause (ASERT-related):** Yes.

The test uses MAIN chain params and builds 110 blocks by:
1. Getting a block template from `CreateNewBlock` (nBits from `GetNextWorkRequired` → `GravityAsert`)
2. Overwriting nTime, coinbase, merkle root, and **nNonce** from `blockinfo[]`
3. Leaving nBits from the template

`blockinfo[]` holds 110 precomputed `(extranonce, nonce)` pairs from Bitcoin/Litecoin (different genesis and DAA). Those nonces were found for blocks with the old fixed/periodic nBits. With ASERT, nBits changes every block, so the hardcoded nonces no longer satisfy the targets. PoW validation rejects each block.

**Proposed fix (test-only):** Replace use of `blockinfo[]` with dynamic mining: solve for a valid nonce via `CheckProofOfWork` in a loop, as in `validation_block_tests::FinalizeBlock` and `setup_common.cpp`. Keep the same test logic (110 blocks, coinbase handling, etc.) but compute nonces per block so they match the ASERT nBits.

---

### 1.2 validation_block_tests/processnewblock_signals_ordering

| Field | Value |
|-------|-------|
| **Test** | `validation_block_tests/processnewblock_signals_ordering` |
| **Type** | Unit (Boost) |
| **File** | `src/test/validation_block_tests.cpp` lines 167, 192, 199 |
| **Symptom** | `ProcessNewBlockHeaders` fails; `processed` assertion fails; `ProcessNewBlock` fails |

**Root cause (ASERT-related):** Yes.

`validation_block_tests` uses `RegTestingSetup` (regtest) and `Block(prev_hash, height)` which:
1. Calls `CreateNewBlock` to get a template
2. Uses the template’s nBits
3. Builds a chain/tree via `BuildChain` without connecting blocks

`CreateNewBlock` uses the current chain tip (genesis at start) to compute nBits. So the template’s nBits is for the block after genesis. That is correct for block 1. For block 2 (child of block 1), the template is still “block after genesis” because the chain tip is still genesis, so the template’s nBits is wrong for block 2. Under ASERT, nBits changes per block; under `fPowNoRetargeting`, all blocks share the same nBits, so the bug was latent.

**Proposed fix (test-only):** In `Block()`, compute nBits for the block being built using the actual parent, not the chain tip. Two options:

- **Option A:** Have `Block()` take a `CBlockIndex*` (or equivalent) for the parent and call `GetNextWorkRequired(parent, block_header, Params())` before finalization. `BuildChain` would need to track parent indices; this is invasive because blocks are built without being connected first.
- **Option B:** Implement a small `GetNextWorkRequired`-compatible helper that, given `prev_hash`, `height`, and `block_time`, returns the expected nBits. This may require access to a synthetic parent index or duplicating ASERT logic for tests.

- **Option C (preferred):** Change `BuildChain` so blocks are connected to the chain as they are built. Then the chain tip matches the parent of the next block, and `CreateNewBlock` returns the correct nBits. This requires adjusting `BuildChain` to connect each block before building its children.

---

### 1.3 miner_tests – downstream failures (bad-txns-inputs-missingorspent)

| Field | Value |
|-------|-------|
| **Test** | `miner_tests/CreateNewBlock_validity` (continuation) |
| **Symptom** | After the 110-block loop fails, `CreateNewBlock` later throws `bad-txns-inputs-missingorspent` |

**Root cause:** Cascading. The 110-block loop fails because of PoW, so the chain never advances. The later parts of the test assume 110 blocks were accepted (e.g. mature coinbase outputs). When they are not, mempool and chain state are wrong and `CreateNewBlock` fails with `bad-txns-inputs-missingorspent`.

**Proposed fix:** Resolve the PoW/nBits issue (fix 1.1). Once blocks 1–110 are accepted, these later failures should disappear.

---

## 2. Functional Test Failures

### 2.1 create_cache.py (blocks all multi-test runs)

| Field | Value |
|-------|-------|
| **Test** | `create_cache.py` |
| **Type** | Functional (prerequisite for multi-test runs) |
| **Symptom** | `generatetoaddress` RPC exceeds 30s; node may not stop cleanly |

**Root cause (ASERT-related):** Possibly, but not certain.

`create_cache` mines 199 blocks to build a chain cache. If `generatetoaddress` exceeds 30s, either:
- Mining is too slow (e.g. regtest PoW harder than expected under ASERT), or
- RPC or node is blocked (BDB, env, prior run, etc.)

With regtest and `fPowNoRetargeting = true`, difficulty should remain low. If `GetNextWorkRequired` effectively always uses ASERT and regtest params, the first blocks should still be easy to mine. Without repro, the timeout could be ASERT-related, BDB-related, or environment-related.

**Proposed fixes:**
1. **Test-only:** Increase the `generatetoaddress` RPC timeout for `create_cache` (or for cache-related calls) so cache creation can complete when mining is slower.
2. **Investigate:** Confirm regtest genesis and ASERT params produce low difficulty for early blocks. If not, adjust params or add a short-circuit in `GetNextWorkRequired` for regtest when `fPowNoRetargeting` is true (return parent’s nBits). That would restore constant difficulty on regtest and match many existing tests.

---

## 3. Summary Table

| Test | Type | ASERT-Related | Primary Fix |
|------|------|---------------|-------------|
| miner_tests/CreateNewBlock_validity | Unit | Yes | Replace blockinfo with dynamic nonce solving |
| validation_block_tests/processnewblock_signals_ordering | Unit | Yes | Compute nBits per parent in Block() / BuildChain |
| create_cache.py | Functional | Maybe | Increase RPC timeout; optionally restore fPowNoRetargeting behavior for regtest |

---

## 4. Overarching Fix Strategy

**No production consensus changes unless necessary.** Prefer test-only changes.

### Phase 1: miner_tests

- **Change:** Replace `blockinfo[]` with dynamic nonce solving in `CreateNewBlock_validity`.
- **Rationale:** Nonces are test fixtures; they must match the current DAA. Mining in the test keeps the same coverage without touching consensus.

### Phase 2: validation_block_tests

- **Change:** Ensure `Block()`/`BuildChain` uses nBits computed from the real parent for each block (Option C: connect blocks as built, or Option B: helper that computes expected nBits from parent).
- **Rationale:** Tests must build blocks with nBits valid under ASERT; the template from `CreateNewBlock` only applies when the chain tip is the parent.

### Phase 3: create_cache

- **Change 1:** Increase RPC timeout for `generatetoaddress` in the cache setup.
- **Change 2 (optional):** If regtest is supposed to have constant difficulty, reintroduce a path in `GetNextWorkRequired` that returns `pindexLast->nBits` when `fPowNoRetargeting` is true for regtest. This affects consensus but only for regtest and matches the intent of `fPowNoRetargeting`.
- **Rationale:** Functional tests must be able to create the cache; a timeout or regtest difficulty change may be needed.

### Phase 4: feature_asert_regtest.py

- **Note:** This test requires `--enable-asert-regtest` and is skipped in a normal build. No change for the current build.

### Effect of Option B (fPowNoRetargeting) on the above

- **miner_tests:** Uses MAIN params (`fPowNoRetargeting = false`). Option B has no effect; dynamic mining (Phase 1) is still required.
- **validation_block_tests:** Uses REGTEST (`fPowNoRetargeting = true`). Option B restores constant nBits, so the template’s nBits matches every block. Phase 2 may no longer be needed.
- **create_cache:** Uses REGTEST. Option B restores easy, constant-difficulty mining; Phase 3 timeout increase may no longer be needed.

---

## 5. Production Code Options

**Option A (recommended):** Fix tests only. No production changes.

**Option B (if regtest difficulty is the issue):** Add a branch in `GetNextWorkRequired` (in `src/pow.cpp`, before the min-difficulty block):

```cpp
// Regtest: constant difficulty when fPowNoRetargeting (matches many functional tests)
if (params.fPowNoRetargeting)
    return pindexLast->nBits;
```

This restores constant difficulty for regtest when `fPowNoRetargeting` is true (current non-ASERT-regtest build). Mainnet/testnet are unchanged (`fPowNoRetargeting` is false). This is a minimal production change that honors the existing chainparams flag and fixes create_cache and validation_block_tests without further test changes.
