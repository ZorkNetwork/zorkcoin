# ASERTi3-12h Integration Review – Zorkcoin

## Executive Summary

The ASERT (Absolutely Scheduled Exponentially Rising Targets) difficulty adjustment algorithm has been integrated into Zorkcoin as ASERTi3-12h, using genesis as the anchor block. This document summarizes the code review, identifies issues, and provides recommendations.

---

## 1. Code Review

### 1.1 Formula and Parameters

**Correct:**
- **Exponent formula**: `exponent = ((nTimeDiff - params.nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / params.nASERTHalfLife` matches the ASERT spec.
- **Units**: Zorkcoin uses millisecond timestamps; `nPowTargetSpacing` (150000 ms) and `nASERTHalfLife` (43200000 ms) are consistent with `doc/timestamp-semantics.md`.
- **Cubic approximation**: Constants `195766423245049`, `971821376`, `5127` match the reference implementation (BCH/Lotusia).
- **16.16 fixed-point**: Radix 65536 and shift logic are correct.
- **Anchor selection**: Genesis at height 0 is used as anchor; for genesis there is no parent, so using genesis time as the reference is correct per BCH spec (“anchor block itself iff anchor is genesis”).

### 1.2 Time Reference

**Current behavior:** For genesis anchor, `nTimeAnchor = pindexAnchor->GetBlockTime()` is correct because genesis has no parent.

**Future-proofing:** If a non-genesis anchor is ever used (e.g. for a future fork), the spec requires the **parent** of the anchor block’s timestamp. BCH uses:

```cpp
nPrevBlockTime = pindexAnchorBlock->pprev
    ? pindexAnchorBlock->pprev->GetBlockTime()
    : pindexAnchorBlock->GetBlockTime();
```

For genesis-only anchor, the current implementation is correct.

### 1.3 Issues Found

#### 1.3.1 Overflow Handling (Medium)

**Location:** `pow.cpp` lines 79–95

**Current:** Shifts are clamped to ±256 before applying.

**BCH approach:** Detects overflow when left-shifting and sets target to powLimit:

```cpp
arith_uint256 nextTargetShifted = nextTarget << shifts;
if ((nextTargetShifted >> shifts) != nextTarget) {
    nextTarget = powLimit;
} else {
    nextTarget = nextTargetShifted;
}
```

**Recommendation:** Add the overflow check and only clamp if it would still overflow (e.g. via `arith_uint256` behavior). This handles pathological timestamps more accurately and aligns with the reference implementation.

#### 1.3.2 Testnet Min-Difficulty Rule Units (Low)

**Location:** `pow.cpp` lines 122–134

The logic converts `nPowTargetSpacing` and timestamps between ms and seconds based on heuristic checks. Zorkcoin consistently uses milliseconds. The condition `nTargetSpacing > 30000` assumes values > 30000 are in ms, and `nTimeLast > 1000000000000` detects ms timestamps. This is brittle; consider documenting units or centralizing conversion.

#### 1.3.3 Regtest and ASERT Testing

**Location:** `chainparams.cpp` line 314

`GetNextWorkRequired` always runs ASERT (no `fPowNoRetargeting` check in the current code path). Regtest uses `fPowNoRetargeting = true` by default, but that only affects `MineBlocksOnDemand()` (e.g. block version override), not the difficulty calculation.

**ASERT regtest build:** Build with `--enable-asert-regtest` sets `fPowNoRetargeting = false` for regtest. The `feature_asert_regtest` functional test requires this build and skips with a clear message when not built that way. Run with: `test_runner.py --asert-regtest`.

#### 1.3.4 Integer Division Semantics (Very Low)

**Location:** `pow.cpp` line 64

The spec uses floor division for the exponent; C++ integer division truncates toward zero for negative operands. For typical inputs the difference is negligible. BCH uses the same C++ pattern. No change required unless strict spec compliance is needed.

### 1.4 Positive Aspects

- Use of `arith_uint256` and no floating-point; deterministic.
- Min target clamping prevents zero targets.
- Min-difficulty blocks for testnet are handled.
- `serfloat.cpp` and `ConvertBitsToDouble` are correctly used for display only.
- `util/serfloat.cpp` is included in the build (`Makefile.am`).

---

## 2. Recommendations

### 2.1 Implementation Fixes

1. **Overflow handling**  
   Replace shift clamping with overflow detection as in BCH. If overflow is detected on left-shift, set target to `powLimit`.

2. **Optional future-proof time reference**  
   If a non-genesis anchor is ever supported, switch to anchor-parent time:
   ```cpp
   int64_t nTimeRef = pindexAnchor->pprev
       ? pindexAnchor->pprev->GetBlockTime()
       : pindexAnchor->GetBlockTime();
   nTimeDiff = nTimeLast - nTimeRef;
   ```

3. **Chainparams sanity check**  
   Extend `sanity_check_chainparams` (or equivalent) to assert `nASERTHalfLife > 0` and that ASERT-related parameters are consistent with block spacing.

### 2.2 Testing

1. **C++ unit tests**  
   Add `pow_tests` cases for ASERT:
   - Constant hashrate: difficulty remains stable.
   - Simple time-delta cases (e.g. behind/ahead of schedule).
   - Clamping to pow limit and min target.

2. **Functional tests**  
   Add `feature_asert.py` on testnet:
   - Mine with ideal spacing; difficulty should stay roughly constant.
   - Mine faster (e.g. 75 s); difficulty should increase.
   - Mine slower (e.g. 300 s); difficulty should decrease.
   - Check that nBits evolve as expected.

3. **Test vectors**  
   Optionally validate against BCH-style vectors (adapted for Zorkcoin parameters).

### 2.3 Operational

1. **Logging**  
   Consider debug-level logs when difficulty changes significantly (e.g. target change > 10%).

2. **Monitoring**  
   After deployment, monitor mean block time and difficulty over several halflives (e.g. 12 hours) to confirm stability.

---

## 3. Parameter Verification

| Parameter          | Zorkcoin Value   | Spec / Design                         |
|--------------------|------------------|---------------------------------------|
| `nPowTargetSpacing`| 150000 ms (2.5 m)| ✓ Matches 2.5 min blocks              |
| `nASERTHalfLife`   | 43200000 ms (12 h)| ✓ 4× faster than 2-day (10 min chain) |
| Anchor height      | 0 (genesis)      | ✓ Fixed from start                    |

---

## 4. Changes Applied

The following fixes were implemented:

1. **pow.cpp**
   - Use anchor's parent timestamp when available (future-proof; for genesis, parent is null so anchor time is used).
   - Replace shift clamping with overflow detection per BCH; clamp to powLimit on overflow.

2. **pow_tests.cpp**
   - Replace legacy tests with ASERT tests that call GetNextWorkRequired.
   - Add ASERT tests: `asert_basic`, `asert_ahead_of_schedule_increases_difficulty`, `asert_sanity_params`.

3. **feature_asert.py**
   - New functional test on testnet (ASERT enabled).
   - Verifies stable difficulty with ideal spacing, increased difficulty when mining fast, decreased when mining slow.

4. **test_runner.py**
   - Add `feature_asert.py` to BASE_SCRIPTS.

---

## 5. References

- [BCH ASERT Fork Spec](https://reference.cash/protocol/forks/2020-11-15-asert)
- [Lotusia ASERT Spec](https://lotusia.org/docs/specs/difficulty-adjustment)
- [BCH Node pow.cpp](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/pow.cpp)
- Zorkcoin `doc/timestamp-semantics.md`
