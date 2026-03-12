## ASERT Difficulty Patch

- **Base commit:** 2fcb48036e9a80294020be8a33b4fba0cbfa2129
- **ASERT commits included:**
  - 3ce1f7c7ef – introduces `nASERTHalfLife` and Marscoin PoW timing across chain params.
  - 48ec665be6 – adds DarkGravityWave2/3, `GravityAsert`, and the header-validation helpers (now all expressed with `arith_uint256` arithmetic).
  - 6a5fb15a18 – cleans logging and moves ASERT constants into consensus parameters (`nASERTAnchor`, `nASERTSpacing`).

### Contents of `asert-changes.patch`
- `src/consensus/params.h`: adds ASERT-specific consensus fields (`nASERTHalfLife`, and optionally `nASERTAnchor`, `nASERTSpacing`).
- `src/kernel/chainparams.cpp`: wires network-specific values for ASERT parameters and activation heights. **Note**: Contains Marscoin-specific chain parameters that must be replaced with your chain's values.
- `src/pow.cpp`: implements DarkGravityWave variants, the `GravityAsert` DAA, and the height-based dispatcher using `arith_uint256` only (no OpenSSL dependency).
- `src/util/serfloat.{h,cpp}` & `src/validation.cpp`: add `ConvertBitsToDouble` and adapt proof-of-work checks for the new algorithms.

**Important**: This patch does NOT include `src/bignum.h` or any OpenSSL dependencies. All arithmetic operations use the standard `arith_uint256` type that exists in Bitcoin Core and Litecoin Core.

### Licensing
- All source additions remain under the Marscoin/Bitcoin MIT license.
- No OpenSSL linkage is required; the patch relies solely on existing `arith_uint256` helpers.

### Litecoin Core Compatibility
- Patch touches only files that exist unmodified in Litecoin Core, so it can be ported without introducing new headers or libraries.
- `arith_uint256` already provides the operations ASERT needs (compact encoding, ±, shifts, ×/÷ via temporary `arith_uint256` factors), so no replacement for `CBigNum` is necessary.
- Expect only mechanical context adjustments in `src/pow.cpp` (Litecoin's DGW tuning differs slightly), but no dependency or build issues should arise.

---

## Patch Application Instructions

### Prerequisites
- A clean working tree (commit or stash any uncommitted changes)
- Git installed and configured
- The target codebase should be based on Bitcoin Core or Litecoin Core (or a compatible fork)
- The codebase should already have `arith_uint256` support (standard in Bitcoin Core 0.10+ and Litecoin Core)

### Step-by-Step Application

1. **Verify Base Compatibility**
   - Ensure your codebase has the following files:
     - `src/consensus/params.h`
     - `src/kernel/chainparams.cpp` (or `src/chainparams.cpp` in older versions)
     - `src/pow.cpp`
     - `src/util/serfloat.h` and `src/util/serfloat.cpp`
     - `src/validation.cpp`
   - If any files are missing or in different locations, you'll need to adjust the patch paths manually.

2. **Apply the Patch**
   ```bash
   git apply asert-changes.patch
   ```
   - If successful, proceed to step 3.
   - If you get conflicts, see the "Handling Conflicts" section below.

3. **Review Chain-Specific Parameters**
   The patch includes Marscoin-specific values that MUST be customized for your chain:
   
   **In `src/kernel/chainparams.cpp` (or `src/chainparams.cpp`):**
   - **Genesis block parameters**: The patch modifies genesis block creation. Replace Marscoin's genesis timestamp, nonce, and script with your chain's values.
   - **Consensus parameters**: Review and adjust:
     - `consensus.nSubsidyHalvingInterval` (Marscoin: 395699)
     - `consensus.powLimit` (Marscoin: `00000fffff...`)
     - `consensus.nPowTargetTimespan` (Marscoin: 3.5 days)
     - `consensus.nPowTargetSpacing` (Marscoin: 2.5 minutes)
     - `consensus.nASERTAnchor` (Marscoin: 2999999) - **Critical**: Set this to the block height where ASERT should activate
     - `consensus.nASERTHalfLife` (Marscoin: 2 hours = 7200 seconds)
     - `consensus.nASERTSpacing` (Marscoin: 123 seconds = 2 Mars-minutes)
   
   **In `src/pow.cpp`:**
   - **Activation heights**: The `GetNextWorkRequired` function dispatches based on block height:
     ```cpp
     if (nHeight >= 120000 && nHeight < 125999) {
         return DarkGravityWave2(...);
     } else if (nHeight >= 126000 && nHeight < 2999999) {
         return DarkGravityWave3(...);
     } else if (nHeight >= 2999999) {
         return GravityAsert(...);
     }
     ```
     Adjust these height ranges to match your chain's difficulty algorithm history and ASERT activation height.

4. **Build and Test**
   ```bash
   ./autogen.sh  # if needed
   ./configure
   make
   ```
   - Fix any compilation errors (see "Common Issues" below)
   - Run tests if available
   - Test difficulty adjustment on a testnet or regtest

### Handling Conflicts

If `git apply` reports conflicts, you'll need to resolve them manually:

1. **Identify conflicted files**: Git will mark conflicts with `<<<<<<<`, `=======`, and `>>>>>>>` markers.

2. **Common conflict locations:**
   - **`src/kernel/chainparams.cpp`**: Your chain likely has different genesis block parameters, BIP activation heights, and consensus values. Keep your chain's values but add the ASERT parameters (`nASERTAnchor`, `nASERTHalfLife`, `nASERTSpacing`) to all network definitions (mainnet, testnet, regtest, signet).
   - **`src/pow.cpp`**: If your chain already has custom difficulty algorithms, you may need to merge the ASERT implementation with your existing code. The key function to preserve is `GravityAsert()` and the dispatcher logic in `GetNextWorkRequired()`.
   - **`src/consensus/params.h`**: Simply add `int64_t nASERTHalfLife;` (and `nASERTAnchor`, `nASERTSpacing` if the patch includes them) to the `Params` struct. No conflicts should occur here unless the struct layout is significantly different.

3. **After resolving conflicts:**
   ```bash
   git add <resolved-files>
   git commit -m "Add ASERT difficulty adjustment algorithm"
   ```

### Common Issues and Solutions

1. **"File not found" errors**
   - **Problem**: File paths in the patch don't match your codebase structure.
   - **Solution**: Use `git apply --directory=<path>` or manually adjust file paths in the patch. For example, if your `chainparams.cpp` is in `src/` instead of `src/kernel/`, you'll need to edit the patch.

2. **Compilation errors with `arith_uint256`**
   - **Problem**: Missing includes or incorrect usage of `arith_uint256` operators.
   - **Solution**: Ensure `#include <arith_uint256.h>` is present. The patch uses standard `arith_uint256` operations that should work in Bitcoin Core 0.10+ and Litecoin Core.

3. **"nASERTAnchor not found" errors**
   - **Problem**: The consensus parameters weren't added to all network definitions.
   - **Solution**: Add `consensus.nASERTAnchor`, `consensus.nASERTHalfLife`, and `consensus.nASERTSpacing` to ALL network parameter sections in `chainparams.cpp` (CMainParams, CTestNetParams, CRegTestParams, CSigNetParams).

4. **Difficulty calculation returns wrong values**
   - **Problem**: Activation heights or ASERT parameters are incorrect.
   - **Solution**: 
     - Verify `nASERTAnchor` matches the intended activation block height
     - Ensure `nASERTSpacing` matches your chain's target block spacing
     - Check that `nASERTHalfLife` is set correctly (typically 2 hours = 7200 seconds)

5. **Validation errors after applying**
   - **Problem**: The `ConvertBitsToDouble` function or validation logic conflicts with existing code.
   - **Solution**: The patch adds `ConvertBitsToDouble` to `serfloat.cpp/h`. If your codebase already has this function, remove the duplicate or merge implementations.

### Post-Application Checklist

- [ ] All ASERT parameters (`nASERTAnchor`, `nASERTHalfLife`, `nASERTSpacing`) are set in all network definitions
- [ ] Activation heights in `GetNextWorkRequired()` match your chain's history
- [ ] Genesis block parameters are restored to your chain's values (not Marscoin's)
- [ ] Code compiles without errors
- [ ] Tests pass (if available)
- [ ] Difficulty adjustment tested on regtest/testnet
- [ ] ASERT activates at the correct block height

---

## AI Prompt for Zorkcoin Integration

Use the following prompt with an AI coding assistant (like Cursor, GitHub Copilot, or ChatGPT) to apply this ASERT patch to the Zorkcoin project:

```
I need to integrate the ASERT (Absolutely Scheduled Exponentially Rising Targets) difficulty adjustment algorithm into Zorkcoin, a blockchain project based on Litecoin Core source code.

I have two files:
1. `asert-changes.patch` - A git patch file containing ASERT implementation
2. `asert-changes.md` - Documentation explaining the patch

Context about ASERT:
- ASERT is a difficulty adjustment algorithm that uses an exponential moving average based on an anchor block
- It activates at a specific block height (configurable via `nASERTAnchor` consensus parameter)
- The algorithm uses three key parameters:
  - `nASERTAnchor`: Block height where ASERT becomes active
  - `nASERTHalfLife`: Time constant for exponential decay (typically 2 hours = 7200 seconds)
  - `nASERTSpacing`: Target block spacing in seconds (should match the chain's actual target spacing)

The patch modifies these files:
- `src/consensus/params.h`: Adds `nASERTHalfLife` (and possibly `nASERTAnchor`, `nASERTSpacing`) to consensus parameters
- `src/kernel/chainparams.cpp`: Adds ASERT parameter values for all networks and includes Marscoin-specific chain parameters that need to be replaced
- `src/pow.cpp`: Implements DarkGravityWave2, DarkGravityWave3, and GravityAsert algorithms, plus a height-based dispatcher
- `src/util/serfloat.cpp` and `src/util/serfloat.h`: Adds `ConvertBitsToDouble` helper function
- `src/validation.cpp`: Adapts proof-of-work validation to work with the new difficulty algorithms

Tasks:
1. Apply `asert-changes.patch` to the Zorkcoin codebase. If there are conflicts, resolve them by:
   - Keeping Zorkcoin's genesis block parameters, consensus values, and BIP activation heights
   - Adding the ASERT consensus parameters (`nASERTAnchor`, `nASERTHalfLife`, `nASERTSpacing`) to all network definitions
   - Preserving any existing Zorkcoin-specific difficulty adjustment code if present

2. Customize ASERT parameters for Zorkcoin:
   - Set `nASERTAnchor` to the block height where ASERT should activate (e.g., if Zorkcoin is new, use a height like 100000 or a specific milestone)
   - Set `nASERTSpacing` to match Zorkcoin's target block spacing (check `nPowTargetSpacing` in chainparams)
   - Set `nASERTHalfLife` appropriately (7200 seconds = 2 hours is standard, but can be adjusted based on chain characteristics)

3. Adjust activation heights in `src/pow.cpp`:
   - The `GetNextWorkRequired` function dispatches to different algorithms based on block height
   - Modify the height ranges to match Zorkcoin's difficulty algorithm history:
     - If Zorkcoin starts with ASERT from genesis, remove the DarkGravityWave branches
     - If Zorkcoin has existing difficulty algorithms, adjust the height ranges accordingly
     - Ensure the ASERT activation height matches `nASERTAnchor`

4. Verify the implementation:
   - Ensure all files compile without errors
   - Check that `arith_uint256` is used throughout (the patch should not require OpenSSL/bignum)
   - Confirm that ASERT parameters are set in all network definitions (mainnet, testnet, regtest, signet if applicable)

5. Provide a summary of:
   - What changes were made
   - What Zorkcoin-specific values were used for ASERT parameters
   - Any conflicts that were resolved and how
   - Recommendations for testing the difficulty adjustment

Important notes:
- The patch is designed for Litecoin Core-based codebases and uses `arith_uint256` (no OpenSSL dependency)
- All Marscoin-specific values in the patch must be replaced with Zorkcoin equivalents
- The patch includes helper functions (`GetMyDifficulty`, `TargetToMyDifficulty`) that may need adjustment if Zorkcoin has different difficulty calculation needs
- Test thoroughly on regtest before deploying to mainnet
```

### Additional Context for AI Integration

**Zorkcoin-Specific Considerations:**
- If Zorkcoin has a different genesis block, BIP activation heights, or consensus parameters than Litecoin, these will need to be preserved when applying the patch
- The patch assumes standard Bitcoin/Litecoin Core file structure; if Zorkcoin has a different layout, file paths may need adjustment
- If Zorkcoin already implements DarkGravityWave or other difficulty algorithms, you may need to merge implementations rather than replace them
- The ASERT activation height (`nASERTAnchor`) should be set to a future block height to allow for testing and network preparation

**Testing Recommendations:**
- Use regtest to verify difficulty adjustment works correctly
- Test the transition from previous difficulty algorithm to ASERT at the activation height
- Verify that difficulty adjusts smoothly and doesn't cause chain splits
- Monitor difficulty adjustments over several adjustment periods to ensure stability
