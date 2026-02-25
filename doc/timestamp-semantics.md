Millisecond Timestamp Semantics
================================

This document summarizes the intended units and semantics for timestamps after
the millisecond upgrade, and how they are used across consensus, wallet,
network, and UI layers.

Consensus / Blockchain
----------------------

- **Block header time (`CBlockHeader::nTime`, `CBlockIndex::GetBlockTime*`)**
  - Unit: **milliseconds since Unix epoch** (int64).
  - All consensus logic that works with block times (difficulty retarget,
    median-time-past checks, and future-time checks) should treat these as
    millisecond values.

- **Difficulty / retarget parameters**
  - `Consensus::Params::nPowTargetTimespan` and `nPowTargetSpacing` are
    expressed in **milliseconds**, and the difficulty code uses the same units
    as `nTime`.
  - Tests in `src/test/pow_tests.cpp` construct timestamps in milliseconds and
    use `LL * 1000` literals so arithmetic is performed in int64_t, avoiding
    overflow and unit mismatches.

- **ChainTxData::nTime**
  - Unit: **milliseconds**; values should be set either directly in
    milliseconds or as a 64‑bit literal multiplied by 1000 (e.g.
    `1758215212LL * 1000`) to preserve precision and avoid UBSan issues.

- **Sanity windows**
  - `MAX_FUTURE_BLOCK_TIME` and `TIMESTAMP_WINDOW` in `chain.h` are expressed
    in **milliseconds**, and any comparison with block times should be
    millisecond‑to‑millisecond.

- **BIP68 time-based relative lock-time (sequence locks)**
  - Block time and median-time-past (MTP) are in **milliseconds** in this codebase.
  - BIP68 time-based relative lock-time still uses **512-second granularity** (the
    encoded value is in units of 512 seconds; see `SEQUENCE_LOCKTIME_GRANULARITY`).
  - When evaluating sequence locks, the node converts the 16-bit count × 512 seconds
    into milliseconds before adding to the coin’s MTP, so that the minimum required
    time and the block’s MTP are compared in the same unit (ms). See
    `CalculateSequenceLocks` in `src/consensus/tx_verify.cpp`.

Wallet and Transaction Metadata
-------------------------------

- **Wallet internal timestamps**
  - Transaction times (`CWalletTx::nTime`, `nTimeSmart`), key birth times
    (`CKeyMetadata::nCreateTime`), and wallet‑level timestamps used for rescans
    are in **milliseconds**.
  - Tests such as `ComputeTimeSmart` in `wallet_tests.cpp` construct mock and
    block times in milliseconds and assert against millisecond values.

- **Rescans (`CWallet::RescanFromTime`, `ScanForWalletTransactions`)**
  - `RescanFromTime(startTime, ...)` receives `startTime` in **milliseconds**.
  - It locates the starting block using:
    - `chain().findFirstBlockWithTimeAndHeight(startTime - TIMESTAMP_WINDOW, 0, ...)`
  - The `TIMESTAMP_WINDOW` used here is in milliseconds, and `findFirstBlock…`
    expects a millisecond timestamp matching `CBlockIndex::GetBlockTimeMax()`.
  - The goal is:
    - For an imported key with birth time `T_key`, rescan from the **earliest**
      block whose time is within a reasonable window before `T_key`, so we
      neither miss historical transactions nor scan excessively early blocks.

Network / Non‑Consensus Timing
------------------------------

- **Addrman / peer connection times**
  - `CAddress::nTime` and addrman connection bookkeeping remain in **seconds**
    for protocol compatibility.
  - Higher‑level calls such as `GetAdjustedTime()` now return milliseconds, so
    addrman converts explicitly:
    - Divide by 1000 when storing or comparing against second‑based fields.
    - Multiply by 1000 only when comparing against millisecond‑based limits.

- **Bantime and related logic**
  - Internal logic normalizes bantime to **milliseconds**, but wire formats and
    persisted values continue to respect their defined units. Conversions are
    explicit at the boundaries.

UI, RPC, and Logging
--------------------

- **Formatting and parsing**
  - `FormatISO8601DateTime` / `FormatISO8601Date` take millisecond inputs and
    internally convert `nTime / 1000` to `time_t` for rendering.
  - `ParseISO8601DateTime` returns **milliseconds**, casting the parsed
    seconds‑since‑epoch to int64 and multiplying by 1000.
  - This ensures that round‑tripping a timestamp through human‑readable form
    preserves millisecond precision where the original value was in
    milliseconds.

- **RPCs and GUI models**
  - For compatibility, many RPCs and GUI displays present timestamps in
    seconds; they should do so by dividing internal millisecond values by 1000
    when forming `time_t` or JSON numbers.
  - Where an RPC is explicitly documented to return milliseconds (or takes
    millisecond parameters), it should pass millisecond values through without
    truncation.

Implementation Notes
--------------------

- When introducing new timestamps:
  - Choose the unit deliberately (milliseconds for on‑chain / wallet time,
    seconds where constrained by protocol or legacy formats).
  - Document the unit in code comments near the field or function.
  - Avoid ad‑hoc `* 1000` / `/ 1000` conversions; instead:
    - Use a clearly named helper or an inline comment explaining the unit
      change.

- When comparing or combining times:
  - Ensure both operands are in the same unit before arithmetic.
  - Prefer `int64_t` for intermediate computations and add `LL` suffixes to
    large literals that participate in multiplications (e.g. timestamps * 1000)
    to avoid overflow and UBSan issues.

