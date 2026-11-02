# Block 1 Bitcoin launch lock

Height 1 on **mainnet** and **testnet** requires a qualifying embedded Bitcoin header in the coinbase. Regtest and testnet4 leave the lock disabled.

| Network | Genesis / T0 | Lock `min_unix_time` | `nbits_floor` |
|---|---|---|---|
| Mainnet | 2026-11-21 21:25:29.728 UTC (`nTime = 1795296329728` / `0x1A200000000`) | `1795296330` (first whole second after genesis) | `0x1702353d` |
| Testnet | 2026-11-01 21:24:36.480 UTC (`nTime = 1793568276480` / `0x1A199000000`) | `1793568277` (first whole second after genesis) | `0x1702353d` |

See `src/kernel/genesis_mainnet.h` and `src/kernel/genesis_testnet.h` for the pinned genesis and launch-lock constants.

Release binaries may ship before the lock second. **Consensus still rejects height 1** until the coinbase carries a qualifying embedded Bitcoin header (see below).

**Product rule:** Block 1 must not exist before the lock instant on the intended path. Height 1 is gated on a **copied** Bitcoin mainnet block header — taken from public sources after the lock second, not mined for Zorkcoin. Zork miners embed those 80 bytes in the block 1 coinbase and mine block 1 with kHeavyHash as usual.

**Launch practice vs what nodes enforce**

| | Launch practice (operators) | Consensus (every node, locally) |
|---|---|---|
| Source of header | Observe a real Bitcoin mainnet block after T0 (`getblockheader`, explorer, etc.) | Does not fetch Bitcoin; validates only the 80 bytes in the coinbase |
| When block 1 is built | After a qualifying header exists to copy | Rejects height 1 if timestamp, difficulty floor, or SHA256d checks fail |
| Fairness | Same public bytes available to all miners, including the project team | No special path for Core developers; same rules in `CheckBlock` |

Bitcoin has no role in Zorkcoin beyond supplying that header copy. Mining Bitcoin is unrelated to mining Zork.

---

## Why a Bitcoin header

On the **intended launch path**, no one can finish valid mainnet block 1 before T0, because no post-launch Bitcoin block header is available to copy yet.

After T0, any Bitcoin mainnet block whose header meets the rules below can supply the embed. Miners may choose different qualifying blocks; consensus does not require everyone to use the same one. Anyone with the same public source sees the same 80 bytes for a given Bitcoin block hash.

**Launch practice:** observe a public Bitcoin block; do not pre-grind or stockpile a header before T0. Pre-mining Zork mainnet ahead of launch is what this procedure prevents.

Nodes validate the embedded bytes only. They do not connect to Bitcoin during sync or reindex.

---

## Launch procedure (operators)

1. **T0:** Publish genesis with the fixed `nTime` (`src/kernel/genesis_mainnet.h` / `src/kernel/genesis_testnet.h`).
2. **Observe Bitcoin:** Wait until Bitcoin mainnet produces a block whose header satisfies the timestamp and difficulty rules below. Copy the 80-byte header from a source you trust — for example:

   ```bash
   bitcoin-cli getblockheader <block-hash> false
   ```

   The result is 160 hex characters (80 bytes). **Do not mine Bitcoin on behalf of Zorkcoin** — only copy a header from a block the Bitcoin network already found.

3. **Build Zork block 1:** Put that header in the height-1 coinbase `OP_RETURN` (format below). Mine with kHeavyHash.

Optional: `-btclaunchheader=<160 hex>` when using Zorkcoin Core’s in-tree block template (`CreateNewBlock` at height 1). Pools that assemble their own coinbase can embed the same output without that flag; consensus inspects the submitted block, not how it was built.

Height **2 and above** use the normal coinbase rules; the launch lock applies only at height 1.

---

## Coinbase payload

Mainnet and testnet, for any block whose parent is genesis (height 1, including competing block-1 candidates).

Exactly one 0-value `OP_RETURN` in the coinbase. The witness Merkle commitment is a separate `OP_RETURN` and is ignored by this rule:

```
OP_RETURN
  PUSH "btc"
  PUSH 42
  PUSH <80-byte Bitcoin header>
```

Standard Bitcoin header layout (not a Zork 88-byte header):

| Offset | Field | Encoding |
|---|---|---|
| 0–3 | version | uint32 LE |
| 4–35 | prev block | 32 bytes |
| 36–67 | merkle root | 32 bytes |
| 68–71 | timestamp | uint32 LE **unix seconds** |
| 72–75 | `nBits` | uint32 LE compact target |
| 76–79 | nonce | uint32 LE |

Genesis time is in **milliseconds**; the embedded Bitcoin field is **whole Unix seconds**.

---

## What nodes check (consensus)

All checks use only the bytes in the `OP_RETURN`. No HTTP, RPC, or live lookup to Bitcoin.

### 1. Timestamp

`nTime = ReadLE32(header + 68)` must be **≥** the network’s pinned `min_unix_time` (mainnet `1795296330`, testnet `1793568277`).

Headers copied from real Bitcoin blocks at or after that instant satisfy this. A header claiming an earlier time is rejected.

### 2. Difficulty floor (`nBits`, decoded)

`nBits = ReadLE32(header + 72)` uses Bitcoin compact encoding. Consensus decodes the header target and the pinned floor with `SetCompact`, rejects invalid targets, then requires:

```
header_target <= floor_target
```

(smaller target = harder work). Floor compact value **`0x1702353d`**, frozen from Bitcoin mainnet block **962490** (2026-08-14). Later Bitcoin retargets do not change Zork consensus.

Do not compare raw compact integers (`0x1d00ffff` is a larger integer but an easier target than `0x1702353d`).

### 3. SHA256d proof of work

```
SHA256d(80-byte header) interpreted as uint256 <= header_target
```

Bitcoin’s double-SHA256, not kHeavyHash. A header copied from a real Bitcoin block typically already satisfies this; nodes re-check locally.

---

## Fair launch

| Question | Answer |
|---|---|
| Who finds the Bitcoin block? | The Bitcoin network, on its own schedule. |
| Do Zork miners need Bitcoin hashrate? | **No.** They copy an 80-byte header from a block Bitcoin already found. |
| Who may use the header? | Anyone who can read the same public header bytes. |
| Does Core get a consensus bypass? | **No.** The team follows the same `CheckBlock` rules; no private validation path. |
| When can block 1 be mined? | After a qualifying header exists to copy and operators follow observe-after-T0 practice. |

After the header is public, **block 1’s kHeavyHash work** is the mining race — standard PoW, same as later heights (with ASERT on the Zork header).

Pinned constants live in `src/kernel/genesis_mainnet.h` (`BTC_LAUNCH_*`) and `src/kernel/genesis_testnet.h` (`BTC_LAUNCH_TESTNET_*`) and can be audited before the lock second.

---

## Guarantees and limits

**On the intended launch path**

1. Block 1 should not be assembled until a post-T0 Bitcoin header exists to copy.
2. The coinbase cannot carry a cheap forged header: difficulty is pinned at roughly one Bitcoin block at the floor (`0x1702353d`, from BTC #962490).
3. Validation is deterministic: every node applies the same three checks to the embedded 80 bytes.

**What consensus does not prove**

- That the header is on Bitcoin’s best chain at validation time (membership would need heavy proofs or non-deterministic fetches). Launch practice uses headers from the public Bitcoin chain; nodes treat the blob as self-contained evidence of timestamp, difficulty, and PoW.
- That operators waited for wall-clock T0 before copying (social launch discipline). Consensus enforces `nTime ≥ min_unix_time`, not human ceremony timing.

**Offline grind (out of band):** A party could grind an 80-byte blob that passes the three checks without copying a live Bitcoin block. That is costly (floor work) and **not** part of launch practice. The product rule is observe-and-copy after T0, not pre-stockpile before T0.

**Separate from this rule:** Block 1’s kHeavyHash difficulty comes from Zork ASERT on the 88-byte header.

---

## Implementation pointers

- Checker: `src/consensus/btc_launch_lock.cpp`
- Enforced in `CheckBlock` when `hashPrevBlock == genesis`
- Params: `Consensus::Params::btc_launch_lock` (enabled on mainnet and testnet)
- Assembler: `-btclaunchheader` (optional; embeds the OP_RETURN in the in-tree template at height 1)

Unit tests on `MAIN` and `TESTNET` disable this lock (`DisableBtcLaunchLockForUnitTests`); production mainnet and testnet enable it. Rehearsal before the lock second uses regtest or historical header hex for drill only — not a pre-launch stockpile.
