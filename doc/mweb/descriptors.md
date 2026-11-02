# MWEB Descriptors

This document specifies how MWEB keys and stealth receive addresses are represented in descriptor wallets. The cryptographic protocol (DKSAP address generation, output construction, and identification) is defined in [stealth-addresses.md](stealth-addresses.md). This document covers **descriptor packaging**: forms, parsing, storage, import/export, scanning policy, and PSBT-related use.

Normative LIP-0008 shapes are summarized below together with ADGL multi-account policy, wallet-internal records, and import rules.

### Relationship to the LIP-0008 draft

The LIP-0008 draft ("MWEB Descriptor Standard"; not part of Litecoin Core or the official LIP repository) defines exactly three forms:

| LIP-0008 form | This document |
|---|---|
| `mweb(master_scan,master_spend,*)` | [Form 1](#1-ranged-account--lip-0008), ranged account |
| `mweb(master_scan,master_spend,<i>)` | [Form 2](#2-indexed-single--lip-0008), indexed single |
| `mweb(master_scan,subaddr_spend)` | [Form 3](#3-two-parameter), rows `priv,priv` and `priv,pub` |

Parameter semantics, canonical export, and validation guidelines here follow the draft except where listed below. This tree adds one form that the draft does not define: the **wallet internal** form `mweb(A_i,B_i,i,acct_cksum)`. It is a wallet-local extension and should not be expected to parse in other implementations. There is no descriptor form of a payment address; MWEB addresses are written in bech32.

Differences from the draft:

* **Private scan key:** the draft requires a private master scan key when parsing. This tree parses every form with a public scan key, as Bitcoin Core accepts public keys in any descriptor, and needs the scan secret only where the descriptor is used: `importdescriptors` accepts a public scan key only when the wallet already holds the matching scan secret, `deriveaddresses` does not take MWEB descriptors, and a PSBT input descriptor without the scan secret is an error. Litecoin Core fails the parse with "private master_scan_key is needed".

* **Two-argument form with an extended spend key:** the draft defines the second argument of `mweb(master_scan,subaddr_spend)` as subaddress spend material in any `KEY` encoding. This tree, like Litecoin Core's 24.x branch, parses `mweb(<scan>,<xpub or xprv expression>)` as a **ranged account** whose spend key is the master spend key (`src/script/descriptor.cpp`, `IsMWEBExtKeyExpression`). The same string therefore means one subaddress to a draft-conforming tool and the whole account here.

* **Key encoding:** the draft's `KEY` list (copied from BIP-380) mentions uncompressed `04…` public keys and ranged `/*` extended keys. MWEB keys are always 33-byte compressed points, and range is expressed by the third argument, so this tree rejects ranged extended keys, x-only keys and uncompressed keys in every argument.

## Why MWEB descriptors differ from L1

Layer-1 descriptors such as `wpkh(xpub/84h/0h/0/0/*)` describe a BIP32 path where each index `i` yields a **public** child key that is the receive address. Anyone with the exported xpub can enumerate all receive addresses.

MWEB stealth addresses do **not** work that way. Per-index material `(A_i, B_i)` requires the **private** master scan scalar `a` and the **public** master spend key `B`: `B_i = B + HASH32('A' || LE32(i) || a)·G` and `A_i = a·B_i` (see [Address Generation](stealth-addresses.md#address-generation)). The master spend secret `b` is not needed to derive addresses, only to spend. Without `a` no subaddress can be computed, so there is no public-only (xpub-style) derivation.

A MWEB payment target, the bech32 `mweb1…` / `tmweb1…` address, **always requires both** the scan public key `A_i` and the spend public key `B_i`. Either key alone is insufficient for a sender to construct a valid output.

## Notation

| Symbol | Meaning |
|--------|---------|
| `a`, `A` | Master scan scalar and pubkey `A = a·G` |
| `b`, `B` | Master spend scalar and pubkey `B = b·G` |
| `i` | Stealth subaddress index, `0` to `2147483647` in descriptors |
| `a_i`, `A_i` | Per-index scan scalar / pubkey |
| `b_i`, `B_i` | Per-index spend scalar / pubkey |
| `KEY` | BIP-380 key expression |
| `priv` / `pub` | Whether a `KEY` provides secret material |

Parameter order is always **scan, then spend**.

Descriptor strings contain **no whitespace**. Spaced forms in this document are illustrative only.

## Address derivation (descriptor-relevant)

From masters `(a, b)` and index `i`:

1. `b_i = b + HASH32('A' || LE32(i) || a)`
2. `B_i = b_i · G`
3. `a_i = a · b_i`
4. `A_i = a_i · G`

Where `HASH32` is 32-byte BLAKE3 with ASCII `'A'` as the hash tag (libmw `EHashTag::ADDRESS`), and `LE32(i)` is `i` as 4-byte little-endian. Scalar results must be valid non-zero secp256k1 scalars per stealth-addresses / libmw rules.

**Derivation relationship (LIP-0008):** if `a`, subaddress spend material, and index `i` are known, the master spend material can be recovered: `b = b_i - HASH32('A' || LE32(i) || a)` for the secret, or `B = B_i - HASH32('A' || LE32(i) || a)·G` for the public key.

Address material for index `i` is the pair `(A_i, B_i)`.

### Bech32 address

The bech32 `mweb1…` / `tmweb1…` address encodes `(A_i, B_i)` and is the only form used to send to or publish a receive address. It carries no scan or spend secrets. A string such as `mweb(<hex>,<hex>)` is not an address: it is the [two-parameter form](#3-two-parameter) with a public scan key. Address arguments reject it: `validateaddress`, `sendtoaddress`, `sendmany`, `send`, `createrawtransaction`, `createpsbt`, `walletcreatefundedpsbt`, `zorkcoin-tx` outputs, `addr(...)` descriptors, and the GUI's send and address-book fields.

Bech32 rules: Bech32 (not Bech32m); HRP `mweb` (mainnet) / `tmweb` (test/signet/regtest); data is witness version symbol `0` then 5-bit conversion of 66 bytes `A_i || B_i` (each key 33-byte compressed).

## Priv vs pub

A `KEY` is **priv** if the wallet can obtain a secp256k1 secret scalar from it (WIF, `xprv` with a path that yields a private key, or equivalent).

A `KEY` is **pub** if only public material is present (compressed pubkey hex, `xpub`, or a neutered view of an `xprv` KEY).

`KEY` expressions follow BIP-380, including optional origin brackets and BIP32 derivation steps. Ranged extended keys (trailing `/*` or `/*'`) are rejected inside `mweb`; account-wide range is expressed only by the literal third argument `*`. X-only (64-hex) keys are rejected. MWEB keys are 33-byte compressed points (`02`/`03` + 32-byte X). Uncompressed keys, as `04…` hex or as an uncompressed WIF, are rejected in every parameter. The wallet-internal form accepts only valid compressed pubkeys in hex.

## Typical BIP32 paths (informative)

When masters are BIP32-derived from a seed, the usual Litecoin/MWEB layout is:

| Role | Path |
|------|------|
| Master scan `a` | `m/0'/100'/0'` |
| Master spend `b` | `m/0'/100'/1'` |

The wallet's default account uses the account path from the chain parameters (`MWEBAccountPath()`, `m/0'/100'` on every network), with the scan key at its `0'` child and the spend key at its `1'` child. Seed recovery and the wallet's key checks derive along the same path, so a network's value must not change once wallets exist.

Example ranged account:

```
mweb(<xprv>/0'/100'/0',<xprv>/0'/100'/1',*)
```

Watch-only spend side (scan remains private):

```
mweb(<xprv-or-WIF-for-a>,<xpub>/0'/100'/1',*)
```

Paths live inside ordinary `KEY` expressions; they are not a separate descriptor grammar.

Other paths are added with `importdescriptors`; there is no option for them at wallet creation. For example, an account with a custom path:

```
mweb(<xprv>/0h/200h/0h,<xprv>/0h/200h/1h,*)
```

or the wallet's own scan key with a spend key held elsewhere, such as on a hardware device:

```
mweb(<wallet xprv>/0h/100h/0h,[fp/path]<external xpub>,*)
```

`listdescriptors true` prints the wallet xprv. Any hardened steps of the spend path must already be inside the external xpub: a hardened step written after an xpub can't be derived without the private key, so the wallet would not know the spend public key (see [Export](#export-listdescriptors)).

## Forms

Optional trailing `#checksum` uses ordinary descriptor checksum rules.

### 1. Ranged account — LIP-0008

```
mweb(master_scan,master_spend,*)
```

| Parameter | Constraint |
|-----------|------------|
| `master_scan` | Private `KEY` → `a` |
| `master_spend` | Private `KEY` → `b` (spend-capable) **or** public `KEY` → `B` (watch-only; external signer) |
| `*` | Literal |

Covers all subaddresses from `(a,b)`. Primary **account** form for minting. A wallet may hold several accounts; one may be **active** for `getnewaddress`.

### 2. Indexed single — LIP-0008

```
mweb(master_scan,master_spend,i)
```

Same key rules as ranged. Capability limited to index `i`: decimal digits only, no sign, no leading zeros, from `0` to `2147483647`. Larger values would collide with libmw's markers for a custom key (`0xFFFFFFFE`) and an unknown index (`0xFFFFFFFF`) and do not fit the wallet's signed 32-bit index fields. The wallet-internal form uses the same index rule.

### 3. Two-parameter

```
mweb(scan,spend)
```

| `scan` | `spend` | Meaning |
|--------|---------|---------|
| priv (`a`) | priv (`b_i`) | Identify + spend one subaddress; index not encoded |
| priv (`a`) | pub (`B_i`) | Identify one subaddress (external spend signer); index not encoded |
| pub (`A`) | priv or pub | As the rows above, with the scan key given as `A = a·G`; usable only by a wallet that already holds `a` |

The second parameter is **subaddress** spend (`b_i` / `B_i`), not master spend, unless it is an extended key.

#### LIP two-arg import (`a` + `b_i` or `a` + `B_i`)

These are imported and persisted as follows:

1. Find the accounts whose scan secret is the imported `a`.
2. If one of them derives the address (it holds `B` and `B + H('A' || LE32(i) || a)*G == B_i` for some index `i` it searches), record the address on that account at `i`. A private `b_i` then gives the account its master spend key, as described in [Validation on import](#validation-on-import).
3. Otherwise keep the import as a **single-address entry** (not ranged `*`), reusing an existing entry for the same address. It identifies and spends only that address: spend-capable if `b_i` is private, watch-only or external-signer if only `B_i` is present. It never mints further indices and never receives change.

### 4. Wallet internal — extension

```
mweb(A_i,B_i,i,acct_cksum)
```

| Parameter | Meaning |
|-----------|---------|
| `A_i` | Compressed scan pubkey (hex) |
| `B_i` | Compressed spend pubkey (hex) |
| `i` | Decimal index |
| `acct_cksum` | 8-character checksum of the account descriptor **as stored** in this wallet |

Internals are a **wallet-local** convenience: indices this wallet has minted or otherwise cares about. Not a cross-tool identity scheme.

`acct_cksum` is the BIP-380 descriptor checksum of the exact unchecksummed account descriptor text as stored (characters after `#`). One internal per `(acct_cksum, i)`. Public `listdescriptors` includes internals. Import requires a matching account checksum; otherwise **rejected**.

## Parse disambiguation

| Shape | Form |
|-------|------|
| 3 args, third `*` | Ranged account |
| 3 args, third an index (`0` to `2147483647`, no leading zeros) | Indexed single |
| 2 args, second an extended key | Ranged account |
| 2 args, otherwise | Two-parameter; then priv/pub table |
| 4 args: compressed pubkey, compressed pubkey, integer, 8-char checksum | Wallet internal |
| Anything else | Parse error |

Legacy forms such as `mweb(xpub/0h/100h)` and `mweb(xpub/100h/0h/0h/0/*)` are rejected. There is no `mweb_scan()` descriptor type and no separate `mweb_scan_secret` import field — scan material enters only as the first `KEY` of an `mweb` form that requires it.

## Capabilities

| Form | Identify | Spend | Mint | `importdescriptors` |
|------|----------|-------|------|---------------------|
| `mweb(a,b,*)` | all `i` | yes | yes if active | yes → ranged account |
| `mweb(a,B,*)` | all `i` | no | yes if active | yes → watch-only ranged account |
| `mweb(a,b,i)` | that `i` | yes | no | yes → recorded on the matching account; creates a supporting account if absent |
| `mweb(a,B,i)` | that `i` | no | no | yes → recorded on the matching account; creates a watch-only supporting account if absent |
| `mweb(a,b_i)` | that subaddr | yes | no | yes → recorded on the account that derives it, else a separate single-address entry |
| `mweb(a,B_i)` | that subaddr | no | no | yes → recorded on the account that derives it, else a separate watch-only single-address entry |
| any of the above with public scan `A` | as with `a` | as with `a` | as with `a` | only when the wallet holds `a`; otherwise "Cannot import mweb() descriptor: the wallet has no scan secret for its scan key" |
| `mweb(A_i,B_i,i,ck)` | lookup | no | no | yes (requires matching account) |

Watch-only accounts (`a` + public spend) identify/unmask like spend-capable for scanning. Signing needs the spend secret on a signer (local or hardware via PSBT).

## Account checksum

Spend-capable vs watch-only account strings (spend neutered) have different on-disk strings. Internals always refer to the account string stored in **that** wallet. Exporters that compute `acct_cksum` for matching use the **public** (neutered) account descriptor body so watch-only and spend-capable wallets can share internals.

## Wallet storage of secrets

| Material | Storage |
|----------|---------|
| Spend secrets (`b`, `b_i`, spend-side `xprv`) | Descriptor key records (`walletdescriptorkey`, or `walletdescriptorckey` when the wallet is encrypted); unlock required to sign |
| Scan secret (`a`), every wallet kind | Plaintext in the `mwebscank` record of each MWEB entry, **also in an encrypted wallet**: anyone who can read the wallet file can see the wallet's MWEB payments without the passphrase, as in both Litecoin Core releases. In a spend-capable wallet it is also derivable from the wallet's keys (for the default account, the master key at `m/0'/100'/0'`), and the two must be equal |
| Spend public key (`B`) of an account with a hardened spend path, and the other hardened key expressions | The descriptor cache (`walletdescriptorcache`, Bitcoin Core's record for derived xpubs), written when the keys are available: when the account is created or imported, or at the first unlock. Key origins and `B` then resolve while locked |

Scanning and address generation never need an unlock. Spend secrets stay encrypted. The `mwebscank` record is written only when the entry has none, after the descriptor cache.

**Upgrade:** an encrypted wallet created before the `mwebscank` record covered every wallet kind has neither the record nor the cached `B`. Until its first unlock after the upgrade it neither detects MWEB payments nor issues MWEB addresses while locked, and blocks connected in that state are not scanned later. After that unlock, run `rescanblockchain`, `mwebrescan` or `mwebscanutxoset` once.

**Checks:** the wallet compares its keys with these records on load, at unlock, on import, and before `encryptwallet`:

- the scan secret derived from the wallet's keys must equal the `mwebscank` record;
- every internal record must match the account's `a` and `B`;
- at unlock, the decrypted spend key must match the spend public key used while locked;
- on import, a scan key imported for an existing entry, watch-only ones included, must equal its `mwebscank` record; the import does not replace the record.

A mismatch on load fails it with "Wallet corrupted"; the log names the entry, and the index for an internal record. A mismatch on import fails that descriptor's import with the reason. A mismatch at unlock fails the unlock with the reason (`walletpassphrase`, `walletpassphrasechange` and `encryptwallet` return it; the GUI reports a wrong passphrase and the reason is in `debug.log`). Every MWEB entry stays locked and nothing is written; the entry whose records were refused neither scans nor issues addresses until the wallet is reloaded. The records are not authenticated, as Bitcoin Core's descriptor and cache records are not: whoever can write the wallet file can replace the scan record, the cached spend key and every internal record consistently with keys of their own, and a wallet loaded locked then hands out their addresses until an unlock refuses the records. Restore such a wallet from a backup or its seed.

The scan secret is more than a viewing key for received coins: outputs the wallet creates use a range-proof nonce derived from it (`DeriveRewindKey` / `DeriveProofNonce`), and sender signing keys are derived as `DeriveSenderSigningKey(a, i)`. Holding `a` is enough cryptographically to identify and rewind amounts for outputs the wallet **sent**. The wallet performs that sender-side recovery when scanning (keypool lookahead over `K_s`). See [payment-proofs.md](payment-proofs.md).

## Canonicalization (export)

Exporters MUST emit canonical forms:

| Situation | Export |
|-----------|--------|
| Ranged account | `mweb(master_scan,master_spend,*)` |
| Single index, masters + `i` known | `mweb(master_scan,master_spend,i)` |
| Single subaddr, masters/`i` unavailable | `mweb(master_scan,subaddr_spend)` |
| Bookkeeping for used index | `mweb(A_i,B_i,i,acct_cksum)` |
| Share/receive/send address | bech32 |

**Public** `listdescriptors`: emit each account as the watch-only form `mweb([origin]<scan WIF>,[origin]<spend pubkey hex>,*)` (no spend private material) and internals. See [Export](#export-listdescriptors). Unlike Bitcoin Core's public descriptors, this output contains a secret (the master scan key) and is returned without unlocking the wallet. An account whose spend public key is unknown (a watch-only account imported with a hardened spend path under an xpub, or an upgraded encrypted wallet before its first unlock) is exported in its stored form, for example `mweb(xpub/0h/100h/0h,xpub/0h/100h/1h,*)`.

**Private** `listdescriptors true` (unlocked): may emit private KEYs.

## Validation on import

- Scan key: private, or public when an account in the wallet holds the matching scan secret, which the import then uses. Otherwise the import fails with "Cannot import mweb() descriptor: the wallet has no scan secret for its scan key". A public scan key given as an extended key with a derivation path fails the same way, since the wallet's secret cannot stand in for the BIP32 parent.
- Ranged: literal `*`; validate KEY paths per descriptor rules.
- Indexed: valid index, not `0`/`1` (change and peg-in are initialized locally for full accounts). Derive the address from the descriptor's own keys, then find an account with both the same scan secret and master spend public key. Equivalent key material expressed with different origins or HD expressions reuses that account. Record the address as `mweb(A_i,B_i,i,acct_cksum)`. If no account matches, create a supporting account holding the resolved master keys and their origins, then record the index. Its `mweblimitedaccount` wallet record restricts discovery to explicitly registered indices across reload and rescan; it is inactive, has no lookahead, and does not automatically register reserved change/peg-in addresses. Repeated indexed imports preserve existing records, index progress and private keys. Two different master spend keys sharing a scan key form different accounts. Importing an explicit `mweb(a,B,*)` account later promotes the matching supporting account to ordinary full discovery, preserving its identity and registered indices. Backups of the wallet database preserve the discovery restriction; explicitly importing its exported wildcard account descriptor opts into full discovery.
- LIP two-arg: apply priv/pub table; the second key is the subaddress spend key (unless it is an extended key; see [Relationship to the LIP-0008 draft](#relationship-to-the-lip-0008-draft)). Each account with the same scan secret and a known `B` is searched for the address: its recorded addresses, then indices below `max(1024, keypool size)` and a keypool-sized band around its next index. On a match the address is recorded on that account at that index. Otherwise the import is kept as a separate single-address entry, reusing an existing entry for the same address; watch-only entries use the `mwebscank` scan secret.
- Private spend keys and accounts: when the account that derives the address holds `B` but not `b`, and the import carries a private spend key, the account's master spend key is recovered (`b = b'` for an indexed import, `b = b_i - H('A' || LE32(i) || a)` for a two-argument one), checked against `B`, and stored with the account, which can then spend from every address. The scan key and one subaddress spend key already determine `b`, so this discloses nothing the import did not. An account whose spend key expression cannot hold a private key (an xpub with a path) refuses such an import.
- Wallets with private keys disabled: as in Bitcoin Core, private keys are refused ("Cannot import private keys to a wallet with private keys disabled"), except the scan argument's own material, the scan key or the root of an xprv scan expression, which a watch-only MWEB wallet needs. A spend argument sharing that root (`mweb(xprv/0h/100h/0h,xprv/0h/100h/1h,*)` or `mweb(xprv/0h/100h/0h,xpub/0h/100h/1h,*)`) parses to the same key set and imports with a warning; the wallet keeps only `a`, and with a hardened spend path it cannot derive the account's addresses or change, so it sees only coins of addresses whose records are imported. Import the account as `listdescriptors` shows it without private keys to watch every address.
- Imported records are tagged user-imported (`MANUAL`, persisted) unless they already carry the keep tag. Records loaded from the wallet are prunable unless a saved tag says otherwise.
- Record checks: an account accepts a record at index `i` only for its own address at `i`, both on import and, when the account's `B` is known at that point, on load. A watch-only or encrypted wallet whose keychain is not loaded yet checks `a*B_i == A_i` instead.
- Internal: compressed pubkeys; matching account checksum; unique `(acct_cksum,i)`. Remapped keys that fail derivation (including onto indices `0`/`1`) are rejected. Honest change/peg-in internals **may** be imported so watch-only wallets can see those UTXOs.

## Reserved stealth indices

| Index | Use |
|-------|-----|
| `0` | Change |
| `1` | Peg-in receive |
| `≥ 2` | User receive |

Applies to ranged accounts that mint indices. Single-subaddress entries and limited supporting accounts do not allocate from this scheme. User-facing `getnewaddress(mweb)` allocates from index `2` upward on the active full account. Indices `0` and `1` are initialized when a full account is first set up or a supporting account is promoted by explicit wildcard import.

## Multiple accounts

Multiple accounts allowed (ranged, indexed-master, and single-subaddress). Active **ranged** account mints new indices. Coins on other accounts remain usable when keys allow. Change goes to the active account; see [Change and peg-in routing](#change-and-peg-in-routing).

Scan-secret identity is the join key when importing LIP two-arg against existing accounts.

**Active account (L1 parity):** Exactly one MWEB account descriptor is **active** at a time. `getnewaddress(mweb)` mints indices on the active account only. `createwalletdescriptor('mweb')` or `importdescriptors` with `"active": true` switches which account is active. UTXOs on **inactive** accounts remain `IsMine` and spendable; coin selection and change routing across accounts are specified in [Spending across accounts](#spending-across-accounts).

## Spending across accounts

A wallet holds multiple MWEB accounts whenever an account has been imported (recovery, merging funds from another wallet) or after `encryptwallet` rotates the seed (see [Wallet encryption](#wallet-encryption)). Spending must work over the union of all spend-capable accounts; a user with sufficient total balance must never be unable to pay merely because the balance is split across accounts.

### Protocol basis

MWEB transaction signing is **per input**: each spent coin signs with its own per-output spend key, and the transaction balance proof aggregates per-coin blinding factors (`TxBuilder::BuildTx`). Nothing in the protocol requires all inputs of a transaction to derive from the same account. Combining inputs from different accounts in one transaction is therefore valid; the only decision the wallet must make is where change goes.

Because default selection consolidates small coins, tests that need a large leafset must create it explicitly (for example many peg-ins to distinct addresses) rather than relying on default spends.

### Spendable set

A coin is **selectable** when all of the following hold:

| Condition | Meaning |
|-----------|---------|
| Confirmation window | Depth within the requested `min_depth` / `max_depth` (unconfirmed only when explicitly allowed) |
| Not already spent | Not consumed by a wallet transaction (confirmed or pending) |
| Spend-capable account | The coin's account has spend material resolvable when unlocked |

Coins belonging to **watch-only** accounts (`mweb(a,B,*)` or single-subaddr `mweb(a,B_i)`) are shown in balances and `listunspent`. They are selectable only when building an **unsigned PSBT** (`walletcreatefundedpsbt`, `send`/`sendall` with `psbt=true`), for a signer that holds the spend secret; see [psbt.md](psbt.md). Signed sends never select them. When a signed spend fails because the selectable balance is insufficient but watch-only funds would cover it, the error must say so explicitly rather than reporting a generic insufficient-funds failure.

### Selection algorithm

Many MWEB-capable wallets track only a single master key. Selection therefore **drains non-active accounts first**, so a wallet holding imported or pre-encryption accounts converges over time to funds held solely under the active account (change routing, below, reinforces this). Combining inputs from different accounts carries no on-chain linkage cost — MWEB senders, receivers, and amounts are confidential — so account priority exists purely for key-management convergence, not privacy.

**Account priority for the candidate pool:**

1. Coins from **non-active** spend-capable accounts (pooled together).
2. Coins from the **active** account are added only when non-active coins cannot fulfill the remaining requirement.

**Fee model (kept, Litecoin-compatible):**

MWEB weight prices *state growth*, not data processed: outputs weigh `18`, kernels `2`–`3` plus peg-out script bytes, and **standard inputs weigh `0`** (`Weight::CalcInputWeight` counts only optional input extra data, which wallet-built inputs never carry). The required fee is a flat `100 sat × mweb_weight` plus the L1 byte fee for any peg components (see [weight.md](weight.md)). Consequences the selection algorithm exploits:

- Adding inputs does **not** increase the required fee; spending inputs *shrinks* the global UTXO leafset (spent leaves are pruned), so consuming many coins is free for the user and beneficial for the network.
- The only fee reduction input selection can achieve is **eliminating the change output** (saves `18` weight = `1,800` sat and one permanent leafset entry).

**Default algorithm (consume small coins; prefer changeless):**

Define two targets from the recipients and the kernel weight:

| Target | Meaning |
|--------|---------|
| `target_nc` | Recipient amounts + kernel fee for a transaction **without** a change output |
| `target_c` | The same **with** a change output: `target_nc + 1,800 sat` (one standard output's weight fee) |

1. Sort each account-priority tier ascending by amount; tiers are consumed in priority order (all non-active coins, smallest first, before any active-account coin).
2. Accumulate coins **smallest-first** until the running total is `≥ target_nc`. If the pool (or the per-transaction input bound, below) is exhausted first, the spend fails with insufficient funds.
3. **Changeless window:** if the total is `≤ target_c`, build the transaction **without a change output** — the entire excess (`total − recipient amounts`) is committed as kernel fee. By construction this fee is never more than the user would have paid on the with-change path.
4. Otherwise (`total > target_c`), build with a change output worth `total − recipient amounts − fee_with_change`.

Because the two windows are adjacent (`target_c = target_nc + 1,800`), every accumulation lands in exactly one of them — the outcome is fully **deterministic** with no randomized branch-and-bound. The overshoot at the crossing step is strictly smaller than the smallest unselected coin, so wallets holding small coins converge naturally onto changeless transactions.

Properties: maximizes inputs consumed per spend (free under the fee model; maximal leafset pruning), deterministic for a given coin set, and changeless whenever the coin distribution allows.

**Input bound:** the wallet caps a transaction at the relay limits, `MAX_STANDARD_MWEB_TX_INPUTS` (1,000 inputs) and `MAX_STANDARD_MWEB_TX_WEIGHT` (4,000 MWEB weight); see [weight.md](weight.md#relay-limits-policy-non-consensus). A transaction above either limit is consensus-valid but non-standard, so default nodes would neither relay nor mine it from the mempool. If a spend needs more inputs than the cap, selection fails (or, in the mixed MWEB+L1 path, the remainder is funded from L1); consolidate first with smaller spends.

**@todo (source):** the selector still bounds inputs at the consensus maximum `mw::MAX_NUM_INPUTS` (50,000) and does not check the relay weight limit. Litecoin's wallet does not enforce the relay limits either.

**No separate minimum-fee mode:** the MWEB fee is flat per weight unit and inputs are weightless, so no confirmation-target or input-count choice can lower it. The only available saving — dropping the change output — is already attempted by the default algorithm on every spend.

**Explicit change destination:** if the caller sets a change address via coin control, the changeless window is skipped and the with-change path is used.

**Manual selection:** coin control may specify any set of coins from any accounts explicitly; the wallet honors it (subject to the spendable-set rules above).

### Change and peg-in routing

| Output | Destination |
|--------|-------------|
| Change | **Active** account, index `0` |
| Peg-in received coin | **Active** account, index `1` |

Change always routes to the active account regardless of which accounts funded the inputs. This is L1 descriptor-wallet parity (change goes to the active change descriptor, not back to the funding descriptor) and it implements post-encryption fund migration: after `encryptwallet`, every spend of pre-encryption coins moves the remainder onto the new, never-stored-plaintext account.

**Fallback:** if the active account cannot produce a change address (its keychain has no spend public key), change routes to the account contributing the largest MWEB input amount among those that can produce one. Separate single-address entries and limited supporting accounts never automatically produce change addresses: they recognise only their registered addresses, so change derived at an unregistered reserved index would go undetected. A wallet whose only spend-capable MWEB keys are such entries therefore cannot make a signed MWEB spend that needs automatically routed change ("Failed to retrieve change stealth address") until it has a full account that can produce one. An explicitly supplied change destination remains supported.

**Which entry owns a coin:** a separate single-address entry and an account can both recognise one address (for example when the entry was imported before the account, or the account derives the address beyond the import search window). The wallet then attributes the coin to the first entry in a fixed order: entries that hold spend material first, then accounts, then by descriptor id. The order is re-evaluated when the coin is used, so a coin attributed while locked moves to the spend-capable entry after unlock; the coin's index is then taken from the entry that owns it, never carried over from the one that first found it.

An active account whose spend key is held elsewhere, by an external signer or a PSBT signer, receives change like any other active account. This is intended: a local scan key paired with an externally held spend key is a normal configuration, and the signer that holds the spend key spends that change.

**Rejected alternative — change back to the funding account:** this would preserve per-account balance separation, but it breaks the post-encryption migration property (funds would remain on the pre-encryption seed indefinitely) and diverges from L1 change semantics. Users who need strict account separation can achieve it with coin control.
### Restrictions

- Spending requires the wallet to be **unlocked**: spend material for every selected coin is resolved from the owning account's keychain at signing time.
- All-watch-only wallets cannot sign MWEB spends (no spend secret). They fund unsigned PSBTs for an external signer instead.
- One transaction produces a single MWEB change output at most; there is no per-account change splitting.

Litecoin comparison: released Litecoin Core (0.21) has exactly one implicit MWEB account, so none of this section applies there. Litecoin Core's 24.x branch uses descriptor wallets with one active external MWEB descriptor (spend key `m/0'/100'/1'`) and a separate active internal (change) descriptor that shares the scan key and uses spend key `m/0'/100'/2'`; this tree instead sends change to index `0` of the active account. This is an intentional fork extension; on-chain transaction structure is unchanged and fully compatible. To recover a Litecoin seed, import `mweb(<xprv>/0'/100'/0',<xprv>/0'/100'/1',*)` as the active account; for a 24.x wallet's change, also import `mweb(<xprv>/0'/100'/0',<xprv>/0'/100'/2',*)` inactive and run `mwebrescan` with its checksum. `mweb_wallet_recovery.py` checks the addresses against Litecoin Core 0.21.4 and recovers coins on both accounts.

## Wallet encryption

`encryptwallet` on a previously unencrypted wallet keeps upstream Bitcoin Core semantics: a **new random seed** is generated and fresh active descriptors — including a **new MWEB account** — are created from it, because every key that existed before encryption sat unencrypted on disk at some point. No funds move.

Continuity guarantees after encryption:

| Guarantee | Mechanism |
|-----------|-----------|
| Pre-encryption MWEB coins remain visible and spendable | Old account descriptor and its internal descriptors remain in the wallet (encrypted); all accounts are scanned and spend-capable |
| Payments to previously handed-out addresses are still detected while locked, including after a restart | The `mwebscank` record and the old account's internal descriptors |
| New receive / change / peg-in addresses use only the new account | Active-account routing (above) |
| Funds migrate to post-encryption keys over time | Change from any spend routes to the active (new) account |

A wallet loaded while locked scans and issues MWEB addresses; see [Wallet storage of secrets](#wallet-storage-of-secrets) for the records this relies on and the checks on them.

**Backup implication:** a backup taken before encryption cannot recover post-encryption funds. Take a fresh backup after encrypting (as the `encryptwallet` RPC instructs). Seed-only recovery restores only that seed's account; the wallet file is the authoritative backup.

**Litecoin deviation (documented):** released Litecoin Core (0.21) skips seed rotation on encrypt entirely to avoid MWEB key-management complexity (single-account wallet), and keeps its scan secret in plaintext so it can scan while locked. Litecoin Core's 24.x branch rotates the transparent descriptors but keeps the existing MWEB descriptors, whose scan key is stored in plaintext inside the descriptor string. This fork keeps upstream rotation and instead supports multiple accounts with the continuity guarantees above. On-chain behavior is unaffected.

## Wallet lifecycle

### Create (new wallet)

1. Wallet creates ranged account descriptor `mweb(xprv…/0h/100h/0h,xprv…/0h/100h/1h,*)#checksum` in the encrypted keystore.
2. Reserved indices `0` (change) and `1` (pegin) are derived and persisted as `mweb(A0,B0,0,acct_cksum)` and `mweb(A1,B1,1,acct_cksum)`.
3. No chain scan is required (no prior history assumed).
4. Keypool top-up extends the account's range to `next_index + -mwebkeypool` and watches those indices in memory (the [lookahead window](#normal-block-connected-scan)); it persists no internal descriptors for them.

### Receive address (`getnewaddress(mweb)`)

1. Account keychain loaded (scan secret and spend public key); the spend secret is not needed. Per-index spend keys `b_i` are stored on the next unlock.
2. Choose next stealth index `i` (≥ 2 for user receive) on that account.
3. Derive `(A_i, B_i)` via DKSAP from scan/spend masters.
4. Persist `mweb(A_i,B_i,i,acct_cksum)`.
5. Return encoded `mweb1…` / `tmweb1…` for use with `sendtoaddress`.

### Export (`listdescriptors`)

Public export lists:

- Each account in the watch-only form `mweb([fp/0h/100h/0h]<scan WIF>,[fp/0h/100h/1h]<spend pubkey hex>,*)`: the scan secret as WIF and the spend master as a plain public key, both with key origins. A hardened spend path under an xpub would hide the spend public key, so the account is not exported that way. An account whose spend public key is unknown is exported in its stored form `mweb(xpub/0h/100h/0h,xpub/0h/100h/1h,*)` (`src/wallet/export.cpp`).
- All wallet-internal `mweb(A_i,B_i,i,acct_cksum)` descriptors.

Public export does **not** list:

- Private KEY material.

Private export (`listdescriptors true`, unlocked) may include private KEY material on accounts.

### Import watch-only

Import the public export form into a `disable_private_keys` wallet:

```json
[
  { "desc": "mweb([fp/0h/100h/0h]<scan WIF>,[fp/0h/100h/1h]<spend pubkey hex>,*)#checksum", "timestamp": 0, "active": true }
]
```

The account works end to end without any internal descriptors: `getnewaddress(mweb)` mints receive addresses, received coins and change appear in balances and `listunspent`, and `walletcreatefundedpsbt` / `send` / `sendall` with `psbt=true` fund unsigned PSBTs for a signer that holds the spend secret ([psbt.md](psbt.md)). The key origins are kept verbatim, so a signing device's own account (for example `[fp/1000'/1000'/0'/0']` and `[fp/1000'/1000'/0'/1']`) imports the same way. `listdescriptors` exports the descriptor as imported.

The checksum of this form differs from the account checksum that internal descriptors reference. Importing an internal descriptor requires a matching account whose `acct_cksum` equals the internal descriptor’s checksum; a watch-only account needs none.

With the scan secret embedded in the account descriptor, the wallet can DKSAP-rewind outputs and surface them in `listunspent`. Like every account, it watches the subaddresses it has handed out and a lookahead window past them while scanning blocks (see [Normal block-connected scan](#normal-block-connected-scan)), so coins paid to addresses the signing device handed out are found as they are mined; coins paid further out are found with `mwebrescan` or `mwebscanutxoset`. A fully public `mweb(A,B,*)` imports only into a wallet that already holds `a`.

Imported internal descriptors are tagged `MANUAL` (persisted) and are never removed by automatic pruning. `mwebkeep <index> false` clears the tag, after which the record is prunable like any other.
### Import account (recovery)

Import a ranged account descriptor with private keys:

```json
{ "desc": "mweb(<xprv>/0h/100h/0h,<xprv>/0h/100h/1h,*)#checksum", "timestamp": …, "active": true }
```

Additional account imports are allowed after wallet creation. Each import adds a new account descriptor with its own `#checksum` and triggers a **stealth-index chain scan** scoped to that account (see [Scanning](#scanning)). Internal descriptors are created **lazily** — only for indices where chain activity (receive or spend) is found, using that account's `acct_cksum`.

### Prune

Automatic pruning of excess internal descriptors is **conservative**. An internal descriptor is eligible for pruning only when **all** of the following hold:

| Condition | Meaning |
|-----------|---------|
| Spent | All MWEB UTXOs associated with that `(acct_cksum, i)` have been spent |
| Not protected | Descriptor is not tagged `keep`, not manually added, and not reserved (indices `0` / `1` are never auto-pruned) |
| Inactive | No further receive or spend activity at that index within the inactivity timeout |
| Over capacity | Total stored internal descriptors exceeds the MWEB descriptor threshold |

If any condition fails, the descriptor is retained.

**Configurable parameters** (wallet args; defaults chosen at implementation time, aligned with `-keypool` scale):

| Parameter | Purpose | Suggested default |
|-----------|---------|-------------------|
| `-mwebdescriptorthreshold` | Internal descriptor count above which pruning may run | `1000` (same scale as `-keypool`) |
| `-mwebdescriptorinactivity` | Seconds without activity before an index is prune-eligible | `7776000` (90 days) |

Pruning removes the internal descriptor record only. Transaction history (`mweb_coin` records) is retained. A full wallet with the matching account keys can re-derive pruned indices during `mwebrescan`. Watch-only wallets cannot.

### Rescan (`mwebrescan`)

Re-examine chain history for MWEB outputs using ephemeral private derivation over a window of indices, scoped to a specified account (`acct_cksum` or account descriptor). Internal descriptors are **re-added only when a matching output or spend is found** — rescan does not pre-populate the wallet with unused indices.

### UTXO-set scan (`mwebscanutxoset`)

Enumerate unspent MWEB outputs from active chainstate at tip (leafset + PMMR), run DKSAP rewind against wallet keys, and persist matching coins into the wallet. This restores **balance and spend capability** without walking extension blocks — the same role L1 `scantxoutset` plays for transparent outputs.

Use when:

- Recovering MWEB balance on an AssumeUTXO snapshot node after a successful `loadwallet` / restore (AttachChain does **not** auto-scan; load may fail until pre-snapshot L1 blocks are on disk). Prefer bare `mwebscanutxoset` (default import stealth-index window) or an explicit `[acct_cksum] [start_index] [end_index]` range. Snapshot format: [store.md — AssumeUTXO MWEB section](store.md#assumeutxo-mweb-section).
- Importing an MWEB account when block history is unavailable but chainstate at tip is trusted (`importdescriptors` runs the same UTXO-set scan automatically).

Does **not** populate transaction history; run `mwebrescan` after background sync when blocks are available. A bare call registers ephemeral stealth indices for every MWEB account using the default import window (at least indices `0..1000`, or keypool size if larger). Optional `[acct_cksum] [start_index] [end_index]` uses an explicit window instead. High indices above the scanned window require a wider explicit range or block-scan gap discovery.

## Scanning

### Normal block-connected scan

When a new block arrives, the wallet checks the MWEB extension block against, for each account:

- every index with a stored `mweb(A_i,B_i,i,acct_cksum)`;
- the **lookahead window**: the unused indices from `next_index - -mwebkeypool` up to the larger of the account's range end and `next_index + -mwebkeypool`. Unlike L1, which keeps every derived script, indices more than one window below `next_index` that were never used are dropped, so memory stays bounded however far the account has moved.

The lookahead works like L1's keypool lookahead, where `-keypool` scripts past the last used one are watched. Another copy of the keys (a signing device, a second wallet, a newer backup) may have handed out addresses this wallet never did; a payment to one of them is found as soon as it is mined. A payment at index `i ≥ next_index` moves `next_index` to `i + 1` and the window with it, as an L1 payment to a lookahead script does; the block's other outputs are then checked again, so a payment the moved window reaches is found whatever its position in the block. The paid address also gets a receive entry in the address book, as L1 receive addresses found in a block do.

`-mwebkeypool=<n>` sets the window size per account; it defaults to the `-keypool` value (`1000`). The window is held in memory only: it is derived again when the wallet loads, and only indices that see activity get an internal descriptor. A smaller window uses less memory and work but misses payments to addresses more than `n` past the last used one, until `mwebrescan` or `mwebscanutxoset` finds them. `keypoolrefill <n>` raises the account's range end to `next_index + n`, which widens the window up to it.

Single-address and indexed descriptors have no window; they cover exactly their one address.

Output identification uses the `B_i → (acct_cksum, i)` map built from internal descriptors and the window, and DKSAP rewind per [Output Identification](stealth-addresses.md#output-identification).

**Cost.** Unlike an L1 script lookup, recognising an MWEB output costs an elliptic curve multiplication per output and account (the view tag check); the window size does not change it, since the window is a map lookup after the shared secret is known. The view tag rejects about 255 of 256 foreign outputs, so the remaining per-output work is rare. The view tag checks run in chunks of 256 outputs spread over up to 8 threads (`src/mweb/mweb_output_match.cpp`); for new blocks and `rescanblockchain` they run before the wallet lock is taken, while `mwebrescan`, `mwebscanutxoset` and block disconnection run them under it. `bench_bitcoin -filter=MWEBOutputMatch.*` measures them: about 19 µs per output on one thread.

### Account import scan

When importing `mweb(a,b,*)`, the wallet sequentially derives `(A_i, B_i)` for increasing `i` on **that account** and searches the chain.

The default scan bound matches HD `importdescriptors` when `range` is omitted: **`m_keypool_size`** (wallet `-keypool`, default **`1000`**). The phase-1 window is never smaller than **`1000`** indices; a larger `-keypool` or optional `max_index` on import only **raises** the ceiling above `1000`.

#### Phase 1 — indices `0` through at least `1000` (always scanned)

The wallet **always** probes every index from `0` through at least `1000` inclusive (and through `max(1000, m_keypool_size, max_index)` when those exceed `1000`). **Gap limit is not used** in this range — there is no early stop based on consecutive empty indices below the highest active index.

Rationale: the same default depth as HD keypool import; a wallet may have used a high index within the default window without using lower indices.

#### Phase 2 — indices above the phase-1 ceiling (only if needed)

Scanning stops once the last `gap_limit` (`20`) scanned indices had no activity. Otherwise the wallet scans the indices from the ceiling + 1 up to the highest active index plus `max(1000, m_keypool_size)` in one more pass over the blocks, and repeats with the new ceiling. Example: with `-keypool=100` and coins at indices `990` and `1095` only, phase 1 finds `990`, which is within `20` of the ceiling, so a second pass scans `1001..1990` and finds `1095`; `1095` is far below `1990`, so scanning stops. A coin within the [lookahead window](#normal-block-connected-scan) of one already found (here up to `1090`) is found by the same block pass, without another one.

Optional `max_index` on import may raise the phase-1 ceiling above `1000` (never below it); the same rule then applies from that ceiling.

**On activity at index `i`:** persist `mweb(A_i,B_i,i,acct_cksum)` and update `last_active = i`.

**After scan:** set `next_index` for that account to at least `max(last_active + 1, 2)`.

**Empty gap indices below first funding:** indices `≥ 2` and `< first_funding_index` may be retained briefly after import for gap safety; eligible for pruning later under the [Prune](#prune) rules.

### Rescan window

`mwebrescan` examines, per account:

- **Backward:** pruned indices the wallet no longer holds (ephemeral derive; persist internal descriptor only on match).
- **Forward:** up to `m_keypool_size` indices beyond the highest known index for that account (ephemeral derive; persist only on match).

Rescan must not re-add internal descriptors unless chain activity is found.

## PSBT (MWEB)

Descriptors in LIP-0007 PSBT flows (the full workflow and RPCs are in [psbt.md](psbt.md)):

| PSBT use | Typical `mweb(...)` |
|----------|---------------------|
| Input address descriptor (`PSBT_IN_MWEB_ADDR_DESCRIPTOR`) | The wallet writes `mweb([fp/path]a,[fp/path]B,i)#checksum` for every MWEB input it knows, with the account's key origins. Readers also accept `mweb(a,b,i)`, `mweb(a,b_i)` and `mweb(a,B_i)`. The scan key must be private, as in Litecoin Core; a descriptor without it is an error ("MWEB address descriptor has no scan private key"). A private spend key enables delegated signing by a keyless wallet or `descriptorprocesspsbt` |
| Output stealth / payment | Stealth address bytes or the bech32 address as the payment target |
| Soft watch-only updater | Wallet holds `mweb(a,B,*)` or single-subaddr `mweb(a,B_i)`; fills amount, shared secret / Ke, address descriptor; hardware holds spend |

## RPC surfaces

| RPC | MWEB behavior |
|-----|---------------|
| `getnewaddress("mweb")` | Allocate index on account; persist internal descriptor; return `mweb1…` / `tmweb1…` |
| `listdescriptors` | Public: watch-only account form `mweb([origin]<scan WIF>,[origin]<spend pubkey>,*)` + internals. Private: may include private KEYs |
| `importdescriptors` | Account / indexed / single-subaddr / internal forms; a public scan key only when the wallet holds its scan secret |
| `getaddressinfo` | Litecoin 24.x fields for an MWEB address: no `scriptPubKey`; `ismweb`, `scan_pubkey`, `spend_pubkey`; `solvable` and `desc` when the wallet holds the address's scan secret, `desc` being `mweb([origin]<scan WIF>,[origin]<spend pubkey>,i)` for an account address and `mweb([origin]<scan WIF>,<address spend pubkey>)` for a separate single-address entry or an account without its spend pubkey; `parent_desc` is the account's `listdescriptors` form (the stored public form when the account has no spend pubkey) or the separate entry's `desc`; `hdkeypath` is `x/<index>` with the scan key's `hdmasterfingerprint` |
| `deriveaddresses` | Refuses MWEB descriptors ("deriveaddresses does not support MWEB descriptors") |
| `createwalletdescriptor("mweb",…)` | Creates ranged account descriptor |
| `mwebrescan` | Per-account index-window rescan; lazy descriptor persistence |
| `mwebscanutxoset` | Scan the MWEB UTXO set at the tip for every account (indices 0..1000) or an explicit index window |
| `mwebkeep` | Set or clear the keep tag on an internal descriptor index (prevents pruning) |

## Relationship to DKSAP and bech32 encoding

| Concern | Specified in |
|---------|--------------|
| `(A_i, B_i)` derivation from masters | [stealth-addresses.md](stealth-addresses.md) |
| Master key paths `m/0'/100'/0'`, `m/0'/100'/1'` | [stealth-addresses.md](stealth-addresses.md) |
| Output construction and identification | [stealth-addresses.md](stealth-addresses.md) |
| Bech32 `mweb` / `tmweb` encoding (includes both pubkeys) | [stealth-addresses.md](stealth-addresses.md) |
| Descriptor storage, export, scan policy | This document |

The bech32 address carries the public pay-to material `(A_i, B_i)`. DKSAP mathematics are unchanged.

### Why bech32 (not bech32m)

MWEB stealth addresses use **bech32** encoding under the `mweb` / `tmweb` HRP, not bech32m. See [stealth-addresses.md](stealth-addresses.md#address-encoding-zorkcoin): the payload has a single fixed length (66 bytes), so Bech32's insertion/deletion weakness, which motivated bech32m for variable-length witness programs, does not apply.

## Explicit non-goals

- Ranged `mweb(xpub/…/*)` receive descriptors that pretend to enumerate stealth addresses from public material alone (cannot work for DKSAP).
- `mweb_scan()` as a separate descriptor type.
- A side-channel `mweb_scan_secret` import field (scan enters as the first `KEY`).
- A descriptor form of a payment address; MWEB addresses are written in bech32.
- Internal/external BIP32 chain mirroring (`/0` vs `/1`) for MWEB.
- xpub-only enumeration of future stealth receive addresses.
- Backward compatibility with legacy `mweb(xpub/0h/100h)` or `mweb(xpub/100h/0h/0h/0/*)` descriptors.

## Grammar

```
mweb_desc :=
    "mweb(" KEY "," KEY ",*)" |
    "mweb(" KEY "," KEY "," index ")" |
    "mweb(" KEY "," KEY ")" |
    "mweb(" compressed_pubkey "," compressed_pubkey "," index "," acct_cksum ")"

index              := "0" | nonzero_digit *digit, at most 2147483647
acct_cksum         := 8-character descriptor checksum alphabet
compressed_pubkey  := compressed secp256k1 pubkey in hex
```

No whitespace. Type constraints as in [Forms](#forms).

## Examples

Ranged account (private, unlocked wallet):

```
mweb(tprv8ZgxMBicQKs…/0h/100h/0h,tprv8ZgxMBicQKs…/0h/100h/1h,*)#qj8x4s2a
```

Watch-only account (scan private, spend public), as exported by public `listdescriptors`:

```
mweb([d34db33f/0h/100h/0h]cNWR3ndNdXDQ…,[d34db33f/0h/100h/1h]0379fb6de6ab…,*)#…
```

Wallet internal (public export):

```
mweb(02ef01…,03abcd…,2,qj8x4s2a)#k7m2p9w3
```

Single subaddress with a public scan key `A = a·G` (imports only into a wallet that holds `a`):

```
mweb(02ef01…,03abcd…)#n4r8t1x5
```

Encoded pay-to address for `sendtoaddress` (testnet/signet/regtest HRP `tmweb`):

```
tmweb1qqfj00qqzxhsqmy83ukuh4hkqkghkfm05lccrmzqczthwnx2qnv9mqqaypwaxzn76kv9kc8d37rgr9kt5vkxp5vllaeksjhl03ug3m3gm8vf4epvr
```

Mainnet addresses use HRP `mweb` and look like `mweb1…`.
