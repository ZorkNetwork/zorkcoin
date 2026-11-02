# ZORK-AUXPOW-001: Kaspa KHeavyHash Auxiliary Proof of Work

**Status:** Draft (revised 2026-09-28)
**Type:** Consensus
**Layer:** Consensus / Mining
**Title:** Kaspa KHeavyHash Auxiliary Proof of Work for Zorkcoin
**Author:** Zorkcoin Contributors
**Created:** 2026-07-29
**Updated:** 2026-09-28
**License:** BSD-2-Clause
**Requires:** Zorkcoin base consensus, Kaspa-compatible KHeavyHash / peer-header validation
**Replaces:** None

## Abstract

This specification defines a Kaspa-based Auxiliary Proof-of-Work (“AuxPoW”) mechanism for Zorkcoin.

The mechanism is modeled on Dogecoin-style merged mining: a Zorkcoin block header is cryptographically committed into a **peer-chain** (Kaspa) mining object before proof-of-work is performed, and the completed peer proof is included in the Zorkcoin **block header** as `CAuxPow` (the AuxPoW header extension).

**Terminology:** Kaspa is a **peer** proof-of-work format, not a “parent” chain. Zorkcoin does not subordinate consensus to Kaspa blockDAG acceptance. “Peer” describes the external header/coinbase format used as the AuxPoW header extension (`CAuxPow`). The AuxPoW data is always called the **AuxPoW header extension** (or `CAuxPow` / `ZorkKaspaAuxPow`), following Dogecoin.

Kaspa-format KHeavyHash is used to validate the peer proof. A qualifying proof MUST satisfy **both**:

1. **Zorkcoin Floor Mode:** the peer PoW hash is at least **4× harder** than the ordinary native Zorkcoin ASERT target for that height (encoded in the Zorkcoin header’s `nBits`); and
2. **Kaspa-Derived Mode:** the peer PoW hash is at least **3,000× harder** than the ordinary Kaspa target declared in the submitted Kaspa peer header’s `bits` field.

Equivalently, with \(T_Z\) the target decoded from the Zorkcoin header `nBits` and \(T_K\) the target decoded from the Kaspa peer header `bits`:

\[
h_{\mathrm{PoW}}
\le
\left\lfloor
\frac{T_Z}{4}
\right\rfloor
\quad\text{and}\quad
h_{\mathrm{PoW}}
\le
\left\lfloor
\frac{T_K}{3000}
\right\rfloor
\]

The proof is self-contained. Zorkcoin nodes SHALL NOT require proof that the submitted Kaspa block was accepted into the Kaspa blockDAG, is part of Kaspa’s selected chain, remains available from Kaspa nodes, or remains available after Kaspa pruning.

The submitted proof SHALL instead demonstrate locally that:

1. the Kaspa peer header is structurally valid for the pinned Kaspa format;
2. the Kaspa peer header declares a valid Kaspa compact target;
3. the peer KHeavyHash result satisfies the ordinary Kaspa target \(T_K\);
4. the peer KHeavyHash result satisfies the Kaspa-derived auxiliary target \(\lfloor T_K/3000\rfloor\);
5. the peer KHeavyHash result satisfies the Zorkcoin floor target \(\lfloor T_Z/4\rfloor\);
6. a Kaspa coinbase transaction is cryptographically committed by the Kaspa peer header;
7. a Kaspa coinbase transaction is committed by the peer header merkle root;
8. the coinbase `extra_data` commits to an **auxiliary-chain merkle root** (multi-chain merged-mining tree), Dogecoin-style;
9. the Zorkcoin pure-header hash is a leaf of that aux-chain merkle tree at the declared index; and
10. that header hash binds the Zorkcoin transaction set and coinbase payout (via the Zorkcoin header merkle root).

This design avoids requiring Zorkcoin to store hundreds of Kaspa block headers per Zorkcoin block. A single exceptionally low KHeavyHash result serves as a compact statistical proof.

---

## Mathematical Notation and Rendering

This specification uses Markdown with a LaTeX mathematics extension. Mathematical expressions are normative where they appear in consensus rules.

* Inline mathematical expressions SHALL be delimited by a single dollar sign on each side: `$...$`.
* Display mathematical expressions SHALL be delimited by `\[` and `\]`, with each delimiter on its own line.
* Renderers used to produce HTML, PDF, or other presentation formats SHALL support these LaTeX math delimiters.
* Literal LaTeX source SHALL NOT be interpreted as ordinary prose.
* Markdown setext-heading underline syntax (`===` or `---`) SHALL NOT be used inside a mathematical display block.

## 1. Motivation

Kaspa produces blocks at approximately ten blocks per second, while Zorkcoin targets a block interval of approximately 131 seconds (`nPowTargetSpacing = 1<<17` ms).

If Zorkcoin attempted to accumulate and directly include all Kaspa work associated with a Zorkcoin mining session, an AuxPoW proof could require hundreds or thousands of Kaspa block headers. Such a design would impose excessive block-size, storage, bandwidth, and validation costs.

This specification replaces explicit accumulation of many ordinary Kaspa blocks with a compact statistical proof of work, while ensuring AuxPoW is never cheaper than native Zorkcoin mining.

Under this specification, a Kaspa-format proof is accepted only when both floor and Kaspa-derived checks pass. Ordinary Kaspa-valid hashes SHALL NOT normally qualify as Zorkcoin blocks.

AuxPoW is an **optional alternate mining path**. Native Zorkcoin KHeavyHash mining remains first-class forever. Miners MAY choose either path per block.

---

## 2. Scope

This specification defines:

* the Zorkcoin Kaspa AuxPoW consensus model;
* Dogecoin-derived wire and commitment patterns adapted to Kaspa;
* the required cryptographic bindings;
* the logical AuxPoW header-extension structure;
* dual target derivation (Floor + Kaspa-Derived);
* proof validation;
* ASERT interaction;
* replay prevention;
* consensus failure conditions;
* estimated proof-size requirements; and
* implementation requirements.

This specification does not define:

* Kaspa consensus;
* Kaspa difficulty adjustment;
* Kaspa blockDAG acceptance;
* Kaspa selected-parent selection;
* Kaspa transaction validity beyond coinbase structure needed for the commitment proof;
* Kaspa mining-pool protocols;
* Zorkcoin ordinary native proof-of-work algorithms (except how AuxPoW relates to them); or
* Zorkcoin block subsidy and reward policy.

---

## 3. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 3.1 Kaspa Peer Proof

A Kaspa-format block header and associated transaction-commitment evidence, carried in the AuxPoW header extension as the external proof of work.

Kaspa is a **peer**, not a parent. Zorkcoin does not require the submitted proof to be accepted by Kaspa consensus.

### 3.2 Zorkcoin Auxiliary Block

A Zorkcoin block whose proof-of-work is satisfied through a valid `ZorkKaspaAuxPow` AuxPoW header extension (Zorkcoin header AuxPoW version flag set).

### 3.3 Native Zorkcoin Target

The proof-of-work target encoded in the Zorkcoin block header’s `nBits` field for the block’s height, as produced by ASERT (`GravityAsert`) for ordinary native mining:

\[
T_Z=\operatorname{DecodeCompact}(\texttt{zork.nBits})
\]

### 3.4 Kaspa Peer Target

The proof-of-work target encoded in the submitted Kaspa peer header’s `bits` field:

\[
T_K=\operatorname{DecodeKaspaCompact}(\texttt{peer\_header.bits})
\]

The target SHALL be obtained from the submitted Kaspa peer header. It SHALL NOT be supplied independently by the miner as a separate AuxPoW field.

### 3.5 Zorkcoin Floor Target (Floor Mode)

\[
T_{\mathrm{Floor}}
=
\left\lfloor
\frac{T_Z}{4}
\right\rfloor
\]

AuxPoW MUST be at least **4×** the work required by native Zorkcoin at the same height.

### 3.6 Kaspa-Derived Auxiliary Target

\[
T_{\mathrm{KD}}
=
\left\lfloor
\frac{T_K}{3000}
\right\rfloor
\]

### 3.7 Effective AuxPoW Target

\[
T_{\mathrm{Aux}}
=
\min(T_{\mathrm{Floor}},\,T_{\mathrm{KD}})
\]

A proof MUST satisfy \(h_{\mathrm{PoW}}\le T_{\mathrm{Floor}}\) **and** \(h_{\mathrm{PoW}}\le T_{\mathrm{KD}}\) (equivalently \(h_{\mathrm{PoW}}\le T_{\mathrm{Aux}}\)).

### 3.8 Compact Targets / `nBits` Fields (Important)

There are **exactly two** compact-target fields involved:

| Field | Location | Role |
| --- | --- | --- |
| `nBits` | Zorkcoin 88-byte block header | ASERT native target \(T_Z\) for this height. Floor check uses \(T_Z/4\). |
| `bits` | Kaspa peer header (inside AuxPoW header extension) | Declared Kaspa target \(T_K\). Kaspa-derived check uses \(T_K/3000\). |

There is **no third** AuxPoW-only `nBits` field in the AuxPoW header extension. The “3000× Kaspa difficulty” value is **derived** at validation time from `peer_header.bits`; it is not stored separately.

### 3.9 Kaspa Coinbase Transaction

The Kaspa transaction containing the miner-controlled commitment payload (`extra_data`) used to bind the Kaspa peer proof to the Zorkcoin block header.

---

## 4. Relationship to Dogecoin AuxPoW

Dogecoin merged-mining (Litecoin peer / parent in Dogecoin docs) is the design template. Zorkcoin follows it unless Kaspa’s format forces a difference.

| Concern | Dogecoin | Zorkcoin Kaspa AuxPoW |
| --- | --- | --- |
| Peer role | Litecoin header + coinbase | Kaspa peer header + coinbase |
| Flag in child header | `nVersion` bit 8 (`0x0100`) | Same pattern: AuxPoW bit in Zorkcoin `nVersion` |
| Chain ID | Upper 16 bits of `nVersion` | **Differs:** locked AuxPoW `nNonce` (`'AuxPoW' << 16 \| chain_id`), so the `nVersion` upper bits stay with BIP9 |
| Header extension | `CAuxPow` after 80-byte hashed fields (header-bearing P2P included) | `CAuxPow` after 88-byte hashed fields (header-bearing P2P included) |
| Child leaf | `hash(child pure header)` | `hash(Zorkcoin pure header)` |
| Multi-chain tree | `vChainMerkleBranch` + `nChainIndex` → `auxMerkleRoot` | **Same** — retained so other chains can share one Kaspa coinbase |
| Coinbase commit | `0xfabe'mm'` + `auxMerkleRoot` (+ size / chain-id fields) in peer coinbase `scriptSig` | Same logical record in Kaspa coinbase **`extra_data`** (Kaspa has no Bitcoin-style coinbase `vin`) |
| Tx inclusion | `vMerkleBranch` coinbase → peer `hashMerkleRoot` | Merkle proof coinbase → Kaspa `hash_merkle_root` |
| Template / payout binding | Implicit via child header merkle root | Same |
| PoW checked | Peer PoW ≤ **child** `nBits` target | Peer PoW ≤ \(\lfloor T_Z/4\rfloor\) **and** ≤ \(\lfloor T_K/3000\rfloor\) |
| Child `nNonce` | Not the PoW nonce when AuxPoW | Same, and locked to the marker and chain ID; PoW nonce lives in the Kaspa peer header |
| Peer chain sync | Not required | Not required |

### 4.1 Why Keep the Aux-Chain Merkle Tree

Dogecoin’s aux-chain merkle tree lets **many** merge-mined chains share one peer coinbase commitment: each chain’s header hash is a leaf; the coinbase stores only the tree root (plus magic / size / expected chain-id metadata).

Zorkcoin SHALL preserve this structure so pools and other projects can reuse the same Kaspa merged-mining mechanism without a Zork-only one-leaf shortcut. A solo Zork miner MAY still use a trivial one-leaf tree (`nChainIndex = 0`, empty branch); that is a special case of the same rules, not a separate commitment format.

### 4.2 Why Not Reinvent Per-Field Template Commitments

Dogecoin commits to the **entire child pure header** as the aux-tree leaf. That header already commits to previous block hash, merkle root (txs + payout), time, bits, and version.

Zorkcoin SHALL do the same. Separate `zork_template_hash` / `zork_payout_commitment` fields are **not required** for consensus.

---

## 5. Design Goals

1. **Compactness** — approximately one Kaspa peer header + coinbase + tx merkle proof + aux-chain merkle branch.
2. **Permanent Verifiability** — validate from Zorkcoin block data alone.
3. **No Kaspa Historical Dependency** — no archival Kaspa node required.
4. **Pre-Mining Attribution** — aux merkle root in Kaspa coinbase before PoW.
5. **Candidate Binding** — proof usable only for the committed Zorkcoin header leaf.
6. **Multi-Chain Friendly** — Dogecoin-style aux-chain merkle so other projects can share the same Kaspa coinbase commitment.
7. **Never Cheaper Than Native** — Floor Mode enforces ≥4× native work.
8. **Kaspa Rarity** — Kaspa-Derived Mode enforces ≥3000× declared Kaspa target work.
9. **Independent Verification** — every Zorkcoin node computes peer PoW locally.
10. **Optional Forever** — native mining remains valid indefinitely.

---

## 6. Non-Goals

The mechanism does not attempt to prove:

* that the submitted Kaspa block was propagated on the Kaspa network;
* that the submitted Kaspa block was accepted into the Kaspa blockDAG;
* that the submitted Kaspa block became a selected-chain block;
* that the miner performed exactly 3,000 ordinary Kaspa block-equivalents of work;
* that Zorkcoin possesses a specified percentage of Kaspa’s total network security.

Security for Zorkcoin is the absolute work check against \(T_{\mathrm{Floor}}\) (and the additional \(T_{\mathrm{KD}}\) constraint). Kaspa DAG acceptance is irrelevant.

---

## 7. Consensus Parameters

```text
ZORK_AUXPOW_VERSION = 1

ZORK_AUXPOW_FLOOR_MULTIPLIER = 4

ZORK_AUXPOW_KASPA_MULTIPLIER = 3000

ZORK_AUXPOW_HEADER_FLAG =
    (1 << 8)   # nVersion bit; same position as Dogecoin VERSION_AUXPOW

ZORK_AUXPOW_NONCE_MARKER =
    0x576F50787541 << 16   # ASCII "AuxPoW" read little-endian, above the chain ID

ZORK_AUXPOW_CHAIN_ID (uint16, per network; wire bytes of nNonce in quotes) =
    main           0x4b5a   "ZKAuxPoW"
    test/testnet4  0x545a   "ZTAuxPoW"
    regtest        0x525a   "ZRAuxPoW"
    signet         0x535a   "ZSAuxPoW"

ZORK_AUXPOW_EASIEST_KASPA_BITS =
    0x2100ffff   # T_K = 0xffff << 240; informative, the largest target that
                 # decodes (no consensus bound on declared Kaspa bits)

ZORK_AUXPOW_PINNED_KASPA_FORMAT =
    post-Toccata mainnet header/tx rules as implemented in rusty-kaspa
    (Toccata activated mainnet DAA 474_165_565, 2026-06-30)
```

Multipliers are **difficulty** multipliers (divide targets), not target multipliers.

Implementations MUST NOT compute \(T_{\mathrm{Floor}}=4T_Z\) or \(T_{\mathrm{KD}}=3000T_K\).

---

## 8. Zorkcoin Header Flag and Chain ID

Following Dogecoin for the flag, and departing from it for the chain ID:

* Bit 8 of `nVersion` SHALL be set if and only if the header carries a `ZorkKaspaAuxPow` / `CAuxPow` header extension. Bit 8 is the only `nVersion` bit AuxPoW uses; every other bit keeps its native and BIP9 meaning.
* An AuxPoW header's 64-bit `nNonce` SHALL equal `ZORK_AUXPOW_NONCE_MARKER | ZORK_AUXPOW_CHAIN_ID` for the validating network. Any other value is invalid (`auxpow nonce marker mismatch` when the upper 48 bits differ, `auxpow chain id mismatch` when only the low 16 bits differ). Written little-endian, the eight wire bytes read as the two-letter network code followed by `AuxPoW` (for example `ZKAuxPoW` on main).
* **Hashed preimage** (`GetHash()`, `GetPoWHash()`, aux-tree leaf) SHALL be the 88-byte header fields only. The AuxPoW header extension is **not** part of the hash.
* When bit 8 is set, the **wire header** SHALL be those 88 bytes followed by `CAuxPow` (≤ 1280 bytes). Bit 8 without the extension is invalid.
* Header-bearing P2P messages (`headers`, header-sync, compact-block header fields) SHALL include the AuxPoW header extension when bit 8 is set. `CheckAuxPow` SHALL run on that header. Do not skip proof-of-work. Do not index or credit chain work without a verified extension.
* Identity is the 88-byte hash; chain work uses serialized `CAuxPow` size \(S\). A node SHALL pin the first verified extension for a given hash. A later different `CAuxPow` for the same hash is a mutation (`bad-auxpow-mismatch`) and MUST NOT overwrite stored `nAuxPowSize` / `nChainWork`.
* When the flag is clear, the header stays 88 bytes; native PoW rules apply.
* Full block = that header, then `vtx` (then MWEB if present).

`IsAuxPow()` is true iff bit 8 is set.

For AuxPoW blocks, the Zorkcoin header `nNonce` is not the peer PoW nonce (Dogecoin parallel). The solving nonce is in the Kaspa peer header, so locking the Zorkcoin `nNonce` costs the miner nothing. The chain ID feeds `GetExpectedIndex` (see **Aux-Chain Merkle Branch**) from the network parameter; the copy in `nNonce` binds the header itself to one network.

Dogecoin keeps its chain ID in the upper 16 bits of `nVersion`. Zorkcoin does not, because those bits belong to BIP9 signalling and must stay usable for future deployments.

**Version bits.** Bit 8 is reserved:

* no BIP9 deployment SHALL use bit 8;
* bit 8 lies outside the live signalling bits (0–4; this fork applies BIP323 with `VERSIONBITS_NUM_BITS = 5`), so unknown-version warnings never count AuxPoW blocks;
* bit 8 is inside the BIP323 range that mining software may roll as extra nonce, so version-rolling software MUST NOT roll bit 8. Rolling it on a native header produces an invalid header (bit 8 without an extension); flipping any version bit on an AuxPoW header changes the hashed header, so the proof no longer commits to it.

---

## 9. Commitment (Dogecoin-Style Aux-Chain Merkle)

Two merkle linkages are required, matching Dogecoin:

```text
[Zork pure header] --> hashAuxBlock = GetHash(pure header)
            |
            v
   [vChainMerkleBranch + nChainIndex]
            |
            v
      auxMerkleRoot
            |
            v
  [Kaspa coinbase extra_data]  (magic + auxMerkleRoot + tree size / chain-id fields)
            |
            v
   [vMerkleBranch / tx commitment proof, coinbase index 0]
            |
            v
  [Kaspa peer_header.hash_merkle_root]
            |
            v
       KaspaPeerPoW(peer_header)  <=  min(T_Z/4, T_K/3000)
```

### 9.1 Leaf: Zorkcoin Pure Header Hash

\[
\texttt{hashAuxBlock}=\operatorname{GetHash}(\texttt{Zorkcoin pure header})
\]

The pure header is the 88-byte Zorkcoin header **excluding** the AuxPoW header extension (Dogecoin `CPureBlockHeader` parallel).

### 9.2 Aux-Chain Merkle Branch

The AuxPoW header extension SHALL include:

* `vChainMerkleBranch` — sibling hashes from the leaf to the aux-chain merkle root;
* `nChainIndex` — leaf index of this Zorkcoin commitment in the aux-chain tree.

Validation SHALL recompute `auxMerkleRoot` by walking from `hashAuxBlock` at `nChainIndex` through `vChainMerkleBranch`.

The aux-chain tree MAY contain leaves for other merge-mined chains. Zorkcoin only requires that **its** leaf prove up to the root committed in the Kaspa coinbase.

Multi-leaf aux-chain trees are **supported and required to be tested**. Solo remains valid:

* Solo (`h = 0`): empty `vChainMerkleBranch`, `merkle_size = 1`, `nChainIndex = 0`, `auxMerkleRoot == hashAuxBlock`.
* Multi-leaf (`h ≥ 1`): `h = vChainMerkleBranch.size()`. Dummy siblings (hashes that are not a second real chain) are allowed; the walk still uses Bitcoin/Dogecoin `hash256` pairing, not Kaspa merkle.

`merkle_size` MUST equal `1 << vChainMerkleBranch.size()`. `nChainIndex` MUST equal `getExpectedIndex(merkle_nonce, zork_chain_id, h)` (Dogecoin/Namecoin LCG, implemented as `GetExpectedIndex` in `src/auxpow/auxpow.cpp`). A 2-leaf fixture (`h = 1`, `merkle_size = 2`) is a required test vector (see **Required Test Vectors**).

### 9.3 Coinbase Merged-Mining Record (Dogecoin Bytes, in `extra_data`)

Kaspa coinbases use a structured **payload**; miner-controlled bytes live in trailing **`extra_data`**. There is no Bitcoin/Dogecoin coinbase `scriptSig`. The merged-mining record SHALL use **the same magic and field layout as Dogecoin**, placed in `extra_data` instead of `scriptSig`.

Normative record (44 bytes), identical to Dogecoin / Bitcoin wiki merged mining:

```text
offset  size  field
0       4     pchMergedMiningHeader = { 0xfa, 0xbe, 0x6d, 0x6d }   // 'm','m'
4       32    auxMerkleRoot_bytes   // 32-byte root, **byte-reversed** vs internal uint256
                                              // (same endian convention as Dogecoin)
36      4     merkle_size           // uint32 LE; MUST equal 1 << vChainMerkleBranch.size()
40      4     merkle_nonce          // uint32 LE; used with chain ID to expect nChainIndex
```

Validation SHALL (Dogecoin `CAuxPow::check` semantics, applied to `extra_data`):

1. Search `extra_data` for `pchMergedMiningHeader`.
2. Require exactly one occurrence of the magic.
3. Require the following 32 bytes equal the byte-reversed recomputed `auxMerkleRoot`.
4. Read `merkle_size` and `merkle_nonce` as uint32 LE.
5. Require `merkle_size == (1u << vChainMerkleBranch.size())`.
6. Require `nChainIndex == getExpectedIndex(merkle_nonce, zork_chain_id, vChainMerkleBranch.size())`.
7. Reject if `vChainMerkleBranch.size() > 30` (Dogecoin limit).

`getExpectedIndex` is exactly Dogecoin’s function:

```text
int getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1 << h);
}
```

Aux-chain merkle node combination SHALL use **Dogecoin/Bitcoin double-SHA256** parent hashing (not Kaspa `MerkleBranchHash`), so other merge-mined chains can share the same tree tooling.

### 9.4 Payload Location and Size

Kaspa coinbase payload layout (normative for this spec; see **Kaspa Peer Header v2 (Normative, Self-Contained)**):

```text
blue_score (u64 LE)
|| subsidy (u64 LE)
|| script_public_key_version (u16 LE)
|| script_public_key_length (u8)
|| script_public_key_bytes
|| extra_data
```

Kaspa consensus allows `max_coinbase_payload_len = 204` for the **entire** payload. The 44-byte merged-mining record MUST fit in `extra_data` after blue_score/subsidy/script fields. Other chains belong as **leaves** of the aux merkle tree, not as parallel payload blobs.

> `extra_data` SHALL contain exactly one `pchMergedMiningHeader` record. Zero or more than one SHALL invalidate the AuxPoW proof.

### 9.5 Uniqueness

`hashAuxBlock` plus `nChainIndex` plus the committed `auxMerkleRoot` MUST identify one Zorkcoin pure header. A proof that validates two distinct Zorkcoin pure headers SHALL be invalid.

---

## 10. AuxPoW Header Extension Structure

```text
ZorkKaspaAuxPow
{
    uint32 version;                  // = 1

    KaspaBlockHeader peer_header;

    KaspaTransaction coinbase_transaction;

    // Peer tx merkle: coinbase -> peer_header.hash_merkle_root
    TransactionCommitmentProof
        coinbase_commitment_proof;   // Dogecoin vMerkleBranch analogue

    // Aux-chain merkle: hashAuxBlock -> auxMerkleRoot in coinbase extra_data
    vector<uint256> vChainMerkleBranch;
    int32 nChainIndex;
}
```

Use **`peer_header`**, not `parent_header`.

The AuxPoW header extension SHALL NOT contain a separately miner-supplied Kaspa target. Decode \(T_K\) only from `peer_header.bits`.

### 10.1 `peer_header`

SHALL be a Kaspa **block header version 2** (Toccata) as fully specified in **Kaspa Peer Header v2 (Normative, Self-Contained)**, which also gives the PoW and header-hash preimage rules. This document is self-contained; external Kaspa docs are not required for validation.

### 10.2 `coinbase_commitment_proof` (tx merkle)

Prove the supplied coinbase is committed by `peer_header.hash_merkle_root` using the Kaspa transaction-hash + merkle algorithm in **Kaspa Coinbase Transaction (Normative)** and **Proving Coinbase ∈ `hash_merkle_root` (Normative)**.

Coinbase MUST be at transaction index **0**.

`coinbase_commitment_proof` is a vector of 32-byte sibling hashes from leaf to root (Dogecoin `vMerkleBranch` analogue). For a single-transaction peer body, the branch is empty and `hash_merkle_root` MUST equal the coinbase transaction hash.

### 10.3 Auxiliary-Chain Merkle Branch (Required)

`vChainMerkleBranch` and `nChainIndex` are **required** consensus fields, including when the tree has a single leaf.

This preserves Dogecoin multi-auxiliary-chain merged mining so other projects can commit distinct header hashes as sibling leaves under the same Kaspa coinbase `auxMerkleRoot`.

---

## 11. Target Derivation and Validation

### 11.1 Decode Targets

\[
T_Z=\operatorname{DecodeCompact}(\texttt{block.nBits})
\]
\[
T_K=\operatorname{DecodeKaspaCompact}(\texttt{peer\_header.bits})
\]

Both MUST be positive, nonzero, canonically encoded, and within permitted ranges.

### 11.2 Derive Auxiliary Targets

\[
T_{\mathrm{Floor}}=\left\lfloor T_Z/4\right\rfloor
\]
\[
T_{\mathrm{KD}}=\left\lfloor T_K/3000\right\rfloor
\]

If either derived target is zero, the proof is invalid.

### 11.3 Compute Peer PoW

\[
h=\operatorname{KaspaPeerPoW}(\texttt{peer\_header})
\]

### 11.4 Required Inequalities

All MUST hold:

\[
h\le T_K
\]
\[
h\le T_{\mathrm{KD}}
\]
\[
h\le T_{\mathrm{Floor}}
\]

(The first is implied by the second when \(T_{\mathrm{KD}}\) is valid, but SHALL still be checked explicitly.)

### 11.5 Native Header PoW

For AuxPoW blocks, the Zorkcoin header’s own `GetPoWHash()` is **not** required to meet \(T_Z\) (Dogecoin parallel: child header scrypt does not meet child bits; peer PoW does). The AuxPoW bit selects the peer-PoW validation path.

---

## 12. ASERT and Chain Work

### 12.1 ASERT

ASERT (`GravityAsert`) SHALL operate **normally on all blocks**, including AuxPoW blocks. Every block advances height and contributes its timestamp. `nBits` on each new header is the ASERT output \(T_Z\) for that height. AuxPoW validation then applies \(\lfloor T_Z/4\rfloor\).

### 12.2 Chain Work for AuxPoW (Size Penalty)

Native and AuxPoW headers both carry the same ASERT `nBits`. AuxPoW additionally proves ≥4× that work, but **must not** receive 4× chain-work credit (that would bias tip selection toward AuxPoW).

AuxPoW also carries a large header extension relative to a native header. Therefore AuxPoW SHALL receive **slightly less** chain work than a native block at the same `nBits`, via an explicit size discount.

Let \(W=\operatorname{GetBitsProof}(\texttt{nBits})\) be the same function used for native blocks (`GetBlockProof` / `GetBitsProof`).

Let \(S\) be the serialized size in bytes of the `ZorkKaspaAuxPow` / `CAuxPow` header extension (the AuxPoW extension only, not the whole block).

Consensus constants:

```text
AUXPOW_CHAINWORK_REF = 8192
```

\[
W_{\mathrm{aux}}
=
\left\lfloor
W\times
\frac{\texttt{AUXPOW\_CHAINWORK\_REF}}
{\texttt{AUXPOW\_CHAINWORK\_REF}+S}
\right\rfloor
\]

Require \(W_{\mathrm{aux}}\ge 1\) whenever \(W\ge 1\).

Examples at equal `nBits`:

| \(S\) (AuxPoW bytes) | Factor vs native \(W\) |
| ---: | ---: |
| 400 | \(8192/8592\approx 0.953\) |
| 800 | \(8192/8992\approx 0.911\) |
| 1280 | \(8192/9472\approx 0.865\) |

Rationale: AuxPoW is never cheaper in PoW (4× floor), but tip comparison mildly prefers leaner native blocks over maximally bloated AuxPoW header extensions. The 4× extra PoW is **not** added into `nChainWork`.

---

## 13. AuxPoW Validation Algorithm

A Zorkcoin node validating an AuxPoW block SHALL:

1. Require AuxPoW deployment ACTIVE (forced active from genesis on initial networks).
2. Require `IsAuxPow()`, `nNonce == ZORK_AUXPOW_NONCE_MARKER | ZORK_AUXPOW_CHAIN_ID` for this network, and `auxpow.version == 1`.
3. Parse `peer_header` canonically; reject malformed headers.
4. Decode \(T_Z\) from Zorkcoin `nBits` and \(T_K\) from `peer_header.bits`.
5. Compute \(h=\operatorname{KaspaPeerPoW}(peer\_header)\).
6. Require \(h\le T_K\), \(h\le\lfloor T_K/3000\rfloor\), and \(h\le\lfloor T_Z/4\rfloor\).
7. Verify coinbase merkle inclusion against `peer_header.hash_merkle_root`.
8. Compute `hashAuxBlock = GetHash(pure header)`; walk `vChainMerkleBranch` at `nChainIndex` to obtain `auxMerkleRoot`.
9. Locate the magic merged-mining record in coinbase `extra_data`; require embedded root (and size/chain-id checks) match.
10. Validate all ordinary Zorkcoin rules (txs, UTXO, coinbase subsidy, weight, time, etc.). AuxPoW does not bypass them.

---

## 14. Kaspa BlockDAG Acceptance Is Not Required

Zorkcoin SHALL NOT require proof that the submitted Kaspa proof:

* was accepted into the Kaspa blockDAG;
* was included in Kaspa’s selected chain;
* received Kaspa confirmations; or
* remains available after Kaspa pruning.

A Kaspa-format proof MAY be constructed solely for Zorkcoin. This is intentional.

---

## 15. Replay and Reuse Prevention

Dogecoin-style aux-chain commitment binds the Zork pure header as a leaf under `auxMerkleRoot` in the Kaspa coinbase. The pure header itself binds parent hash, merkle root (transactions + payout), time, bits, version, and nonce.

Additional checks:

* magic-tagged merged-mining record uniqueness in `extra_data`;
* Dogecoin-style merkle size / `nChainIndex` consistency, with `nChainIndex` derived from the validating network's `ZORK_AUXPOW_CHAIN_ID`;
* the header `nNonce` equal to `ZORK_AUXPOW_NONCE_MARKER | ZORK_AUXPOW_CHAIN_ID` for the validating network (see **Zorkcoin Header Flag and Chain ID**). Because `nNonce` is hashed, a proof built for one network commits to a header that is invalid on every other network.

---

## 16. Serialization and Size Limits

### 16.1 Logical Encoding

```text
ZorkKaspaAuxPow:
    version:                     uint32 little-endian
    peer_header_length:          CompactSize
    peer_header:                 byte[peer_header_length]   // Kaspa Peer Header v2 wire encoding
    coinbase_transaction_length: CompactSize
    coinbase_transaction:        byte[coinbase_transaction_length]  // Kaspa Coinbase Transaction wire encoding
    tx_merkle_branch_len:        CompactSize
    tx_merkle_branch:            uint256[tx_merkle_branch_len]
    chain_merkle_branch_len:     CompactSize
    vChainMerkleBranch:          uint256[chain_merkle_branch_len]
    nChainIndex:                 int32 little-endian
```

### 16.2 Size Budget (Normative)

The middle column is what real Kaspa templates and merged-mining trees produce (lean solo to busy). The right column is what a Zork AuxPoW header extension may carry. Where a real template exceeds a cap, it cannot be used unmodified.

| Component | Seen in practice | Zork consensus cap |
| --- | ---: | ---: |
| Kaspa v2 peer header (RLE parents) | ~234–718 bytes | 720 bytes |
| Kaspa coinbase transaction | ~112–1500+ bytes (full mergeset rewards) | 400 bytes |
| Tx merkle branch (coinbase→header) | 0–12 hashes (0–384 bytes) | 8 hashes (256 bytes) |
| Aux-chain merkle branch | 0–5+ hashes (0–160+ bytes) | 5 hashes (160 bytes) |
| Framing / lengths | ~20–48 bytes | — |
| Whole header extension | — | 1280 bytes |

A full Kaspa mainnet-style coinbase (many mergeset outputs) is **not** appropriate inside Zork blocks. AuxPoW does not require Kaspa DAG acceptance, so miners SHALL use **lean** peer templates for Zork.

**Hard consensus limit:**

```text
MAX_AUXPOW_SERIALIZED_SIZE = 1280
```

The complete serialized `ZorkKaspaAuxPow` (all fields in **Logical Encoding**) MUST be ≤ 1280 bytes. Larger header extensions are invalid.

**Block weight and size.** The header extension is part of the serialized header, so every size rule counts it like the rest of the header: 4 weight units per byte in block weight (at most 5,120 WU), and in full in the serialized-size limit and `getblock` `size` / `weight`. A `headers` message of 2,000 maximal AuxPoW headers is about 2.7 MB, well under the P2P message limit.

The node's block template is native and reserves no separate room for the extension. It fits in the space `-blockreservedweight` (default 8,000 WU, minimum 2,000) sets aside for the header and coinbase: the 88-byte header (352 WU), a typical coinbase, and a maximal extension (5,120 WU) together stay under the default. A miner who lowers `-blockreservedweight` or builds a large coinbase from a full template MUST leave room for the extension, or the finished block fails `bad-blk-weight`.

### 16.3 Full block composition

Wire order for a complete block:

1. Hashed 88-byte Zorkcoin header fields (`nVersion`, `hashPrevBlock`, `hashMerkleRoot`, `nTime`, `nBits`, `nNonce`).
2. `CAuxPow` / `ZorkKaspaAuxPow` **iff** `nVersion` bit 8 is set. Bit 8 without this extension is invalid and MUST NOT be written as an 88-byte native-shaped header.
3. `vtx`.
4. MWEB trailer **iff** the last transaction is HogEx (`vtx.size() ≥ 2` and `vtx.back()` is HogEx).

AuxPoW is a **header extension**. It is not transaction data and not the MWEB trailer. `nVersion` bit 8 (AuxPoW) is distinct from the transaction HogEx flag (also historically bit 8 on the tx version/flag field). Those bits MUST NOT be conflated.

**Component ceilings** (each checked; also subject to the 1280 total):

```text
MAX_AUXPOW_PEER_HEADER_SIZE           = 720   # covers ~718 max estimate
MAX_AUXPOW_COINBASE_TX_SIZE           = 400   # lean AuxPoW coinbase only
MAX_AUXPOW_TX_MERKLE_BRANCH_HASHES    = 8     # 256 bytes
MAX_AUXPOW_CHAIN_MERKLE_BRANCH_HASHES = 5     # 160 bytes; merkle_size <= 32
```

Notes:

* Maxing every component simultaneously exceeds 1280; the **1280 total** is binding.
* Under 1280, a miner cannot use a ~718-byte header **and** a 384-byte (12-hash) tx merkle branch **and** a large coinbase. Valid combinations include:
  * solo lean: header ~250 + coinbase ~200 + empty tx branch ≈ 500 bytes;
  * large header + single-tx body (empty tx branch): header ≤720 + coinbase ≤400;
  * multi-tx peer body: smaller header and/or coinbase so the tx branch fits.
* The 400-byte coinbase cap is intentional and **below** Kaspa’s theoretical max coinbase size.

This is significant bloat versus native PoW. That cost is why **Chain Work for AuxPoW (Size Penalty)** applies a chain-work discount.

---

## 17. Mining Procedure

1. Build a Zorkcoin block template (node RPC / stratum job).
2. Finalize the Zorkcoin pure header fields that enter `GetHash()` (including merkle root / coinbase).
3. Place `hashAuxBlock` as a leaf in the aux-chain merkle tree (solo: one leaf; pools: shared tree with other chains).
4. Embed Dogecoin magic + byte-reversed `auxMerkleRoot` + size + nonce in Kaspa coinbase `extra_data`.
5. Build a Kaspa-format mining header committing to that coinbase via `hash_merkle_root` (see **Kaspa Peer Header v2 (Normative, Self-Contained)**, **Kaspa Coinbase Transaction (Normative)** and **Proving Coinbase ∈ `hash_merkle_root` (Normative)**).
6. Mine Kaspa peer PoW until \(h\le\min(\lfloor T_Z/4\rfloor,\lfloor T_K/3000\rfloor)\).
7. Assemble `ZorkKaspaAuxPow` (≤1280 bytes) and submit the Zorkcoin block.

Step 2 includes the AuxPoW header fields: `nVersion` bit 8 set and `nNonce = ZORK_AUXPOW_NONCE_MARKER | ZORK_AUXPOW_CHAIN_ID`. Both are hashed, so they MUST be final before `hashAuxBlock` is taken in step 3.

Ordinary Kaspa-valid hashes that fail either auxiliary inequality do not qualify.

### 17.1 Node mining RPC (informative, not consensus)

The node does not provide `createauxblock` / `submitauxblock`, and
`getblock` / `getblockheader` have no AuxPoW-specific fields. Miners obtain a
native `getblocktemplate` and set two fields on a local header copy:

```text
nVersion = template_version | 0x100
nNonce   = ZORK_AUXPOW_NONCE_MARKER | ZORK_AUXPOW_CHAIN_ID
```

Every other template `version` bit is kept as given: the BIP9 signalling bits
and the MWEB bit 4. The template never has bit 8 set, because no deployment
may use it (see **Zorkcoin Header Flag and Chain ID**).

The miner then assembles `ZorkKaspaAuxPow` and `submitblock`s the full block
hex. After MWEB activation the template includes HogEx / `mweb`; the miner
still attaches `CAuxPow` locally and MUST submit the full hex **including the
MWEB trailer** (`CBlock` serialization, not a header+`vtx`-only helper). See
`doc/auxpow/mining.md`.

---

## 18. Expected Mining Rate

This section is informative. Let \(r_K \approx 10\) blocks/s be the Kaspa block rate at the real Kaspa target, \(M = 3000\) the Kaspa multiplier, and \(T = 131.072\) s the Zorkcoin block interval (`nPowTargetSpacing`, which ASERT holds regardless of block type).

**Kaspa-derived ceiling.** Hashes meeting \(\lfloor T_K/M \rfloor\) at the real Kaspa target arrive across the whole Kaspa network at \(r_K/M\) per second, one every 300 s. If a fraction \(p\) of Kaspa hashrate merge-mines Zorkcoin and every such hash also met the floor, AuxPoW blocks would be at most this share of Zorkcoin blocks:

\[
\text{share}_{\mathrm{AuxPoW}}
\le
\min\left(1,\ \frac{p \, r_K \, T}{M}\right)
=
\min\left(1,\ \frac{1310.72\,p}{3000}\right)
\approx
0.437\,p
\]

So with all of Kaspa participating, AuxPoW is at most about 43.7% of blocks, roughly 1 in 2.29. The multiplier that caps AuxPoW at 1 in \(N\) blocks is

\[
M = N \, r_K \, T = 1310.72\,N
\]

| Target cap | Multiplier needed |
| --- | ---: |
| 1 in 2 | 2,621.44 |
| 1 in 2.29 | 3,000 (current) |
| 1 in 3 | 3,932.16 |
| 1 in 10 | 13,107.2 |

**The ceiling only binds honest Kaspa targets.** \(T_K\) is whatever the miner declares in the peer header. Zorkcoin does not check it against the Kaspa network (see **Kaspa BlockDAG Acceptance Is Not Required**) and puts no bound on it beyond a valid compact encoding. A miner can declare `ZORK_AUXPOW_EASIEST_KASPA_BITS`, making \(\lfloor T_K/M \rfloor \approx 2^{256}/3000\), far looser than \(\lfloor T_Z/4 \rfloor\) at any realistic Zorkcoin difficulty. The Kaspa-derived rule binds only when \(T_K < 750\,T_Z\). The ceiling above therefore describes miners reusing real Kaspa templates, not a dedicated AuxPoW miner.

**Floor.** Floor Mode always binds: every AuxPoW block costs at least 4× the work of a native block at the same height. Hashrate \(H_A\) mining AuxPoW finds blocks like \(H_A/4\) of native hashrate, so with native hashrate \(H_N\):

\[
\text{share}_{\mathrm{AuxPoW}}
\le
\frac{H_A/4}{H_N + H_A/4}
\]

Miners will use AuxPoW when it is convenient (e.g. already mining Kaspa templates), not because it is easier than native.

---

## 19. Security Considerations

### 19.1 Floor Mode Is the Zork Security Bound

AuxPoW requiring \(h\le T_Z/4\) means AuxPoW is strictly harder than native mining for the same height. Attackers prefer native PoW if choosing the cheaper path. This is intentional and sufficient for Zorkcoin PoW security without Kaspa DAG acceptance.

### 19.2 Kaspa-Derived Mode

The \(T_K/3000\) check ensures a proof is also a rare Kaspa-format hash relative to the declared peer `bits`. Miners can choose easy `bits` only if they still meet the floor against \(T_Z\); the floor prevents undercutting native difficulty.

### 19.3 Statistical Work

A qualifying proof demonstrates expected work statistically, consistent with ordinary PoW.

### 19.4 Commitment Substitution

The merged-mining magic, the chain ID (in the hashed `nNonce` and in `GetExpectedIndex`), and the pure-header hash prevent cross-network and cross-template reuse.

### 19.5 KHeavyHash Consensus Criticality

Peer PoW must match Kaspa’s pre-pow + matrix heavy-hash construction byte-for-byte. Cross-language vectors are mandatory before activation freeze.

### 19.6 Integer Arithmetic

All target division uses exact unsigned integer arithmetic. No floating point.

---

## 20. Reference Validation Pseudocode

```text
bool CheckZorkKaspaAuxPow(const CBlockHeader& hdr, const ZorkKaspaAuxPow& aux)
{
    if (!hdr.IsAuxPow() || aux.version != 1)
        return false;

    if (hdr.nNonce != (ZORK_AUXPOW_NONCE_MARKER | ZORK_AUXPOW_CHAIN_ID))
        return false;

    if (!ParseCanonicalKaspaHeader(aux.peer_header))
        return false;

    Target T_Z = DecodeCompact(hdr.nBits);
    Target T_K = DecodeKaspaCompact(aux.peer_header.bits);
    if (!IsValidTarget(T_Z) || !IsValidKaspaTarget(T_K))
        return false;

    Uint256 h = KaspaPeerPoW(aux.peer_header);

    if (h > T_K)
        return false;

    Target T_KD = T_K / 3000;
    Target T_Floor = T_Z / 4;
    if (T_KD == 0 || T_Floor == 0)
        return false;
    if (h > T_KD || h > T_Floor)
        return false;

    if (!VerifyKaspaCoinbaseMerkle(
            aux.coinbase_transaction,
            aux.coinbase_commitment_proof,
            aux.peer_header.hash_merkle_root))
        return false;

    uint256 hashAuxBlock = hdr.GetHash(); // pure header
    uint256 auxRoot = WalkMerkleBranch(
            hashAuxBlock, aux.vChainMerkleBranch, aux.nChainIndex);

    if (!CoinbaseExtraDataCommitsAuxRoot(
            aux.coinbase_transaction,
            auxRoot,
            aux.nChainIndex))
        return false;

    return true;
}
```

---

## 21. Implementation Requirements

### 21.1 Zorkcoin Node

* AuxPoW `nVersion` bit 8, reserved from BIP9 deployments
* Locked AuxPoW `nNonce` carrying the network chain ID
* Conditional `CAuxPow` ser/deser after the 88-byte hashed header fields (header-bearing P2P included)
* Kaspa peer header parse (post-Toccata pin)
* Kaspa peer PoW (pre-pow + heavy-hash)
* Dual target checks (`/4` and `/3000`)
* Kaspa coinbase + tx merkle proof verification (see **Kaspa Coinbase Transaction (Normative)** and **Proving Coinbase ∈ `hash_merkle_root` (Normative)**)
* Aux-chain merkle + Dogecoin `0xfabe'mm'` record in `extra_data`
* ASERT on all blocks; AuxPoW chain work via the size discount in **Chain Work for AuxPoW (Size Penalty)**
* Enforce `MAX_AUXPOW_SERIALIZED_SIZE = 1280`
### 21.2 Mining Software / Pools

* Obtain Zork template; insert `hashAuxBlock` into shared aux-chain merkle tree
* Commit `auxMerkleRoot` into Kaspa `extra_data`
* Mine to \(\min(T_Z/4,\,T_K/3000)\)
* Preserve peer header, coinbase, tx merkle proof, and aux-chain branch on rare solves
* Set `nVersion` bit 8 and the locked `nNonce` before taking `hashAuxBlock`; never roll bit 8
* Leave block weight for the header extension (see **Serialization and Size Limits**)
* Submit the full block to Zorkcoin

---

## 22. Required Test Vectors

Named coverage (implementation names in `doc/auxpow/testing.md`):

1. valid Kaspa PoW failing floor and/or 3000× checks — `auxpow_check_tests` dual-target permutations;
2. valid proof meeting both — `valid_solo_auxpow_regtest`, `feature_auxpow.py` submit;
3. meets 3000× but fails floor — dual-target `kaspa_3000x_and_zork_met_not_4x`;
4. meets floor but fails 3000× — dual-target `kaspa_met_not_3000x_and_zork_4x`;
5. wrong / missing aux merkle root in `extra_data` — `auxpow_reject_tests` / `rejects_missing_mm_magic`;
6. wrong `nChainIndex` / branch (including multi-leaf trees) — `two_leaf_flipped_index_rejected`, `two_leaf_wrong_sibling_rejected`, `feature_auxpow.py` 2-leaf reject;
7. invalid tx merkle proof — `auxpow_reject_tests`;
8. AuxPoW flag set without header extension / extension without flag — `feature_auxpow.py` native-shaped bit-8 submit and P2P; unserialize throw;
9. native block still valid with AuxPoW active — `feature_auxpow.py` generate; three-way same height;
10. oversized `CAuxPow` rejection — `auxpow_reject_tests` size caps; P2P CompactSize over 720/400/8/5/1280;
11. ASERT retarget across mixed native + AuxPoW tips — `asert_ignores_block_type` (ASERT enabled on regtest; every height's `nBits` equals the all-native computation; wrong AuxPoW `nBits` is `bad-diffbits`);
12. cross-impl Kaspa peer PoW vectors vs rusty-kaspa — `test/data/auxpow/kaspa_goldens.txt` (`a41a333b`);
13. **required** 2-leaf aux-chain fixture (dummy sibling leaf; not “encouraged”) — `valid_two_leaf_auxpow_regtest`, `feature_auxpow.py` 2-leaf accept;
14. AuxPoW + HogEx + MWEB composition and two-node sync — `feature_auxpow_mweb.py`;
15. P2P malformed bit-8 (truncated extension, invalid Kaspa bytes, first-seen mismatch over `headers`) — `feature_auxpow.py` P2P cases; `src/test/fuzz/auxpow.cpp`;
16. locked `nNonce`: wrong chain ID, damaged marker, and zero nonce rejected; wire bytes per network — `checkauxpow_reject_strings`, `nonce_helpers`, `nonce_wire_bytes_per_network`, `feature_auxpow.py` `test_auxpow_nonce`;
17. bit 8 reserved from BIP9 — `auxpow_bit_reserved_from_versionbits` (no deployment uses it; outside the live signalling bits), `auxpow_blocks_do_not_trigger_unknown_version_warnings`;
18. Kaspa parser and `CAuxPow` serializer error paths — `kaspa_header_truncated_at_every_offset`, `kaspa_tx_truncated_at_every_offset`, `kaspa_compact_bits_boundaries`, `auxpow_serialize_and_unserialize_failures`;
19. one AuxPoW+MWEB block carrying SegWit, Taproot key-path, peg-in, peg-out, and MWEB-to-MWEB spends, relayed as a compact block with no `getblocktxn` — `feature_auxpow_mweb.py` `test_mixed_content_auxpow_block`;
20. reorgs in both directions between a native+MWEB tip and an AuxPoW+MWEB tip, with MWEB transactions following the active chain — `feature_auxpow_mweb.py` `test_native_auxpow_mweb_reorg`;
21. AuxPoW headers through low-work headers presync and redownload across a `headers` message boundary, with the exact and one-over `-minimumchainwork` cases — `feature_auxpow_headers_presync.py`.

---

## 23. Deployment

### 23.1 Initial Networks

Kaspa AuxPoW SHALL be **ACTIVE from genesis (block 0)** on the initial Zorkcoin networks (forced active). Versionbits machinery MAY remain in the codebase for future networks but is not required to enable AuxPoW on day one.

### 23.2 Optional Forever

After activation:

* native Zorkcoin KHeavyHash remains valid for every block;
* AuxPoW remains an optional alternate path;
* miners choose per block;
* AuxPoW SHALL NOT disable or deprecate native mining.

### 23.3 Pre-Activation (Future Softfork Networks Only)

On a network that is not genesis-forced, blocks with AuxPoW header extensions are invalid until ACTIVE.

---

## 24. Open Design Items

Resolved in this revision:

* Peer terminology (not parent)
* Dual target rule (Floor 4× **and** Kaspa-Derived 3000×)
* Floor Mode definition
* Genesis-active + optional forever
* Dogecoin-style header flag, header extension, **aux-chain merkle**, and **identical** `0xfa 0xbe 'm' 'm'` record bytes
* ASERT on all blocks
* Chain work: `GetBitsProof(nBits) * 8192/(8192+S)` (no 4× credit)
* Size: `MAX_AUXPOW_SERIALIZED_SIZE = 1280` + component caps
* Self-contained Kaspa v2 header / coinbase / merkle / PoW (see **Kaspa Peer Header v2 (Normative, Self-Contained)**, **Kaspa Coinbase Transaction (Normative)** and **Proving Coinbase ∈ `hash_merkle_root` (Normative)**)
* Chain ID carried in the locked AuxPoW `nNonce`, not in `nVersion`, leaving the `nVersion` upper bits to BIP9. Per-network chain IDs: main `0x4b5a`, test/testnet4 `0x545a`, regtest `0x525a`, signet `0x535a` (wire bytes `ZKAuxPoW`, `ZTAuxPoW`, `ZRAuxPoW`, `ZSAuxPoW`)
* Bit 8 reserved from BIP9 deployments; it is outside the live signalling bits, so it raises no unknown-version warnings
* Block weight: the header extension counts at 4 WU per byte and fits in the default `-blockreservedweight`; templates reserve no separate room
* C++ ↔ rusty-kaspa goldens pinned at commit `a41a333b08848f41bf737b72592e463a6011b8ac` (`test/data/auxpow/kaspa_goldens.txt`)
* Multi-leaf aux-chain is supported; 2-leaf accept/reject fixtures are required (see **Aux-Chain Merkle Branch** and **Required Test Vectors**)
* Full-block order with MWEB: hashed 88 → `CAuxPow` iff bit 8 → `vtx` → MWEB iff HogEx (see **Full block composition**)
* An agent-assisted review of the finished surface was completed (multi-leaf index math, first-seen pin, bit-8 vs HogEx flag, MWEB composition, incomplete-header write path)

Still open before consensus freeze:

1. Independent human consensus review of the finished surface.

---

## 25. Summary

Zorkcoin Kaspa AuxPoW is a self-contained, Dogecoin-style auxiliary proof-of-work path using a **Kaspa peer** header:

\[
h
\le
\left\lfloor
\frac{T_Z}{4}
\right\rfloor
\quad\text{and}\quad
h
\le
\left\lfloor
\frac{T_K}{3000}
\right\rfloor
\]

* \(T_Z\) comes from the Zorkcoin header `nBits` (ASERT).
* \(T_K\) comes from the Kaspa peer header `bits`.
* Commitment: `hashAuxBlock` is an aux-chain merkle leaf; coinbase `extra_data` stores magic + `auxMerkleRoot` (multi-chain capable).
* `CAuxPow` follows the 88-byte hashed fields when version bit 8 is set and includes `vChainMerkleBranch` / `nChainIndex`. Header-bearing P2P messages include this extension. `CheckAuxPow` runs on that header.
* An AuxPoW header's `nNonce` is locked to `'AuxPoW' << 16 | chain_id` (wire bytes such as `ZKAuxPoW`); `nVersion` uses only bit 8, leaving every other bit to BIP9.
* ASERT runs normally on all blocks.
* Active from genesis; native mining remains optional-path peer forever.
* Kaspa blockDAG acceptance is not required.

---

## Appendix A — Dogecoin Reference Notes (Condensed)

See also `Zork_Notes_Dogecoin_AuxPoW_Info.md`.

* AuxPoW flag: `nVersion & 0x0100`
* Chain ID in upper 16 bits of `nVersion`
* After pure header: `CAuxPow{ peerHeader, coinbaseTx, vMerkleBranch, vChainMerkleBranch, nChainIndex }`
* Commitment: `hash(childPureHeader)` → aux merkle → `0xfabe'mm'` + root in peer coinbase
* Validate peer PoW ≤ child target from child `nBits`
* No peer-chain node required

Zorkcoin keeps this architecture (including the aux-chain merkle). Differences: Kaspa peer header/PoW, commitment bytes in Kaspa `extra_data` instead of Bitcoin `scriptSig`, the chain ID in the locked `nNonce` instead of `nVersion`, the dual-target rule, 1280-byte `CAuxPow` cap, and size-discounted chain work.

---

## 26. Kaspa Peer Header v2 (Normative, Self-Contained)

This section defines everything required to parse, hash, and PoW-check the AuxPoW `peer_header`. External Kaspa documentation is not required.

### 26.1 Version

AuxPoW SHALL accept peer headers with:

```text
version = 2   // TOCCATA_BLOCK_VERSION
```

Version 1 headers are rejected for AuxPoW (Zorkcoin pins the post-Toccata format).

### 26.2 Logical Fields

| Field | Type | Notes |
| --- | --- | --- |
| `version` | uint16 LE | Must be 2 |
| `parents_by_level` | RLE compressed parent sets | See **`parents_by_level` (RLE / CompressedParents)** |
| `hash_merkle_root` | 32-byte hash | Tx merkle root (see **Proving Coinbase ∈ `hash_merkle_root` (Normative)**) |
| `accepted_id_merkle_root` | 32-byte hash | Carried for header integrity; **not** re-validated against Kaspa DAG |
| `utxo_commitment` | 32-byte hash | Carried; not re-validated against Kaspa UTXO |
| `timestamp` | uint64 LE | Milliseconds |
| `bits` | uint32 LE | Compact target \(T_K\) |
| `nonce` | uint64 LE | PoW nonce |
| `daa_score` | uint64 LE | Carried; not re-validated |
| `blue_score` | uint64 LE | Carried; not re-validated |
| `blue_work` | Uint192 | See **`blue_work` (Uint192)** |
| `pruning_point` | 32-byte hash | Carried; not re-validated |

Zorkcoin does **not** require the parent references, DAA, blue work, or pruning point to be valid in the Kaspa blockDAG. They MUST still be present and participate in the header hash / PoW preimage exactly as specified, so the PoW binds the whole header.

### 26.3 `parents_by_level` (RLE / CompressedParents)

Parents are stored run-length encoded. A run is `(cum_count: u8, parents: Hash[])`.

* `cum_count` is the **exclusive** end level index of the run (cumulative).
* Example: `[(3, [A]), (5, [B])]` means levels 0..2 use `[A]`, levels 3..4 use `[B]`.
* Consecutive runs MUST have different parent vectors (fully compressed).
* `cum_count` values MUST be strictly increasing.
* First run MUST NOT have `cum_count == 0`.
* Expanded level count = last `cum_count`.
* Level 0 = direct parents. For AuxPoW size control, level-0 length SHOULD be small; Kaspa mainnet allows up to 16 direct parents, but large parent sets may violate the 1280-byte AuxPoW cap.

**Wire encoding inside AuxPoW `peer_header` bytes** (canonical; same length encoding as the hash preimage):

```text
num_runs: u64 LE
for each run:
    cum_count: u8
    num_parents: u64 LE
    parent_hashes: 32 bytes each, in order
```

Then fixed fields in order: `hash_merkle_root` (32), `accepted_id_merkle_root` (32), `utxo_commitment` (32), `timestamp` u64 LE, `bits` u32 LE, `nonce` u64 LE, `daa_score` u64 LE, `blue_score` u64 LE, `blue_work` (see **`blue_work` (Uint192)**), `pruning_point` (32).

(`version` is written first as u16 LE before `num_runs`.)

### 26.4 `blue_work` (Uint192)

192-bit unsigned integer. For hashing, encode as:

1. Take 24-byte **big-endian** representation.
2. Strip leading zero bytes (if all zero, empty slice).
3. Write `len` as u64 LE, then the remaining bytes (`write_var_bytes`).

Example: value `123456` encodes as length=3 then bytes `01 e2 40`.

### 26.5 Header Hash Preimage (BlockHash domain)

Let `BlockHash` be the Kaspa domain-separated hasher used for block hashes (C++ must match rusty-kaspa `kaspa_hashes::BlockHash`).

Preimage write order for `hash_override_nonce_time(header, nonce, timestamp)`:

1. `version` as u16 LE
2. `expanded_level_count` as u64 LE (`parents_by_level` expanded length)
3. For each expanded level `L = 0 .. expanded_level_count-1`:
   * `num_parents` as u64 LE
   * each parent hash as 32 raw bytes
4. `hash_merkle_root` (32)
5. `accepted_id_merkle_root` (32)
6. `utxo_commitment` (32)
7. `timestamp` as u64 LE (**parameter**, not necessarily header.timestamp)
8. `bits` as u32 LE
9. `nonce` as u64 LE (**parameter**)
10. `daa_score` as u64 LE
11. `blue_score` as u64 LE
12. `blue_work` via **`blue_work` (Uint192)**
13. `pruning_point` (32)

`header_hash = BlockHash(preimage with real timestamp & nonce)`.

`pre_pow_hash = BlockHash(preimage with timestamp=0, nonce=0)`.

### 26.6 Compact Target `bits`

Decode `bits` with the standard Bitcoin-style compact target encoding to a 256-bit target \(T_K\) (Kaspa `Uint256::from_compact_target_bits`). Reject negative, overflow, zero, and non-canonical encodings per the same rules Zorkcoin uses for compact targets (aligned with Kaspa’s decoder).

### 26.7 Peer PoW (Kaspa KHeavyHash)

PoW is **not** `HeavyHash(serialize(header))`.

```text
pre_pow_hash = hash_override_nonce_time(header, nonce=0, timestamp=0)
matrix       = Matrix::generate(pre_pow_hash)          // Kaspa matrix construction
pow_hash_x   = PowHash::new(pre_pow_hash, header.timestamp)
               .finalize_with_nonce(header.nonce)
               // feeds: PRE_POW_HASH || TIME || 32 zero bytes || NONCE
h_bytes      = matrix.heavy_hash(pow_hash_x)
h            = Uint256::from_le_bytes(h_bytes)
```

Accept if \(h \le T_K\) (and the Zork AuxPoW inequalities in **Target Derivation and Validation**).

C++ SHALL match rusty-kaspa `kaspa_pow::State` byte-for-byte. Test vectors are mandatory before freeze.

### 26.8 AuxPoW Semantic Checks (Without Kaspa DAG)

Minimum checks beyond parse/PoW:

* `version == 2`
* `parents_by_level` RLE canonical (see **`parents_by_level` (RLE / CompressedParents)**)
* `bits` decodes to valid \(T_K\)
* sizes within AuxPoW caps (see **Size Budget (Normative)**)

Do **not** require parents to exist, blue_work to match GHOSTDAG, or timestamps to follow Kaspa MTP.

---

## 27. Kaspa Coinbase Transaction (Normative)

### 27.1 Structural Requirements for AuxPoW

A Kaspa coinbase submitted in AuxPoW MUST:

* have `inputs.length == 0`
* have `subnetwork_id == COINBASE` where  
  `COINBASE = 20 bytes: { 0x01, 0x00×19 }`
* have `gas == 0`
* have `lock_time` as provided (typically 0)
* have `version == 1` for the Toccata-era pin (`TX_VERSION_TOCCATA = 1`), unless a later documented pin says otherwise
* have `storage_mass == 0` (coinbase mass commitment must be zero)
* have `payload.length` in `[MIN_PAYLOAD_LENGTH, 204]`
* include the Dogecoin merged-mining record in `extra_data` (see **Coinbase Merged-Mining Record (Dogecoin Bytes, in `extra_data`)**)

Outputs: zero or more `TransactionOutput`s. For AuxPoW size, prefer **one** small output. Each output:

```text
value: u64 LE
script_public_key.version: u16 LE
script_public_key.script: length-prefixed bytes
covenant: for tx version >= 1:
    present: u8 boolean
    if present: authorizing_input u16 LE || covenant_id 32 bytes
```

Script public key length inside the **payload** miner script field is limited to 150 bytes by Kaspa params (`coinbase_payload_script_public_key_max_len`).

### 27.2 Payload Layout

```text
payload =
    blue_score:   u64 LE
    subsidy:      u64 LE
    spk_version:  u16 LE
    spk_len:      u8
    spk_bytes:    spk_len bytes
    extra_data:   remaining bytes of payload
```

`MIN_PAYLOAD_LENGTH` = 8+8+2+1 = 19 (empty script + empty extra).  
`max_coinbase_payload_len` = 204.

`extra_data` contains pool tags (optional) and exactly one merged-mining record (see **Coinbase Merged-Mining Record (Dogecoin Bytes, in `extra_data`)**).

### 27.3 AuxPoW Wire Encoding of the Transaction

Canonical AuxPoW storage (must be sufficient to recompute the tx hash in **Proving Coinbase ∈ `hash_merkle_root` (Normative)**):

```text
version: u16 LE
num_inputs: u64 LE          // must be 0
num_outputs: u64 LE
outputs: repeated TransactionOutput encoding (see Structural Requirements for AuxPoW)
lock_time: u64 LE
subnetwork_id: 20 bytes
gas: u64 LE
payload_len: u64 LE
payload: payload_len bytes
storage_mass: u64 LE        // must be 0 for coinbase
```

Total encoded size MUST be ≤ `MAX_AUXPOW_COINBASE_TX_SIZE` (400) and fit in the 1280 total.

---

## 28. Proving Coinbase ∈ `hash_merkle_root` (Normative)

### 28.1 Transaction Hash (Merkle Leaf)

The merkle leaf for a transaction is `TransactionHash` domain hash over the full transaction encoding used by Kaspa `hashing::tx::hash` with `TxEncodingFlags::FULL`:

Write order into `TransactionHash` hasher:

1. `version` u16 LE  
2. `num_inputs` u64 LE; each input (coinbase has none)  
3. `num_outputs` u64 LE; each output:
   * `value` u64 LE
   * `spk.version` u16 LE
   * `spk.script` as `u64 LE length || bytes`
   * if `version >= 1`: `covenant_present` as u8 0/1; if 1: `authorizing_input` u16 LE || `covenant_id` 32  
4. `lock_time` u64 LE  
5. `subnetwork_id` 20 bytes  
6. `gas` u64 LE  
7. `payload` as `u64 LE length || bytes`  
8. Mass commitment: for `version >= 1`, always write `storage_mass` u64 LE (0 for coinbase)

Leaf = finalize(`TransactionHash`).

### 28.2 Merkle Root Algorithm

Given ordered leaf hashes \(H_0,\ldots,H_{n-1}\) (tx 0 = coinbase):

```text
if n == 0: root = ZERO_HASH
if n == 1: root = H_0
else:
    next_pot = next_power_of_two(n)
    allocate array M[0 .. 2*next_pot - 2]
    place leaves at M[0..n)
    for unpaired right children use ZERO_HASH
    interior node = MerkleBranchHash(left || right)   // Kaspa domain hasher
    root = final interior
```

This matches Kaspa `calc_merkle_root` / `merkle_hash` with `MerkleBranchHash` (not Bitcoin double-SHA256).

`peer_header.hash_merkle_root` MUST equal this root for the transaction list committed by the proof.

### 28.3 Inclusion Proof Format

```text
tx_merkle_branch: vector of 32-byte siblings from leaf to root
nTxIndex: implicit 0 for AuxPoW (coinbase)
```

Verification:

```text
hash = TransactionHash(coinbase)
index = 0
for sibling in tx_merkle_branch:
    if index is even:  hash = MerkleBranchHash(hash || sibling)
    else:              hash = MerkleBranchHash(sibling || hash)
    // When the Kaspa tree had a missing right child, the miner MUST supply
    // ZERO_HASH as that sibling so this walk matches Merkle Root Algorithm.
    index >>= 1
require hash == peer_header.hash_merkle_root
```

If the peer body has only the coinbase (`n == 1`), `tx_merkle_branch` MUST be empty and `hash_merkle_root` MUST equal `TransactionHash(coinbase)`.

### 28.4 Practical Guidance Under the 1280 Cap

Prefer **single-transaction** peer bodies for Zork AuxPoW (empty tx merkle branch). Multi-tx bodies are allowed if the full AuxPoW header extension stays ≤ 1280 bytes.

---

## 29. Diff vs Dogecoin (Quick Index)

| Topic | Dogecoin | Zorkcoin |
| --- | --- | --- |
| Peer (parent) chain | Litecoin / Bitcoin-format header, scrypt PoW | Kaspa v2 header, KHeavyHash PoW (see **Kaspa Peer Header v2 (Normative, Self-Contained)**) |
| Merged-mining record | `0xfa 0xbe 'm' 'm'` + root + size + nonce in coinbase `scriptSig` | Same bytes, in Kaspa coinbase `extra_data` (see **Coinbase Merged-Mining Record (Dogecoin Bytes, in `extra_data`)**) |
| Aux-chain merkle tree | Yes, `GetExpectedIndex` LCG | Same |
| AuxPoW flag | `nVersion` bit 8 | Same |
| Chain ID | Upper 16 bits of `nVersion` | Locked `nNonce` (`'AuxPoW' << 16 \| chain_id`); `nVersion` upper bits stay BIP9 (see **Zorkcoin Header Flag and Chain ID**) |
| Child header | 80 bytes | 88 bytes (`nTime` in ms, 64-bit `nNonce`) |
| Target rule | Peer hash ≤ child target | Dual: \(h \le \lfloor T_Z/4 \rfloor\) and \(h \le \lfloor T_K/3000 \rfloor\) (see **Required Inequalities**) |
| Difficulty | Per-chain DigiShield | ASERT on all blocks, unchanged by block type (see **ASERT**) |
| Chain work | Same as native | Discounted by extension size \(S\): \(W \cdot 8192/(8192+S)\) (see **Chain Work for AuxPoW (Size Penalty)**) |
| Extension size | No total cap; chain merkle branch ≤ 30 hashes | 1280 bytes total plus component caps (see **Size Budget (Normative)**) |
| Activation | Height-activated | Active from genesis; native mining valid forever (see **Deployment**) |
