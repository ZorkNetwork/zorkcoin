# MWEB Payment Proofs

A payment proof lets a sender convince an arbiter that a specific stealth address
was paid a claimed amount, without revealing the sender's master keys to the
arbiter.

## Threat model and privacy modes (the "cash receipt" model)

- The **sender** holds (or can derive) the output's sender signing key `k_s`, the
  amount `v`, and the output nonce `n`.
- The **arbiter** has a view of the chain (at least the MWEB header `output_root`
  for some block) and the recipient's stealth address `(A_i, B_i)`.

Choosing how the wallet generates `k_s` is a privacy tradeoff analogous to how
you handle cash transaction receipts:

1. **Default privacy mode (`-mwebdeterministicsenders=0`, Litecoin Core 0.21 style):**
   Each outgoing MWEB output uses a fresh random ephemeral `k_s`. If the
   account's master scan secret `a` is ever captured, an observer cannot scan
   the chain to discover which external outputs the wallet sent or their
   amounts. A payment proof **is** a standalone receipt: if you occasionally
   want a receipt for a payment (or if you are a privacy maximalist who exports
   a proof for every send and stores those receipts offline), you can export a
   payment proof when sending without exposing your entire spend history to
   anyone who obtains `a`.
2. **Opt-in receipt-keeping mode (`-mwebdeterministicsenders=1`, Litecoin Core 24.x style):**
   If you always want the wallet to automatically file a recoverable receipt for
   every outgoing transaction so you can rescan and check spending history from
   keys alone, enable `-mwebdeterministicsenders=1`. Anyone who holds the
   account's master scan secret `a` can then derive the deterministic `k_s`
   sequence (`DeriveSenderSigningKey(a, i)`), identify outputs that account
   sent, and rewind their amounts with `DeriveProofNonce(DeriveRewindKey(a), C)`.
   Treat `a` like a viewing key for sends as well as receives when this mode is
   enabled. When `-mwebdeterministicsenders=1` is used on a wallet whose history
   also includes 21.x-style random-sender transactions, those opaque historical
   sends are tolerated cleanly (owned inputs and change still rewind, and fee
   accounting uses the kernel fee).

Disk-backed wallets do **not** store `sender_key` or `blind` after write
(`SanitizeForDisk`). In deterministic sender mode, amounts and shared secrets
for sends are restored by rewinding with
`DeriveProofNonce(DeriveRewindKey(a), C)`. The external
recipient address is a create-time input after a wipe; it is not recovered from
sender data alone.

## Proof contents

A proof consists of:

1. The MWEB **output** (commitment, keys, message, rangeproof, owner signature).
2. A **TXO PMMR inclusion proof** for that output's leaf against a block's
   `mweb_header.output_root` (see RPCs below).
3. The claimed amount **`v`** and output nonce **`n`**.
4. The recipient stealth address **`(A_i, B_i)`** (or its bech32 encoding).

The owner Schnorr signature already on the output proves knowledge of `k_s`
relative to `K_s`. Inclusion binds that output to the chain. Together with
`v` and `n`, an arbiter can check the output was constructed to the claimed
address for that amount (LIP-0004 §11, with the `K_o` correction below).

## LIP-0004 §11 `K_o` errata

LIP text writes an additive tweak for the one-time output key. This
implementation (and Litecoin's) uses the **multiplicative** form documented in
[stealth-addresses.md](stealth-addresses.md):

`K_o = HASH32('O'||e) · B_i`

Verify with that equation, not the additive LIP construction.

## Verify path

1. Verify the inclusion proof against the block's `output_root` (or an explicit
   root). RPC: `verifymweboutputproof`.
2. Decode the recipient address to `(A_i, B_i)`.
3. Compute `s = HASH32('S'||A_i||B_i||v||n)`, then
   `e = HASH32('D'||s·A_i)`.
4. Check:
   - `K_e ?= s · B_i`
   - `K_o ?= HASH32('O'||e) · B_i`
   - view tag and masked `v'` / `n'` match
   - commitment matches `COMMIT(v, BLIND_SWITCH(v, HASH32('B'||e)))`
     (the contrib Python tool currently checks the key/mask fields only;
     use a consensus-aware verifier for the pedersen commitment check)
5. Optionally confirm the output's owner signature under `K_s` (already required
   for consensus if the output is in a valid block).

## Inclusion RPCs

### `getmweboutputproof`

Arguments: `output_id`, optional `blockhash`.

- Unspent at tip (no `blockhash`): assemble a one-leaf segment against the tip
  leafset and tip `output_root`.
- Spent, or a historical `blockhash`: rewind a local MWEB view with undo data
  to a height where the leaf is still unspent (default: inclusion height) and
  assemble there. Missing undo fails closed with an error. Rewinds more than
  100000 blocks below tip are rejected (RPC DoS bound).

### `verifymweboutputproof`

Arguments: `mwebproof` object from `getmweboutputproof`, optional explicit
`output_root`. Recomputes the PMMR root from the segment and compares. When
`blockhash` is present, the node also checks the active-chain header.

Spent outputs remain in the TXO PMMR as hashes; only the leafset bit is cleared.
That is why historical leafsets are required for spent proofs.

## Obtaining `k_s`

- **With `-mwebdeterministicsenders=1` (24.x receipt-keeping mode, or after wipe):**
  Deterministic sender keys follow `k_s = DeriveSenderSigningKey(a, i)`.
  - If the sender-key index `i` is known, derive `k_s` directly.
  - If only the on-chain `K_s` is known, scan indices `0 .. next+lookahead` until
    `K_s = k_s·G` matches, then derive `n = HASH32('N'||k_s)[0,15]`.
- **With default `-mwebdeterministicsenders=0` (21.x privacy mode):**
  `k_s` is chosen randomly at creation time and cannot be re-derived from `a`
  alone; supply `--sender-key` when exporting the payment proof (receipt) before
  `SanitizeForDisk` / wallet wipe.

The contrib tool `contrib/mweb/mweb_payment_proof.py` implements create/verify
using these RPCs and derivation helpers.

## Tooling

```text
contrib/mweb/mweb_payment_proof.py create  --output-id ... --address ... --amount ... \
    (--sender-key ... | --scan-secret ... [--sender-index N])
contrib/mweb/mweb_payment_proof.py verify --proof proof.json
```

RPC access requires `MWEB_RPC_URL` (e.g. `http://user:pass@127.0.0.1:port`).
The functional test sets that from the node cookie before invoking the tool.
