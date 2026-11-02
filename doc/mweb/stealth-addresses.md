# Stealth Addresses

Transacting on the MWEB happens via stealth addresses. Stealth addresses are supported using the *Dual-Key Stealth Address Protocol (DKSAP)*.
These addresses consist of 2 secp256k1 public keys <code>(A<sub>i</sub>, B<sub>i</sub>)</code> which are derived from 2 master keypairs <code>(a, A)</code> and <code>(b, B)</code>,
and which can be used repeatedly to generate new outputs that are unlinkable by those without knowledge of the master keys.

### Notation
* <code>G</code>, <code>H</code>, and <code>J</code> are curve generator points
* Uppercase letter in code font (<code>A</code>, <code>A<sub>i</sub></code>, etc.) represents a secp256k1 public key
* Lowercase letter in code font (<code>a</code>, <code>a<sub>i</sub></code>, etc.) represents a scalar
* A letter in single quotes (<code>'K'</code>) represents the ASCII value of the character literal
* <code>HASH32(x||y||z)</code> represents the standard 32-byte `BLAKE3` hash of the conjoined serializations of `x`, `y`, and `z`
    * When a <code>HASH32(...)</code> digest is used as a secp256k1 scalar, it is mapped with libmw's <code>SecretKey::FromHash</code>: use the digest if it is in <code>[1, n−1]</code>; otherwise rehash under the tag <code>"MWEB hash-to-scalar"</code> with a little-endian counter until a valid scalar is obtained. Digests are **not** reduced modulo the curve order.
* <code>COMMIT(v,x) = v⋅H + x⋅G</code> represents the pedersen commitment generated with value <code>v</code> and blinding factor <code>x</code>.
* <code>BLIND_SWITCH(v,r)</code> is the switch-commitment blinding factor from <code>secp256k1_blind_switch</code>: <code>r + SHA256(ser33(COMMIT(v,r)) || ser33(r⋅J))</code>, where <code>ser33</code> is compressed-point serialization. The SHA256 digest must already be a valid scalar (if it is ≥ <code>n</code>, the operation fails); it is not a BLAKE3/`HASH32` digest.
* <code>x[y,z]</code> suffix represents the byte range from <code>y</code> to <code>z</code> (inclusive, zero-based indices) of the input <code>x</code>

### Address Generation

Unique stealth addresses should be generated deterministically from a master scan keypair <code>(a, A)</code> and master spend keypair <code>(b, B)</code> using the following process:

1. Choose the lowest unused address index <code>i</code>
2. Calculate one-time spend keypair <code>(b<sub>i</sub>, B<sub>i</sub>)</code> as:<br/>
    <code>b<sub>i</sub> = b + HASH32('A'||i||a)</code><br/>
    <code>B<sub>i</sub> = b<sub>i</sub>⋅G</code>
3. Calculate one-time scan keypair <code>(a<sub>i</sub>, A<sub>i</sub>)</code> as:<br/>
    <code>a<sub>i</sub> = a⋅b<sub>i</sub></code><br/>
    <code>A<sub>i</sub> = a<sub>i</sub>⋅G</code>

The address <code>(A<sub>i</sub>, B<sub>i</sub>)</code> can be computed without the spend secret <code>b</code>:
<code>B<sub>i</sub> = B + HASH32('A'||i||a)⋅G</code> and <code>A<sub>i</sub> = a⋅B<sub>i</sub></code>.
It always needs the scan secret <code>a</code>, so addresses cannot be derived from public keys alone.
<code>i</code> is serialized as 4 bytes little-endian. Every <code>HASH32</code> result used as a scalar is mapped with
<code>SecretKey::FromHash</code> as above.

### Outputs

Outputs consist of the following data:

* <code>C<sub>o</sub></code> - The pedersen commitment to the value.
* <code>K<sub>s</sub></code> - The sender's public key.
* <code>K<sub>o</sub></code> - The receiver's one-time public key.
* Output message, <code>m</code>, consisting of:
  * Feature bits
  * <code>K<sub>e</sub></code> - The key exchange public key.
  * <code>t</code> - The view tag.
  * <code>v'</code> - The masked value.
  * <code>n'</code> - The masked nonce.
  * Optional extra data (if enabled by feature bits)
* A signature using the sender's key <code>k<sub>s</sub></code>.
* A rangeproof of <code>C<sub>o</sub></code> that also commits to the <code>m</code> (see [consensus.md](consensus.md#bulletproofs)).

### Output Construction

To create an output for value <code>v</code> to a receiver's stealth address <code>(A<sub>i</sub>,B<sub>i</sub>)</code>:

1. Choose a sender keypair <code>(k<sub>s</sub>, K<sub>s</sub>)</code>:
   * **Default privacy mode (`-mwebdeterministicsenders=0`, Litecoin Core 0.21 style):** Wallet-created outputs use a fresh random ephemeral <code>k<sub>s</sub></code> per output, as do raw / keystore paths that have no MWEB account. Capturing the scan secret <code>a</code> does not let an observer identify which outputs the wallet sent on-chain.
   * **Opt-in receipt-keeping mode (`-mwebdeterministicsenders=1`, Litecoin Core 24.x style):** Wallet-created outputs use a deterministic <code>k<sub>s</sub> = DeriveSenderSigningKey(a, i)</code> for the active account's master scan secret <code>a</code> and a per-scan durable index <code>i</code> (advanced before the key is returned). Existing wallets that already persisted a non-zero `mweb_sender_key_index` continue using deterministic sender keys unless `-mwebdeterministicsenders=0` is explicitly set.
2. Derive the nonce <code>n = HASH32('N'||k<sub>s</sub>)[0,15]</code>
3. Derive the sending key <code>s = HASH32('S'||A<sub>i</sub>||B<sub>i</sub>||v||n)</code>
4. Calculate <code>P = s⋅A<sub>i</sub></code>. Derive the view tag and shared secret as:<br/>
   <code>t = HASH32('T'||P)[0]</code><br/>
   <code>e = HASH32('D'||P)</code>
5. Calculate the receiver's one-time public key <code>K<sub>o</sub> = HASH32('O'||e)⋅B<sub>i</sub></code>
6. Calculate the key exchange pubkey <code>K<sub>e</sub> = s⋅B<sub>i</sub></code>
7. Encrypt the value using <code>v' = v &oplus; LE64(HASH32('Y'||e))</code>
8. Encrypt the nonce using <code>n' = n &oplus; HASH32('X'||e)[0,15]</code>
9. Calculate the blinding factor <code>x = BLIND_SWITCH(v,HASH32('B'||e))</code>
10. Calculate the commitment <code>C<sub>o</sub> = COMMIT(v,x)</code>
11. Generate the rangeproof <code>&pi;</code> for <code>C<sub>o</sub></code>, committing also to the output message <code>m</code>. See [Outputs](#outputs) above for the field list; wire format in [serialization.md § `mweb_output`](serialization.md#mweb_output) (`features`, conditional `key_exchange_pk` / `view_tag` / `masked_value` / `masked_nonce`, optional `extra_data`). Rangeproof rules: [consensus.md](consensus.md#bulletproofs) (64-bit bulletproof, 675 bytes; `extra_commit` = serialized `m`).
12. Sign the message <code>HASH32(C<sub>o</sub>||K<sub>s</sub>||K<sub>o</sub>||HASH32(m)||HASH32(&pi;))</code> using the sender key <code>k<sub>s</sub></code>.


### Output Identification

To check if an output belongs to a wallet:

0. If <code>K<sub>e</sub></code> or <code>K<sub>o</sub></code> does not parse as a valid secp256k1 point, the output does not belong to the wallet. Consensus does not reject such outputs (see [consensus.md](consensus.md#output-public-keys)), so a wallet must check this before any point arithmetic and must treat any failure in the steps below as "not ours" rather than an error.
1. Calculate the ECDHE point <code>P = a⋅K<sub>e</sub></code>.
2. If <code>HASH32('T'||P)[0]</code> does not match the view tag <code>t</code>, the output does not belong to the wallet.
3. Derive the shared secret <code>e = HASH32('D'||P)</code>.
4. Recover the one-time spend pubkey: <code>B<sub>i</sub> = K<sub>o</sub> / HASH32('O'||e)</code>.
5. Lookup the index <code>i</code> that generates <code>B<sub>i</sub></code> from the wallet's map <code>B<sub>i</sub>->i</code>. If not found, the output does not belong to the wallet.
6. Decrypt the value <code>v = v' &oplus; LE64(HASH32('Y'||e))</code>.
7. Decrypt the nonce <code>n = n' &oplus; HASH32('X'||e)[0,15]</code>.
8. Verify that <code>COMMIT(v, BLIND_SWITCH(v,HASH32('B'||e))) =? C<sub>o</sub></code>.
9. Calculate the send key <code>s = HASH32('S'||A<sub>i</sub>||B<sub>i</sub>||v||n)</code>.
10. Verify that <code>K<sub>e</sub> =? s⋅B<sub>i</sub></code>.

If all verifications succeed, the output belongs to the wallet, and is safe to use.

#### Spend Key Recovery

The spend key can be recovered by <code>k<sub>o</sub> = b<sub>i</sub>⋅HASH32('O'||e)</code>.

Derivation proof:<br/>
<pre>
<code>k<sub>o</sub> = b<sub>i</sub>⋅HASH32('O'||e)</code>
K<sub>o</sub> = HASH32('O'||e)⋅B<sub>i</sub>
      = HASH32('O'||e)⋅(b<sub>i</sub>⋅G)
      = (b<sub>i</sub>⋅HASH32('O'||e))⋅G
      = k<sub>o</sub>⋅G
</pre>

### Implementation Notes

* This node's MWEB uses tagged BLAKE3 hashes with one-byte domains (<code>'A'</code>, <code>'B'</code>, <code>'D'</code>, <code>'N'</code>, <code>'O'</code>, <code>'S'</code>, <code>'T'</code>, <code>'X'</code>, <code>'Y'</code>) and a multiplicative output-key tweak (<code>K<sub>o</sub> = B<sub>i</sub>⋅HASH32('O'||e)</code>).
  * This differs from some DKSAP writeups that use additive output-key tweaks or define the view tag directly as the first byte of <code>e</code>.
* Wallets must keep a map <code>B<sub>i</sub>->i</code> of all used spend pubkeys and the next several unused ones.
* Range-proof nonces for outputs this wallet creates are derived from the master scan secret via <code>DeriveRewindKey(a)</code> then <code>DeriveProofNonce(rewind_key, C<sub>o</sub>)</code> (BLAKE3 tagged hashes, not literal <code>'R'</code>/<code>'P'</code> ASCII in the hasher).
  * **Sender-key privacy vs. receipt keeping (`-mwebdeterministicsenders`):** Think of deterministic sender keys like keeping and filing cash receipts for every spend. With `-mwebdeterministicsenders=1` (24.x style), the wallet derives <code>k<sub>s</sub> = DeriveSenderSigningKey(a, i)</code> and matches on-chain <code>K<sub>s</sub></code> against that sequence (with keypool lookahead) so sent outputs can be rewound for history on rescan even when the recipient is external. With the default `-mwebdeterministicsenders=0` (21.x style), <code>k<sub>s</sub></code> is random so a captured scan key <code>a</code> cannot be used to enumerate the wallet's outgoing sends; users who want a receipt for specific sends (or every send) can export a portable payment proof ([payment-proofs.md](payment-proofs.md)).
  * **Opaque 21.x spend history tolerance:** When `-mwebdeterministicsenders=1` is enabled, historical or imported transactions that were created in 21.x random-sender style remain tolerated: owned inputs and change outputs still rewind via subaddress discovery, while unrewindable external recipient outputs are treated as opaque without failing or advancing the sender-key index (and transaction fee calculation falls back to the explicit MWEB kernel fee).
  * **Repeated `output_id` occurrence tracking:** Consensus forbids duplicate live UTXO IDs but allows a previously spent `output_id` to be recreated in a later block (for example, if two wallets share a scan secret and deterministic sender index). Wallet output and spend tracking is always occurrence-aware: `mapOutputsMWEB` indexes all occurrences per `output_id`, block scans match full transactions by block/kernel membership and disambiguate extension-block placeholders with the output's PMMR leaf index (`header.num_txos - block_outputs + output_pos`), and spentness checks bind spends to their creation height epoch.
  * <code>sender_key</code> / <code>blind</code> are stripped on disk; see [payment-proofs.md](payment-proofs.md).
* Recommended derivation paths (same as Litecoin Core):
  * Master scan key <code>(a, A)</code>: <code>m/0'/100'/0'</code>
  * Master spend key <code>(b, B)</code>: <code>m/0'/100'/1'</code>

### Address encoding (Zorkcoin)

Stealth addresses are encoded with Bech32 (not Bech32m) under the MWEB HRP: `mweb` on mainnet and `tmweb` on test/signet/regtest. This is distinct from native segwit addresses (`zork1…`, `zorktest1…`, `zorksim1…`).

The data part is a version symbol `0` followed by the 5-bit conversion of the 66 bytes <code>A<sub>i</sub>||B<sub>i</sub></code> (each a 33-byte compressed key).

Decoding currently checks only the Bech32 checksum, the HRP, and that the data converts (with valid padding) to exactly 66 bytes. As in Litecoin, it does not check the version symbol, and it does not check that <code>A<sub>i</sub></code> and <code>B<sub>i</sub></code> are valid points. An address with an invalid key decodes (and `validateaddress` reports it valid), but output construction fails when it multiplies the invalid point, so no output can be created for it. Addresses are never seen by consensus.

**@todo:** Reject a non-zero version symbol and invalid <code>A<sub>i</sub></code>/<code>B<sub>i</sub></code> points when decoding. Latest Litecoin has the same gap.

Bech32 is sufficient for MWEB because the payload has a single fixed length (the raw 66-byte key pair `(A_i, B_i)`). Bech32m was introduced because Bech32's checksum does not reliably detect inserting or deleting `q` characters just before a final `p`, which matters for variable-length segwit v1+ witness programs. Decoding requires exactly 66 bytes, so such a length change is rejected and that weakness does not apply.

### Wallet descriptors

How MWEB keys and stealth indices are stored, exported, imported, and scanned in descriptor wallets is specified in [descriptors.md](descriptors.md). That document references this file for DKSAP cryptography; it does not change the protocol math above.

The bech32 `mweb1…` / `tmweb1…` pay-to encoding includes the scan and spend public keys `(A_i, B_i)` required for a sender to construct a valid output. There is no descriptor form of a payment address; see [descriptors.md](descriptors.md).
