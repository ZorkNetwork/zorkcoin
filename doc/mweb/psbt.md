# MWEB PSBTs

ADGL carries MWEB transactions in PSBT version 2 using Litecoin's wire format (LIP-0007) and LIP-0008
`mweb()` descriptors. A PSBT can hold MWEB inputs, MWEB outputs, kernels (fees, peg-ins and peg-outs) and
the transaction offsets next to ordinary transparent inputs and outputs. The same RPCs create, update,
sign, combine, analyze and finalize both kinds.

PSBTs without MWEB components are unchanged: they serialize, combine, finalize and decode exactly as in
Bitcoin Core.

- [Air-gapped hardware workflow](#air-gapped-hardware-workflow)
- [What a signer receives](#what-a-signer-receives)
- [Privacy: an MWEB PSBT is view-key sensitive](#privacy-an-mweb-psbt-is-view-key-sensitive)
- [RPCs](#rpcs)
- [External signers](#external-signers)
- [Differences from Litecoin Core](#differences-from-litecoin-core)

## Air-gapped hardware workflow

A signing device keeps the MWEB spend secret. The node runs a watch-only wallet that knows the scan
secret and the spend public key. That is enough to find the account's coins, build transactions and
fill in everything the device needs. The node never derives device keys. The device account enters the
node only through the descriptor the device exports.

The ADGL SeedSigner fork is such a device. Its MWEB account is `m/1000'/1000'/0'` on every network: the
scan key is `/0'` and the spend key is `/1'`. Subaddress 0 is change, subaddress 1 is reserved for
peg-ins, and receive addresses start at 2, as in ADGL's own wallet.

1. **Export the account from the device.** On the SeedSigner fork choose the MWEB script type and export
   the "MWEB descriptor". It has the form

   ```
   mweb([<fingerprint>/1000'/1000'/0'/0']<scan secret WIF>,[<fingerprint>/1000'/1000'/0'/1']<spend pubkey hex>,*)#<checksum>
   ```

   The scan secret uses Zorkcoin's WIF version for the device's network (167 on main, 239 on test and
   regtest). The spend key is a plain public key with its origin, so the node can derive every
   subaddress without the spend secret.

2. **Import it into a watch-only wallet.**

   ```
   zorkcoin-cli createwallet coordinator true true
   zorkcoin-cli -rpcwallet=coordinator importdescriptors '[{"desc": "<export>", "timestamp": "now", "active": true}]'
   ```

   The two `true` arguments are `disable_private_keys` and `blank`. Use the creation time of the device
   account, or 0, instead of `"now"` when the account already has coins. The wallet stores the descriptor
   as given, and `listdescriptors` exports the same form.

3. **Receive.** `getnewaddress "" mweb` on the coordinator returns the account's next receive address,
   the same one the device derives for that index. Coins paid to it appear in `listunspent` and in the
   balance once mined.

   Block scanning also watches `-mwebkeypool` (default: the `-keypool` value, 1000) subaddresses past
   the last used one, so coins paid to an address the device showed and the coordinator never issued
   appear once mined, and move the window past that address. For coins paid further out, or mined
   before the account was imported with `"now"`, run `mwebscanutxoset` (it checks subaddresses 0..1000
   of every account against the current MWEB UTXO set) or
   `mwebrescan <acct_cksum> <start_index> <end_index>`.

4. **Build the transaction.** `walletcreatefundedpsbt`, `send` and `sendall` with `"psbt": true` fund an
   unsigned PSBT from the account's MWEB coins, paying MWEB recipients, transparent recipients (peg-outs)
   or both. Specific coins can be chosen with `{"mweb_out": "<output id>"}` inputs. MWEB change goes to
   subaddress 0. Calling `walletprocesspsbt` on the coordinator adds updater data but cannot complete the
   PSBT.

5. **Carry the PSBT to the device.** The device shows the recipients and the fee, then signs with only
   the data in the PSBT. The fee it shows is the total the transaction pays: transparent inputs minus
   transparent outputs (peg-in outputs included), plus kernel fees. It does not list peg-in outputs as
   recipients. It refuses a PSBT whose input address descriptors carry a scan key WIF for another
   network. For each MWEB input the device takes the
   subaddress index from `PSBT_IN_MWEB_ADDR_DESCRIPTOR`, re-derives the address and refuses to sign if it
   does not own the coin.

6. **Finalize and broadcast.** Bring the signed PSBT back, then run `finalizepsbt` and
   `sendrawtransaction`. `combinepsbt` merges PSBTs signed separately.

The same flow works with a node instead of a device: an offline node can sign with a wallet holding the
private `mweb()` account (`walletprocesspsbt`), or with no wallet at all by passing the private
descriptor to `descriptorprocesspsbt`.

The functional tests `mweb_psbt_watchonly_signer.py` and `mweb_psbt_seedsigner_interop.py` run this
workflow. The second one drives the SeedSigner fork's signer, which runs in a container, through
`$ADGL_MWEB_SIGNER`. Unsigned PSBTs from `mweb_psbt_watchonly_signer.py --dumpvectors` are committed under
`src/test/data/mweb_psbt_interop/`; `mweb_psbt_interop_vectors.py` checks that each one decodes to its
recorded recipients and fee and that the recorded device keys sign it.

## What a signer receives

For every MWEB input the wallet knows, the updater writes what a keyless signer needs, whether or not
the wallet signs:

| Field | Key |
|-------|-----|
| Output ID | `PSBT_IN_MWEB_OUTPUT_ID` (0x90) |
| Output commitment | `PSBT_IN_MWEB_COMMIT` (0x91) |
| Output public key | `PSBT_IN_MWEB_OUTPUT_PUBKEY` (0x92) |
| Address descriptor | `PSBT_IN_MWEB_ADDR_DESCRIPTOR` (0x96) |
| Amount | `PSBT_IN_MWEB_AMOUNT` (0x97) |
| Shared secret and/or key-exchange public key | `PSBT_IN_MWEB_SHARED_SECRET` (0x98), `PSBT_IN_MWEB_KEY_EXCHANGE_PK` (0x99) |

The address descriptor is the single-address LIP-0008 form with key origins,
`mweb([fp/path]<scan WIF>,[fp/path]<spend pubkey>,<index>)#<checksum>`. Its origins are the wallet's
own, or those of the imported descriptor, preserved exactly. A 4-byte legacy value is ignored on read
and never written. The scan key must be private, as in Litecoin Core: a descriptor with a public scan
key, such as `mweb(<hex>,<hex>)`, makes processing the PSBT fail with "MWEB address descriptor has no
scan private key".

`decodepsbt` shows these fields under each input's `mweb` object (`output_id`, `output_commit`,
`output_pubkey`, `address_descriptor`, `amount`, `shared_secret`, `key_exchange_pk`, and `signature`
once signed). Kernels and offsets appear at the top level as `kernel_count`, `kernels`,
`mweb_tx_offset` and `mweb_stealth_offset`.

## Privacy: an MWEB PSBT is view-key sensitive

An MWEB PSBT from an ADGL wallet contains the account's **scan secret** (in ADGL's WIF encoding inside
every input's address descriptor) and the **shared secrets** of the coins it spends. Anyone holding the
PSBT can identify every coin the account receives and see its amount. They cannot spend the coins. Treat
an MWEB PSBT like a view key: do not post it publicly or send it over channels you would not trust with
your wallet's history. Because the account's range-proof nonces are derived from the scan secret, the
PSBT also reveals the amounts of outputs the account sent. Neither the scan secret nor the shared
secrets are removed after signing or finalizing (LIP-0007 says signers SHOULD remove them).

## RPCs

| RPC | MWEB behaviour |
|-----|----------------|
| `createpsbt` | Inputs may be `{"mweb_out": "<output id>"}`. Stealth addresses become MWEB outputs. With only MWEB inputs, transparent outputs become kernel peg-outs. Mixing transparent and MWEB inputs, duplicated `mweb_out` entries, and data outputs as peg-outs are rejected. MWEB needs `psbt_version` 2 ("MWEB PSBTs require PSBT version 2"). |
| `converttopsbt` | Converts a transaction with an MWEB part to a version 2 PSBT. Fails with "MWEB output amounts are not known from a serialized transaction; use createpsbt or walletcreatefundedpsbt" when MWEB output amounts are unknown, and with "MWEB PSBTs require PSBT version 2" for `psbt_version` 0. |
| `createrawtransaction` | Never represents MWEB inputs or stealth outputs as raw hex; it errors and points to `createpsbt`. |
| `utxoupdatepsbt` | Fills MWEB inputs (commitment, output pubkey, key-exchange pubkey) from the MWEB UTXO set and mempool by output ID. |
| `decodepsbt` | Shows MWEB input and output objects, kernels (each with its `fee`) and offsets. The top-level `fee` is the whole fee: every input amount (transparent UTXOs and MWEB `mweb_amount`) plus kernel peg-in amounts, minus every output amount (transparent and MWEB) and kernel peg-out amounts. It is omitted when any input amount is missing, or when any amount or running total is out of range. |
| `analyzepsbt` | Reports `estimated_mweb_weight` for PSBTs with MWEB components, and a fee rate over the transparent size after the MWEB weight fee. The next role accounts for MWEB signatures. |
| `combinepsbt` | Merges MWEB fields strictly: conflicting values are an error. |
| `finalizepsbt` | Extracts the transaction once every MWEB component is signed. It fails while a peg-in output still has its placeholder script; the MWEB signer rewrites that script to the kernel ID. |
| `joinpsbts` | Version 0 only, so it never handles MWEB. |
| `descriptorprocesspsbt` | Signs MWEB inputs, outputs and kernels with private `mweb()` descriptors (ranged accounts use `range`, default 0..1000) or a private input address descriptor. A watch-only account descriptor fills input amounts but signs nothing. Transparent inputs are not signed while MWEB signing data is missing. |
| `walletcreatefundedpsbt` | Funds MWEB transactions as unsigned PSBTs, from watch-only and locked wallets too. Accepts `mweb_out` inputs. `changepos` counts MWEB change after the transparent outputs. `lockUnspents` locks MWEB inputs. |
| `send`, `sendall` | With `"psbt": true`, return an unsigned MWEB PSBT for wallets that cannot sign. Accept `mweb_out` inputs. |
| `walletprocesspsbt` | Fills and signs MWEB components before transparent inputs. It does not sign transparent inputs while MWEB is incomplete. |
| `fundrawtransaction` | Rejects HogEx-marked input hex because HogEx is miner-only. Refuses MWEB results ("fundrawtransaction cannot return MWEB transaction hex; use walletcreatefundedpsbt for MWEB funding"). |
| `lockunspent`, `listlockunspent` | Accept and list MWEB coins as `{"mweb_out": "<output id>"}`. |
| `importdescriptors`, `listdescriptors` | Import and export the watch-only account form `mweb([fp/path]<scan WIF>,[fp/path]<spend pubkey>,*)`. |
| `mwebscanutxoset`, `mwebrescan` | Find coins paid to subaddresses past the lookahead window, or mined before the account was imported. |

## GUI

"Create Unsigned" and Send in an external-signer wallet build the PSBT from the MWEB part the wallet
funded, as `walletcreatefundedpsbt` does. In a wallet that signs its sends, "Create Unsigned" (shown
when PSBT controls are enabled) leaves out the signatures the wallet made while preparing the send,
and restores a peg-in output's placeholder script. A watch-only or external-signer wallet counts the MWEB coins
selected in coin control even though it holds no spend keys for them, as `sendall` does, so it can peg
out from them.

## External signers

A `-signer` wallet can hold one MWEB account. No released hardware wallet or HWI version supports MWEB
yet; the interface below is what a signer must implement, and `test/functional/mocks/mweb_signer.py`
implements it for the tests.

- Wallet creation: `getdescriptors` may return the account in `receive` as
  `mweb([fp/path]<scan WIF>,[fp/path]<spend pubkey>,*)`. The scan secret is required, because the wallet
  scans for its coins; it is kept in the wallet's scan key record, like a watch-only account's. MWEB
  descriptors in `internal`, and other MWEB forms, are skipped: change goes to the account itself.
- Signing: when an unsigned MWEB input is one of the wallet's coins and the fingerprint of its address
  descriptor matches the signer, the wallet sends the PSBT with `signtx` before any transparent input is
  signed. No signer command runs when none of the inputs is the wallet's coin, and only `enumerate` runs
  when none of them matches the signer. Inputs whose descriptor doesn't match the signer, such as coins
  of an imported account, are sent without their address descriptor. The signer must sign the MWEB
  inputs, outputs and kernel. Its PSBT is merged with the strict MWEB merge, so a signer that changes
  MWEB data fails the send ("External signer failed to sign") and leaves the wallet's PSBT unchanged;
  fields it leaves out keep the wallet's values.
- `walletdisplayaddress`: sends `displayaddress --desc mweb([fp/path]<scan WIF>,[fp/path]<spend pubkey>,i)`
  over stdin, so the scan secret is not on the signer's command line, and checks the echoed address.
  Addresses of other accounts in the wallet, such as imported watch-only accounts whose key origins
  don't carry the signer's fingerprint, are refused before their descriptor is sent to the signer.

The signer receives the scan secret in input address descriptors and in `displayaddress`, so it can see
the account's received and sent amounts. The wallet does not write MWEB PSBTs to its log.

The wallet does not learn the values of payment outputs the signer creates, so `gettransaction` counts
them in the fee, as it does for a watch-only wallet whose PSBTs are signed elsewhere. Balances and change
are correct.

## Differences from Litecoin Core

### Consensus and policy

- The canonical-kernel rules (`bad-mweb-empty-pegout`, `bad-mweb-empty-extradata`) apply from height 0
  on every ADGL chain. MWEB has never been active on these networks, so there is no history to
  grandfather.
- The txid of an MWEB-only transaction stays the hash of its first kernel, as deployed in Litecoin 0.21.x.
  Litecoin Core 24.x uses the MWEB transaction hash.
- Mempool rejection of an invalid MWEB transaction keeps ADGL's reason `bad-mweb-txn`. Litecoin Core
  appends the consensus error (`bad-mweb-txn-<error>`).

### MWEB signing (libmw)

- Signing is transactional: on failure the transaction is unchanged. Litecoin Core leaves partially
  signed kernels and outputs behind.
- An input whose spend key does not match its output pubkey is refused. Litecoin Core silently
  overwrites the output pubkey, producing an input that does not reference the coin.
- An input whose amount and blinding factor do not open the given commitment is refused. Litecoin Core
  overwrites the commitment.
- Spend-key derivation refuses a coin whose recorded subaddress index does not derive its address,
  before looking for a key-store key. Litecoin Core looks in the key store first.
- Unsigned MWEB outputs compare equal only when their range proof bytes are equal. Litecoin Core
  compares proof object identity.
- A wallet may hold several MWEB accounts. The PSBT filler finds the keychain for each input by scan key.
- A watch-only keychain is built from the scan secret and the spend public key. It derives the same
  addresses and finds the same coins as the full keychain, and cannot sign.

### PSBT format, merge and finalize

The wire format is identical to Litecoin Core's: Litecoin Core's PSBT test vectors round-trip byte for
byte. The differences are in edge cases and in PSBTs without MWEB components.

- PSBTs without MWEB components merge and finalize exactly as in Bitcoin Core: version 0 and version 2
  PSBTs do not mix, conflicting unknown fields keep the first PSBT's value, and input proprietary fields
  are merged. Such a PSBT is never checked for peg-in outputs, even with a final peg-in script and no
  kernels. Litecoin Core applies its MWEB checks to every PSBT.
- `PSBT_GLOBAL_TX_MODIFIABLE`: PSBTs with MWEB components merge it by OR, treat an absent field as no
  information and clear it once any MWEB signature or range proof exists, as Litecoin Core does. PSBTs
  without MWEB components keep Bitcoin Core's BIP-370 merge. Litecoin Core ORs for every PSBT.
- MWEB merges compare stray previous-txid and output-index fields of MWEB inputs strictly. Litecoin Core
  silently keeps the first PSBT's values. Merging also requires equal PSBT versions.
- MWEB inputs keep stray `PSBT_IN_PREVIOUS_TXID` / `PSBT_IN_OUTPUT_INDEX` values exactly, and an all-zero
  stray txid is not re-emitted, as in Litecoin Core. MWEB outputs keep an explicit empty `PSBT_OUT_SCRIPT`.
  Merging an empty script with a non-empty one fails.
- An explicit global kernel count of 0 is accepted and omitted on re-serialization. Kernel keys starting
  0xfd..0xff are single-byte unknown types and are preserved.
- `PSBT_IN_MWEB_ADDR_DESCRIPTOR` must be printable ASCII starting with `mweb(`. A 4-byte legacy value is
  ignored on read and never written.
- Verifying an MWEB input signature never throws on invalid points or public keys. Litecoin Core can
  throw.
- Reading an input's UTXO or building the unsigned transaction checks for a missing previous output
  index. Litecoin Core dereferences it.
- An MWEB signature counts as a signature only on an MWEB input.
- Signing reports an MWEB input as incomplete unless its signature is present and verifies. Litecoin
  Core reports some such inputs as signed.
- Adding a transparent input or output to a PSBT inserts it before the first MWEB entry. Litecoin Core
  appends it and breaks the ordering.
- A version 0 PSBT built from a transaction with an MWEB part carries no MWEB components. RPCs reject
  MWEB with `psbt_version` 0 up front. Serializing a version 0 PSBT that has MWEB fields fails, as in
  Litecoin Core.
- The standard fields of an MWEB output taken from a signed transaction are derived from its feature
  bits.
- Key-size and key-type parse errors use Bitcoin Core's generic wording.

### RPCs

- `createpsbt` keeps Bitcoin Core's arguments: `version` is the fifth positional argument and
  `psbt_version` the sixth (default 2). In Litecoin Core `psbt_version` is the fifth and there is no
  `version`. MWEB with `psbt_version` 0 is rejected with the same error as in Litecoin Core.
- `converttopsbt` keeps its `psbt_version` argument (fourth positional, default 2), which Litecoin Core
  does not have. A transaction whose MWEB output amounts are unknown is an RPC error.
  `converttopsbt` does not strip MWEB signatures, as in Litecoin Core.
- `createpsbt` rejects a duplicated `mweb_out`. Litecoin Core accepts it and builds an invalid draft.
  `createpsbt` also does not turn data outputs into peg-outs of MWEB-only inputs. Litecoin Core builds
  an unspendable peg-out.
- `createrawtransaction` never represents MWEB inputs or stealth outputs as raw hex.
- `decodepsbt` prints `kernel_count` and `kernels` only for PSBTs with MWEB components. Litecoin Core
  always prints them.
- `analyzepsbt` reports `estimated_mweb_weight` only for PSBTs with MWEB components. Litecoin Core
  always reports it, as 0 for other PSBTs.
- Transaction JSON shows `mweb_weight` only for transactions with an MWEB part, and keeps ADGL's
  `ismweb`.
- `utxoupdatepsbt` skips MWEB inputs that already carry a non-witness UTXO.
- `descriptorprocesspsbt` signs MWEB inputs, outputs and kernels. Litecoin Core never signs MWEB there.
  Keys come from private `mweb()` descriptors or a private input address descriptor, and input amounts
  are recovered by rewinding the on-chain output.
- `descriptorprocesspsbt` signs MWEB before transparent inputs. It does not sign transparent inputs while
  an MWEB input lacks signing data or a peg-in output keeps its placeholder script.
- `descriptorprocesspsbt` reports an MWEB PSBT complete only if finalizing a copy succeeds. Other PSBTs
  keep Bitcoin Core's check.
- `descriptorprocesspsbt` accepts watch-only `mweb()` account descriptors: they fill MWEB input amounts
  but sign nothing. An inconsistent input address descriptor or an unsignable MWEB transaction is an RPC
  error.
- `-signer` wallets can hold an MWEB account and send MWEB PSBTs to the signer (see
  [External signers](#external-signers)). Litecoin Core's 24.x branch matches MWEB key origin
  fingerprints in `ExternalSigner::SignTransaction`, but its external signer wallets have no MWEB
  account setup, address display or MWEB merge.

### Descriptors

- Two-argument `mweb(<scan WIF>, <extended spend key>)` descriptors are ranged accounts, as in Litecoin
  Core's 24.x branch. Two-argument forms with a plain spend public key remain single-address descriptors.
  LIP-0008 defines every two-argument form as a single subaddress, so this is a deviation from the draft.
- `listdescriptors` without private keys exports an MWEB account as
  `mweb([fp/path]<scan WIF>,[fp/path]<spend pubkey hex>,*)`. A hardened path under an xpub would hide
  the spend public key. Importing that form into a `disable_private_keys` wallet gives a working
  watch-only account. An account whose spend public key is unknown exports the stored hardened-xpub
  form instead, which does not import as a working watch-only account.

### Wallet

- A wallet MWEB fill or signing failure is reported as "The transaction cannot be valid". Litecoin Core
  reports "PSBT is not well-formed".
- By default (`-mwebdeterministicsenders=0`), new MWEB outputs signed by the wallet use random
  ephemeral sender keys (matching Litecoin Core 0.21 privacy behaviour, so a captured scan secret
  does not reveal outgoing sends). Passing `-mwebdeterministicsenders=1` opts into deterministic
  sender keys (`DeriveSenderSigningKey` from the active account scan secret and a durable per-scan
  index, matching Litecoin Core 24.x receipt-keeping behaviour); existing wallets that already have
  a persisted non-zero `mweb_sender_key_index` continue using deterministic sender keys unless
  `-mwebdeterministicsenders=0` is explicitly set. Paths without an MWEB account always use random
  sender keys.
- Wallet output tracking is occurrence-aware across both modes: if a spent MWEB `output_id` is later
  recreated on-chain (for example, by two wallets sharing a scan secret under deterministic sender
  keys), full transactions are matched by their block/kernel membership and extension-only
  placeholders are disambiguated by their TXO PMMR leaf index.
- While the MWEB components are incomplete, the wallet still adds transparent updater data (UTXOs,
  derivation paths) but does not sign transparent inputs.
- `fundrawtransaction` never locks MWEB inputs. It refuses MWEB results with Litecoin Core's wording,
  and locks transparent inputs only after that check.
- Watch-only and locked wallets fund unsigned MWEB PSBTs from coins they cannot spend
  (`walletcreatefundedpsbt`, `send`/`sendall` with `"psbt": true`). Signed sends still need the spend
  key and keep the locked-wallet and watch-only error messages.
- A locked wallet's `sendall` returns an incomplete PSBT instead of an error, which is Bitcoin Core's
  behaviour for a wallet that cannot sign.
- `walletcreatefundedpsbt` and `sendall` take MWEB inputs as `{"mweb_out": id}`. `send` takes
  `mweb_out` and still accepts ADGL's `output_id`. Explicit MWEB inputs disable automatic input
  selection unless `add_inputs` is set. When they fall short and `add_inputs` is set, more MWEB coins
  are added. Otherwise the error is "Insufficient funds".
- Spending an explicit MWEB input the wallet cannot find fails with ADGL's "Unable to find MWEB output".
  Litecoin Core says "Unable to find UTXO for external input".
- MWEB coin locks are stored under their own wallet database key, `lockedmwebutxo`, keyed by output ID.
  Litecoin Core reuses `lockedutxo` with a variant outpoint. Older ADGL software ignores the new key.
  Locked MWEB coins are hidden from `listunspent` and skipped by automatic selection and `sendall`, but
  can be selected explicitly, and balances do not change. A lock is released when the coin is spent.
- `lockunspent` validates every MWEB entry before changing any lock, and rejects entries mixing
  `mweb_out` with `txid`/`vout`.
- `sendall` sweeps MWEB coins and pays MWEB recipients through the MWEB transaction builder.
  Transparent-only sweeps keep Bitcoin Core's code path. A wallet that can sign sweeps only coins it
  holds the spend key for.
- With subtract-fee-from-outputs, peg-in coin selection adds no peg-in fee allowance, so a sweep of
  exactly the available funds succeeds. Litecoin Core over-targets and fails. A zero-value MWEB change
  output is never created, and the fee of a sweep that leaves nothing does not pay for one, for
  MWEB-to-MWEB, peg-in, peg-out and mixed sweeps. Litecoin Core can create one when a sweep leaves nothing.
- A peg-in that also pays transparent recipients builds. Transparent subtract-fee recipients on a
  peg-in pay their share of the fee, with Litecoin Core's dust check.
- Automatic coin selection for a transaction paying both MWEB and transparent recipients never combines
  transparent and MWEB coins. When neither kind alone covers the payment, it fails with "Insufficient
  funds", where Litecoin Core falls back to a peg-in plus peg-out transaction. Selecting both kinds of
  coins explicitly still builds one.
- A stealth change address on a transaction that neither spends MWEB coins nor pays an MWEB recipient is
  refused with "MWEB change is incompatible with this transaction type". Litecoin Core pegs the inputs
  in and pays the recipients as peg-outs.
- A watch-only account finds coins paid to subaddresses it has not handed out through its lookahead
  window of `-mwebkeypool` subaddresses past the last used one, as Litecoin Core's keypool does; only
  coins paid further out need `mwebrescan` or `mwebscanutxoset`. Litecoin Core stores its keypool
  addresses in the wallet; this tree derives the window again on each load.
- `getrawchangeaddress mweb` returns the active account's change address, subaddress 0, for
  watch-only accounts too. It is the same address on every call and appears on the account's
  change coins. Released Litecoin Core rejects `getrawchangeaddress mweb`; its 24.x branch reserves a
  new MWEB subaddress from its keypool on each call.
