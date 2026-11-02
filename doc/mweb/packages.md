# MWEB Packages

A package submitted with `submitpackage` or `testmempoolaccept` may contain MWEB transactions, including MWEB-only ones. A transaction in a package can spend an MWEB output created by an earlier transaction in the same package, so a fee-paying child can bring in a parent that is below the minimum fee on its own. This follows Litecoin Core 24.x, adapted to this tree's package rules (cluster mempool, package RBF, TRUC). Upstream package rules: [doc/policy/packages.md](../policy/packages.md).

Packages linked only by MWEB outputs are **local only**: peers never find a package parent through an MWEB output (see [Why packages are local only](#why-packages-are-local-only)).

## Package rules

MWEB inputs name the output ID they spend, not a txid and index. Every context-free package check follows MWEB output IDs alongside L1 outpoints (`src/policy/packages.cpp`):

| Check | MWEB rule | Reject |
|---|---|---|
| `IsTopoSortedPackage` | A transaction may not spend an MWEB output created by a later package transaction. | `package-not-sorted` |
| `IsConsistentPackage` | No two package transactions spend the same MWEB output. A transaction with MWEB inputs and no L1 inputs is allowed; one with neither is not. | `conflict-in-package` |
| `IsChildWithParents` | A transaction is a parent when the child spends one of its MWEB outputs. | `package-not-child-with-parents` |
| `IsChildWithParentsTree` (`submitpackage`) | Parents may not spend each other's MWEB outputs. | `package topology disallowed` |

The sets of MWEB output IDs use `SaltedMWHashHasher` (`src/util/hasher.h`), a salted SipHash like Litecoin 24.x's, because MWEB input IDs are chosen by the sender.

`MAX_PACKAGE_WEIGHT` (404,000) counts L1 weight only, as `GetTransactionWeight` does. On nodes enforcing standardness, MWEB weight per transaction is already capped at `MAX_STANDARD_MWEB_TX_WEIGHT` (4,000), so a 25-transaction package carries at most 100,000 MWEB weight, half the consensus MWEB block limit. With `-acceptnonstdtxn` only the consensus limit applies to each transaction.

## Package outputs during validation

`CCoinsViewMemPool::PackageAddTransaction` stages each package transaction's MWEB outputs in `m_temp_added_mweb`, and `GetMWEBCoin` looks there first, before the mempool and chain. `Reset()` clears them after each subpackage, so a failed or `test_accept` package leaves nothing behind. Once the package is submitted, the mempool's MWEB index links children to their MWEB parents as for any MWEB transaction.

## Fees

* **Minimum fee:** a package pays the L1 minimum fee rate on its total vsize plus `GetMWEBFee` on its total MWEB weight (`CheckFeeRate`), as a single MWEB transaction does.
* **Effective fee rate:** `MWEB::MempoolAccept::EffectiveFeeRate` rates a transaction or package with MWEB weight by its adjusted weight, sigop-adjusted L1 weight plus MWEB weight (the measure the mempool ranks by), divided by 4 and rounded up. Without MWEB weight it is upstream's fee over vsize. `testmempoolaccept` and `submitpackage` report it as `effective-feerate`, which upstream's formula would give as 0 for MWEB-only transactions (no L1 vsize). Both RPCs also report `mweb_weight` for transactions with MWEB data (`MempoolAcceptResult::m_mweb_weight`).
* **Package RBF:** the "package is its own chunk" rule compares the package's effective fee rate with the parent's, so an MWEB-only parent and child can replace a mempool transaction. The 1.5x MWEB replacement rule ([consensus.md](./consensus.md#standardness-non-consensus)) and upstream's other package RBF rules are unchanged.

## TRUC

Litecoin has no TRUC. Here, `PackageTRUCChecks` finds in-package parents, siblings and children through MWEB outputs too, so the TRUC ancestor and descendant limits and the version inheritance rules apply to MWEB links. For a transaction with MWEB weight, `TRUC_MAX_VSIZE` and `TRUC_CHILD_MAX_VSIZE` are checked against its adjusted weight in vbytes (`MWEB::MempoolAccept::AdjustedVSize`) instead of its L1 vsize, both alone and in a package. The wallet's v3 weight caps (`TRUC_MAX_WEIGHT`, `TRUC_CHILD_MAX_WEIGHT`) still count L1 weight only, as they already ignore the sigop adjustment, so a v3 wallet transaction within its MWEB weight / 4 vbytes of a cap can be built and then refused by the mempool.

## Differences from Litecoin 24.x

Litecoin 24.x predates reconsiderable rejections and individual-first package evaluation. The ported tests keep this tree's results:

| Case | Litecoin 24.x | This tree |
|---|---|---|
| Parent below the minimum fee, alone | `TX_MEMPOOL_POLICY` | `TX_RECONSIDERABLE`, `mempool min fee not met` |
| Package below its minimum fee | `PCKG_POLICY`, `package-fee-too-low` | `PCKG_TX`, `transaction failed`; the child's result is `mempool min fee not met` |

`submitpackage` first tries each transaction alone; only those failing on fees or missing inputs are validated as a package. `testmempoolaccept` validates the whole package together.

## Why packages are local only

The wtxid is computed without the MWEB body (`TX_NO_MWEB`), and an MWEB-only transaction's txid and wtxid are both the hash of its first kernel, so neither commits to the MWEB inputs, outputs or proofs. Upstream package relay keys orphans, rejections and parent requests by txid and wtxid, and finds parents through L1 prevouts. For MWEB links that would let a peer substitute a different body under the same identity, or force repeated revalidation of bodies that can't be cached by identity. Nodes therefore never look for a package parent through an MWEB input.

Upstream's opportunistic 1-parent-1-child relay still applies through L1 links. A child kept as an orphan for a missing L1 parent is paired with that parent when the parent is rejected for its fee. The pair may carry MWEB data, such as a peg-in parent, and if the child also spends one of the parent's MWEB outputs, that link resolves in the package. An orphan with MWEB data and no missing L1 parent is not kept, so an MWEB-only child never forms a package from P2P messages.

After `submitpackage`, each transaction is announced on its own. A peer accepts it only if it passes that peer's policy alone, so a package whose parent is below the minimum fee is mined by the submitting node (or one it reaches out of band) rather than propagated.

## Combining a parent and child is not a substitute

Merging a parent and child into one MWEB transaction doesn't replace packages:

* Cut-through of the parent's output and the child's input fails the stealth-sum balance check unless done by whoever holds both transactions' keys. The recipient, who is the one paying through a child, doesn't hold the parent's keys; the parent's sender can already replace the parent by fee.
* Without cut-through, the merged transaction's input spends an output created in the same transaction. The mempool looks up MWEB inputs only in the chain and the mempool, so it is refused with `bad-txns-inputs-missingorspent`.
* An MWEB-only transaction's txid and wtxid are its first kernel's hash, and kernels are sorted, so the merged transaction has the parent's or the child's ID. If that transaction is in the mempool, `PreChecks` refuses the merge as `txn-already-in-mempool` before replacement is considered, and peers never request it.

A package is only needed when the parent is below the minimum fee: once the parent is in the mempool, a child alone raises its priority.

## Tests

| Test | Coverage |
|---|---|
| `src/test/mweb_package_tests.cpp` | Litecoin 24.x `package_*` cases; duplicate MWEB spends by package parents; context-free MWEB checks; MWEB-only package RBF; effective fee rate and `m_mweb_weight`; TRUC parent detection and adjusted-weight size limit; a P2P 1-parent-1-child pair with an MWEB link beside its L1 link; size trimming evicts a peg-in and its MWEB child together |
| `test/functional/mweb_mempool.py` | MWEB parent and child through `testmempoolaccept` and `submitpackage`; a conflicting MWEB spend pair |
| `test/functional/mweb_truc_mempool.py` | A v3 MWEB parent and child accepted by `submitpackage` |
