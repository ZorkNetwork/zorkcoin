# Quantum Resistance

**TL;DR:** When the time comes, we will be able to transition MWEB to quantum-resistant cryptography following a similar process and similar security guarantees as for traditional transparent addresses on this chain.

## Background

Elliptic curve cryptography (ECC) uses points on a curve that can be "added" together. Curve points are written with capital letters and scalars (integers) with lowercase letters.

Wallet addresses are derived from a public key (`P`, a curve point), which is calculated from a private key (`k`, a scalar). `P` is `k` times a special point `G` on the curve, the generator: `P = k*G`.

In classical computing it is easy to calculate `P` from `k`, but infeasible to calculate `k` from `P`. That is the elliptic curve discrete logarithm problem (ECDLP).

Quantum computers can solve certain problems much faster than classical computers. One of those problems is the ECDLP, so large-scale quantum computers could theoretically break ECC-based systems.

## Pedersen Commitments

MWEB does not use transparent addresses for shielded amounts. It uses Pedersen commitments: a curve point `C` derived from a blinding factor `r` and a value `v` with generators `G` and `H`:

`C = v*H + r*G`.

See also [Grin / Mimblewimble notes on Pedersen commitments](https://docs.grin.mw/wiki/introduction/mimblewimble/mimblewimble/).

### Perfectly Hiding, Computationally Binding

Security relies on the discrete-log relationship between `H` and `G` remaining unknown: there exists an `x` such that `x*H = G`, but `x` is not known.

Pedersen commitments are perfectly hiding (a single commitment does not reveal `v`) but only computationally binding: with a break of that relationship, an attacker could find another `(v', r')` that opens the same `C`, for example `r' = r - i*x` and `v' = v + i`, creating `i` coins out of thin air.

## Switch Commitments

MWEB derives output blinding factors with a switch commitment so that, later, the network can require a stricter proof when spending existing coins and block that inflation path, migrating toward ElGamal-style commitments without revealing old values automatically.

In this tree, switch blinding is `secp256k1_blind_switch`: `r + SHA256(ser33(v*H + r*G) || ser33(r*J))` (SHA256 of two compressed points; not BLAKE3). See [stealth-addresses.md](stealth-addresses.md) (`BLIND_SWITCH`).

Further reading: [Grin switch commitments](https://docs.grin.mw/wiki/miscellaneous/switch-commitments/) and [eprint 2017/237](https://eprint.iacr.org/2017/237.pdf).

## Summary

MWEB, like transparent ECC addresses, is vulnerable to future quantum breaks of ECDLP. Switch commitments keep a path to require stricter proofs in time, avoiding inflation risk without automatically revealing historical amounts. Activating those proofs before a practical ECDLP break preserves the money supply the same way a timely transparent-address migration would.
