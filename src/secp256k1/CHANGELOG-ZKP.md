# Changelog (ZKP)

All notable changes to the ZKP modules and related packaging in this fork will be documented in this file.

The format matches [CHANGELOG.md](./CHANGELOG.md) and is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Starting with `0.8.1-zkp.3`, `MAJOR.MINOR.PATCH` is the next patch version after the upstream bitcoin-core/secp256k1 release a ZKP release is based on (as in upstream's own `-dev` versions), followed by a `-zkp` pre-release suffix. The first ZKP release on top of an upstream release is `MAJOR.MINOR.PATCH-zkp`, and later ones are `MAJOR.MINOR.PATCH-zkp.NUMBER`. (for example, tag `v0.8.1-zkp.3` is the fourth ZKP release on top of upstream `0.8.0`).

## [0.8.1-zkp.4] - 2026-10-29

#### Fixed
 - ZKP modules: Fixed `secp256k1_scalar_chacha20` on big-endian targets by reading the 32-byte seed with an explicit little-endian reader and byte-swapping ChaCha20 state words into scalar limbs unconditionally instead of gating on `WORDS_BIGENDIAN`.
 - Module `bulletproofs`: Released the verifier's scratch frame when deserializing `A`/`S` or `T1`/`T2` fails in `secp256k1_bulletproof_rangeproof_verify` and `secp256k1_bulletproof_rangeproof_verify_multi`.
 - Tests: Added deterministic `secp256k1_scalar_chacha20` test vectors, a regression test for malformed rangeproof points, a fixed-vector Pedersen commitment parse/serialize test, and BIP-schnorr signing vector checks in `schnorrsig-mw`.

#### ABI Compatibility
The ABI is backward compatible with version 0.8.1-zkp.3 (tag `v0.8.1-zkp.3`).

## [0.8.1-zkp.3] - 2026-10-04

#### Changed
 - Module `bulletproofs`: Synced the rewind API with Litecoin's secp256k1-zkp. `secp256k1_bulletproof_rangeproof_rewind` now returns a 32-byte shared and a 32-byte private payload, each recovered with its own nonce, instead of the value and blinding factor. Rewinding is unauthenticated: a wrong nonce returns unrelated bytes instead of failing, so callers must validate the recovered data.
 - Module `bulletproofs`: The optional message in `secp256k1_bulletproof_rangeproof_prove` is now 32 bytes (previously 20), replaces the value in the shared payload, and requires exactly one commitment. Prove no longer rejects blinding factors that overflow the group order or are zero.
 - Module `commitment`: The exported pointer `secp256k1_generator_h` is now `const`.
 - build: Package versions are now the next patch version after the upstream release with a `-zkp` or `-zkp.N` suffix (see above).

#### Fixed
 - Module `bulletproofs`: `secp256k1_bulletproof_rangeproof_rewind` reports a length of 0 for every message it doesn't extract and clears recovered secrets before returning. Prove rejects a message with `n_commits != 1` before the first step of a multi-party proof, and the multi-party `tauxc` zero check now tests `taux`.
 - Module `bulletproofs`: Fixed the bulletproof benchmark build after the rewind API change.
 - Scratch space: Reject allocation sizes that overflow when added to the header size (cherry-picked from upstream).
 - ci: Disabled the symbol check in the `ci/local-smoke.sh` UBSan/ASan preset, matching upstream's sanitizer job.

#### ABI Compatibility
The signature of `secp256k1_bulletproof_rangeproof_rewind` changed incompatibly, and `secp256k1_generator_h` is now a `const` pointer.
Otherwise, the library maintains backward compatibility with versions 0.8.0-zkp through 0.8.2-zkp.

## [0.8.2-zkp] - 2026-09-13

#### Fixed
 - build: Fixed C++ `-fpermissive` builds for the scratch-space API by wrapping definitions in an `extern "C"` block instead of `extern "C" SECP256K1_API` (double `extern`).

#### ABI Compatibility
The ABI is backward compatible with version 0.8.1 (tag `v0.8.1-zkp`).

## [0.8.1-zkp] - 2026-09-11

#### Fixed
 - ZKP modules: Fixed Autotools/CMake CI failures across Windows, shared-library symbol checks, sanitizers (ASan/UBSan/MSan), Valgrind, big-endian, and related build/link issues after the `v0.8.0-zkp` cut.
 - build: Restored Windows scratch-space symbol export (`SECP256K1_API` / `extern "C"`) and fixed C++ linkage against the scratch API.
 - build: Silenced `-Werror` issues (MSVC C4334, trailing whitespace) and fixed mingw static bench links via `SECP256K1_STATIC`.
 - Module `bulletproofs`: Fixed undefined behavior in test/helper shifts at `nbits == 64`, signed overflow in random helpers, and ChaCha20 limb packing.
 - Module `schnorrsig-mw` / `bulletproofs`: Initialize working scalars with `set_int(0)` instead of `scalar_clear` so Valgrind/MSan VERIFY paths stay defined.
 - sync: Updated ZKP sources to match the main ZKP branch.

#### Added
 - ci: Added `ci/local-smoke.sh` for local CI smoke testing.

#### ABI Compatibility
The ABI is backward compatible with version 0.8.0 (tag `v0.8.0-zkp`).

## [0.8.0-zkp] - 2026-09-09

#### Added
 - Ported Litecoin MWEB/ZKP modules onto bitcoin-core/secp256k1 `0.8.0` / current master APIs:
   - Module `generator`: NUMS generators, parse/serialize, and blinded generation (`include/secp256k1_generator.h`).
   - Module `commitment`: Pedersen commit, blind sum, and related scalar helpers (`include/secp256k1_commitment.h`).
   - Module `bulletproofs`: Rangeproof and inner-product prove/verify with scratch space (`include/secp256k1_bulletproofs.h`).
   - Module `aggsig`: Single and aggregated signature workflows for MWEB (`include/secp256k1_aggsig.h`).
   - Module `schnorrsig-mw`: Mimblewimble Schnorr signatures using a SHA256 challenge (not BIP-340) (`include/secp256k1_schnorrsig_mw.h`).
   - Shared scratch-space API (`include/secp256k1_scratch.h`) and ZKP helpers (`include/secp256k1_zkp.h`, including `secp256k1_ec_seckey_tweak_inv`).
 - build: Enabled ZKP modules by default in Autotools and CMake, with `--enable-module-*=no` / matching CMake options to build without them; enforced module dependencies (e.g. bulletproofs requires generator and commitment).
 - Tests: Unit tests for all ZKP modules; benches for generator and bulletproofs; exhaustive coverage for generator, commitment, aggsig, schnorrsig-mw, and partial bulletproofs; ctime coverage for secret blind/seckey/nonce paths.

#### ABI Compatibility
This is the first ZKP release on top of upstream 0.8.0. Compared to upstream 0.8.0 without ZKP modules, new public symbols are introduced for the modules listed above. Otherwise, the non-ZKP ABI matches upstream 0.8.0.

[0.8.1-zkp.4]: https://github.com/adgl-enterprises/secp256k1/compare/v0.8.1-zkp.3...v0.8.1-zkp.4
[0.8.1-zkp.3]: https://github.com/adgl-enterprises/secp256k1/compare/v0.8.2-zkp...v0.8.1-zkp.3
[0.8.2-zkp]: https://github.com/adgl-enterprises/secp256k1/compare/v0.8.1-zkp...v0.8.2-zkp
[0.8.1-zkp]: https://github.com/adgl-enterprises/secp256k1/compare/v0.8.0-zkp...v0.8.1-zkp
[0.8.0-zkp]: https://github.com/adgl-enterprises/secp256k1/compare/v0.8.0...v0.8.0-zkp
