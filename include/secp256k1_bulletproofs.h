#ifndef SECP256K1_BULLETPROOF_H
#define SECP256K1_BULLETPROOF_H

# include "secp256k1.h"
# include "secp256k1_generator.h"
# include "secp256k1_commitment.h"
# include "secp256k1_scratch.h"

# ifdef __cplusplus
extern "C" {
# endif

/** Opaque structure representing a large number of NUMS generators */
typedef struct secp256k1_bulletproof_generators secp256k1_bulletproof_generators;

/* Maximum depth of 31 lets us validate an aggregate of 2^25 64-bit proofs */
#define SECP256K1_BULLETPROOF_MAX_DEPTH 31

/* Size of a hypothetical 31-depth rangeproof, in bytes */
#define SECP256K1_BULLETPROOF_MAX_PROOF (160 + 36*32 + 7)

/** Allocates and initializes a list of NUMS generators, along with precomputation data
 *  Returns a list of generators, or NULL if allocation failed.
 *  Args:          ctx: pointer to a context object (cannot be NULL)
 *  In:   blinding_gen: generator that blinding factors will be multiplied by (cannot be NULL)
 *                   n: number of NUMS generators to produce
 */
SECP256K1_API secp256k1_bulletproof_generators *secp256k1_bulletproof_generators_create(
    const secp256k1_context* ctx,
    const secp256k1_generator *blinding_gen,
    size_t n
) SECP256K1_ARG_NONNULL(1);

/** Destroys a list of NUMS generators, freeing allocated memory
 *  Args:   ctx: pointer to a context object (cannot be NULL)
 *          gen: pointer to the generator set to be destroyed
 */
SECP256K1_API void secp256k1_bulletproof_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bulletproof_generators *gen
) SECP256K1_ARG_NONNULL(1);

/** Verifies a single bulletproof (aggregate) rangeproof
 *  Returns: 1: rangeproof was valid
 *           0: rangeproof was invalid, or out of memory
 *  Args:       ctx: pointer to a context object initialized for verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  In:       proof: byte-serialized rangeproof (cannot be NULL)
 *             plen: length of the proof
 *        min_value: array of minimum values to prove ranges above, or NULL for all-zeroes
 *           commit: array of pedersen commitment that this rangeproof is over (cannot be NULL)
 *        n_commits: number of commitments in the above array (cannot be 0)
 *            nbits: number of bits proven for each range
 *        value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
 *     extra_commit: additonal data committed to by the rangeproof (may be NULL if `extra_commit_len` is 0)
 *     extra_commit_len: length of additional data
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bulletproof_rangeproof_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char* proof,
    size_t plen,
    const uint64_t* min_value,
    const secp256k1_pedersen_commitment* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* value_gen,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(10);

/** Batch-verifies multiple bulletproof (aggregate) rangeproofs of the same size using same generator
 *  Returns: 1: all rangeproofs were valid
 *           0: some rangeproof was invalid, or out of memory
 *  Args:       ctx: pointer to a context object initialized for verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  In:       proof: array of byte-serialized rangeproofs (cannot be NULL)
 *         n_proofs: number of proofs in the above array, and number of arrays in the `commit` array
 *             plen: length of every individual proof
 *        min_value: array of arrays of minimum values to prove ranges above, or NULL for all-zeroes
 *           commit: array of arrays of pedersen commitment that the rangeproofs is over (cannot be NULL)
 *        n_commits: number of commitments in each element of the above array (cannot be 0)
 *            nbits: number of bits in each proof
 *        value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
 *     extra_commit: additonal data committed to by the rangeproof (may be NULL if `extra_commit_len` is 0)
 *     extra_commit_len: array of lengths of additional data
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bulletproof_rangeproof_verify_multi(
    const secp256k1_context* ctx,
    secp256k1_scratch* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char* const* proof,
    size_t n_proofs,
    size_t plen,
    const uint64_t* const* min_value,
    const secp256k1_pedersen_commitment* const* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* value_gen,
    const unsigned char* const* extra_commit,
    size_t *extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(8);

/** Extracts the shared and private rewind payloads from a single-commit rangeproof given secret nonces
 *
 *  Rewinding is not authenticated. A wrong nonce, or a commit, min_value or extra_commit other than the ones
 *  the proof was created with, still returns 1 and yields unrelated bytes. The caller must validate the
 *  recovered data itself, e.g. by recomputing the Pedersen commitment from it. MWEB wallets do this by
 *  rebuilding the output commitment from the recovered shared message and discarding the output on mismatch.
 *
 *  The message flags stored in the high nibble of proof[64] are not bound by the proof and are ignored by
 *  verification, so anyone relaying a proof can change them without invalidating it. A changed flag makes
 *  this function return 0 or recover the wrong message. Callers that need rewinding to be reliable must
 *  authenticate the full proof bytes by other means. MWEB does this: the sender's output signature covers a
 *  hash of the entire proof, so a modified proof invalidates the output.
 *
 *  Returns: 1: every requested message whose nonce was given was extracted (but see above)
 *           0: the proof is malformed or a message could not be decoded; nothing was extracted
 *  Args:       ctx: pointer to a context object (cannot be NULL)
 *  Out: shared_msg: pointer to array for the 32-byte shared message to be extracted
 *  In/Out: shared_msg_len: in: size of shared_msg (at most 32 bytes are written). Out: number of bytes
 *                  written, or 0 if no shared message was extracted (cannot be NULL if shared_msg is not NULL)
 *      private_msg: pointer to array for the 32-byte private message to be extracted
 *  In/Out: private_msg_len: in: size of private_msg (at most 32 bytes are written). Out: number of bytes
 *                  written, or 0 if no private message was extracted (cannot be NULL if private_msg is not NULL)
 *  In:       proof: byte-serialized rangeproof (cannot be NULL)
 *             plen: length of every individual proof
 *        min_value: minimum value that the proof ranges over
 *           commit: pedersen commitment that the rangeproof is over (cannot be NULL)
 *        value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
 *     shared_nonce: random 32-byte seed used to encrypt the shared message (if NULL, shared message will not be recovered)
 *    private_nonce: random 32-byte seed used to encrypt the private message (if NULL, private message will not be recovered)
 *     extra_commit: additional data committed to by the rangeproof
 * extra_commit_len: length of additional data
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bulletproof_rangeproof_rewind(
    const secp256k1_context* ctx,
    unsigned char* shared_msg,
    size_t* shared_msg_len,
    unsigned char* private_msg,
    size_t* private_msg_len,
    const unsigned char* proof,
    size_t plen,
    uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const secp256k1_generator* value_gen,
    const unsigned char* shared_nonce,
    const unsigned char* private_nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10);

/** Produces an aggregate Bulletproof rangeproof for a set of Pedersen commitments
 *
 *  The blinding factors are not checked. One that is greater than or equal to the group order is reduced
 *  (for the first one this is recorded in the proof so rewinding returns the original 32 bytes), and an
 *  all-zero one is accepted even though the commitment then reveals its value. The caller is responsible
 *  for using valid, secret blinding factors. MWEB derives them with secp256k1_blind_switch, whose output
 *  is always below the group order and is zero only with negligible probability.
 *
 *  Returns: 1: rangeproof was successfully created
 *           0: rangeproof could not be created, or out of memory
 *  Args:       ctx: pointer to a context object initialized for signing and verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  Out:      proof: byte-serialized rangeproof (cannot be NULL)
 *  In/out:    plen: pointer to size of `proof`, to be replaced with actual length of proof (cannot be NULL)
 *            tau_x: only for multi-party; 32-byte, output in second step or input in final step
 *            t_one: only for multi-party; public key, output in first step or input for the others
 *            t_two: only for multi-party; public key, output in first step or input for the others
 *  In:       value: array of values committed by the Pedersen commitments (cannot be NULL)
 *        min_value: array of minimum values to prove ranges above, or NULL for all-zeroes
 *            blind: array of blinding factors of the Pedersen commitments (cannot be NULL)
 *          commits: only for multi-party; array of pointers to commitments
 *        n_commits: number of entries in the `value` and `blind` arrays
 *        value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
 *            nbits: number of bits proven for each range
 *            nonce: random 32-byte seed used to derive blinding factors (cannot be NULL)
 *    private_nonce: only for multi-party; random 32-byte seed used to derive private blinding factors
 *     extra_commit: additonal data committed to by the rangeproof
 * extra_commit_len: length of additional data
 *          message: optional 32-byte message, recoverable by rewinding with `nonce`; it replaces the value in
 *                   the shared payload and requires n_commits == 1
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bulletproof_rangeproof_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch* scratch,
    const secp256k1_bulletproof_generators* gens,
    unsigned char* proof,
    size_t* plen,
    unsigned char* tau_x,
    secp256k1_pubkey* t_one,
    secp256k1_pubkey* t_two,
    const uint64_t* value,
    const uint64_t* min_value,
    const unsigned char* const* blind,
    const secp256k1_pedersen_commitment* const* commits,
    size_t n_commits,
    const secp256k1_generator* value_gen,
    size_t nbits,
    const unsigned char* nonce,
    const unsigned char* private_nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len,
    const unsigned char* message
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(11) SECP256K1_ARG_NONNULL(14) SECP256K1_ARG_NONNULL(16);

# ifdef __cplusplus
}
# endif

#endif
