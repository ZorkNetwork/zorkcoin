/***********************************************************************
 * Aggregated ZKP module implementations (include order preserved here).
 **********************************************************************/

#ifndef SECP256K1_MODULE_ZKP_MODULES_IMPL_H
#define SECP256K1_MODULE_ZKP_MODULES_IMPL_H

#include "zkp_scratch_impl.h"
#include "zkp_eckey_impl.h"

#ifdef ENABLE_MODULE_GENERATOR
# include "generator/main_impl.h"
#endif

#ifdef ENABLE_MODULE_COMMITMENT
# include "commitment/main_impl.h"
#endif

#ifdef ENABLE_MODULE_BULLETPROOF
# include "bulletproofs/main_impl.h"
#endif

#ifdef ENABLE_MODULE_AGGSIG
# include "aggsig/main_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG_MW
# include "schnorrsig_mw/main_impl.h"
#endif

#endif /* SECP256K1_MODULE_ZKP_MODULES_IMPL_H */
