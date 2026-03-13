/* Schnorr signature verification C stubs for OCaml.
 *
 * This file compiles a vendored copy of Bitcoin Core's libsecp256k1 with
 * Schnorr/extrakeys modules enabled. We compile the entire secp256k1
 * implementation in this translation unit. Duplicate symbols with the
 * already-linked secp256k1-internal are handled by the linker (first
 * definition wins for archive linking).
 */

/* Override the local visibility header to prevent "extern hidden" which
 * would conflict with the existing library's symbols. We define it as
 * plain extern; duplicate definitions will be resolved by the linker. */
#define SECP256K1_LOCAL_VISIBILITY_H
#define SECP256K1_LOCAL_VAR extern

/* Enable the modules we need */
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1

/* Prevent OCaml compatibility macros from interfering with secp256k1 code.
 * OCaml's caml/compatibility.h defines 'alloc' as a macro which clashes
 * with a local variable in secp256k1's scratch_impl.h. */
#define CAML_NAME_SPACE

#include <string.h>

/* Include the full secp256k1 implementation.
 * The include_dirs in dune point to the vendor src/ and include/ directories. */
#include "secp256k1.c"

/* Include the precomputed tables */
#include "precomputed_ecmult.c"
#include "precomputed_ecmult_gen.c"

/* Now include OCaml headers, after secp256k1 is fully compiled */
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/bigarray.h>

/* Schnorr public headers (for the API types) */
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"

static secp256k1_context *schnorr_ctx = NULL;

static void ensure_ctx(void) {
    if (schnorr_ctx == NULL) {
        schnorr_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    }
}

/* caml_schnorr_verify(pubkey_x_32bytes, msg_32bytes, sig_64bytes) -> bool */
CAMLprim value caml_schnorr_verify(value v_pubkey, value v_msg, value v_sig) {
    CAMLparam3(v_pubkey, v_msg, v_sig);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_pubkey);
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);
    unsigned char *sig_data = (unsigned char *)Caml_ba_data_val(v_sig);

    secp256k1_xonly_pubkey xonly_pk;
    if (!secp256k1_xonly_pubkey_parse(schnorr_ctx, &xonly_pk, pk_data)) {
        CAMLreturn(Val_false);
    }

    int result = secp256k1_schnorrsig_verify(schnorr_ctx, sig_data, msg_data, 32, &xonly_pk);
    CAMLreturn(Val_bool(result));
}

/* caml_xonly_pubkey_tweak_add_check(internal_pk, tweaked_pk, parity, tweak) -> bool */
CAMLprim value caml_xonly_pubkey_tweak_add_check(value v_internal_pk, value v_tweaked_pk, value v_parity, value v_tweak) {
    CAMLparam4(v_internal_pk, v_tweaked_pk, v_parity, v_tweak);
    ensure_ctx();

    unsigned char *internal_data = (unsigned char *)Caml_ba_data_val(v_internal_pk);
    unsigned char *tweaked_data = (unsigned char *)Caml_ba_data_val(v_tweaked_pk);
    int parity = Int_val(v_parity);
    unsigned char *tweak_data = (unsigned char *)Caml_ba_data_val(v_tweak);

    secp256k1_xonly_pubkey internal_pk;
    if (!secp256k1_xonly_pubkey_parse(schnorr_ctx, &internal_pk, internal_data)) {
        CAMLreturn(Val_false);
    }

    int result = secp256k1_xonly_pubkey_tweak_add_check(schnorr_ctx, tweaked_data, parity, &internal_pk, tweak_data);
    CAMLreturn(Val_bool(result));
}
