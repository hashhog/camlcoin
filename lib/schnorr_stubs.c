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
#include <caml/alloc.h>
#include <caml/fail.h>

#include <stdio.h>

/* Schnorr public headers (for the API types) */
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"

static secp256k1_context *schnorr_ctx = NULL;

static void ensure_ctx(void) {
    if (schnorr_ctx == NULL) {
        schnorr_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
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

/* caml_schnorr_sign(seckey_32bytes, msg_32bytes) -> bigarray(64 bytes) */
CAMLprim value caml_schnorr_sign(value v_seckey, value v_msg) {
    CAMLparam2(v_seckey, v_msg);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(schnorr_ctx, &keypair, sk_data)) {
        caml_failwith("caml_schnorr_sign: invalid secret key");
    }

    /* Read 32 bytes of auxiliary randomness from /dev/urandom */
    unsigned char aux_rand[32];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL || fread(aux_rand, 1, 32, f) != 32) {
        if (f) fclose(f);
        caml_failwith("caml_schnorr_sign: failed to read /dev/urandom");
    }
    fclose(f);

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(schnorr_ctx, sig64, msg_data, &keypair, aux_rand)) {
        caml_failwith("caml_schnorr_sign: signing failed");
    }

    long dims[1] = { 64 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, sig64, 64);
    CAMLreturn(result);
}

/* caml_schnorr_sign_tweaked(seckey_32bytes, tweak_32bytes, msg_32bytes) -> bigarray(64 bytes)
   Creates a keypair, applies the BIP-341 taproot tweak, then signs. */
CAMLprim value caml_schnorr_sign_tweaked(value v_seckey, value v_tweak, value v_msg) {
    CAMLparam3(v_seckey, v_tweak, v_msg);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);
    unsigned char *tweak_data = (unsigned char *)Caml_ba_data_val(v_tweak);
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(schnorr_ctx, &keypair, sk_data)) {
        caml_failwith("caml_schnorr_sign_tweaked: invalid secret key");
    }

    /* Apply the taproot tweak to the keypair (handles parity internally) */
    if (!secp256k1_keypair_xonly_tweak_add(schnorr_ctx, &keypair, tweak_data)) {
        caml_failwith("caml_schnorr_sign_tweaked: tweak failed");
    }

    /* Read 32 bytes of auxiliary randomness */
    unsigned char aux_rand[32];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL || fread(aux_rand, 1, 32, f) != 32) {
        if (f) fclose(f);
        caml_failwith("caml_schnorr_sign_tweaked: failed to read /dev/urandom");
    }
    fclose(f);

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(schnorr_ctx, sig64, msg_data, &keypair, aux_rand)) {
        caml_failwith("caml_schnorr_sign_tweaked: signing failed");
    }

    long dims[1] = { 64 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, sig64, 64);
    CAMLreturn(result);
}

/* caml_derive_xonly_pubkey(seckey_32bytes) -> bigarray(32 bytes) */
CAMLprim value caml_derive_xonly_pubkey(value v_seckey) {
    CAMLparam1(v_seckey);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(schnorr_ctx, &keypair, sk_data)) {
        caml_failwith("caml_derive_xonly_pubkey: invalid secret key");
    }

    secp256k1_xonly_pubkey xonly_pk;
    if (!secp256k1_keypair_xonly_pub(schnorr_ctx, &xonly_pk, NULL, &keypair)) {
        caml_failwith("caml_derive_xonly_pubkey: failed to extract xonly pubkey");
    }

    unsigned char pubkey32[32];
    if (!secp256k1_xonly_pubkey_serialize(schnorr_ctx, pubkey32, &xonly_pk)) {
        caml_failwith("caml_derive_xonly_pubkey: failed to serialize xonly pubkey");
    }

    long dims[1] = { 32 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, pubkey32, 32);
    CAMLreturn(result);
}
