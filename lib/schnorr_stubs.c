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
#define ENABLE_MODULE_ELLSWIFT 1
#define ENABLE_MODULE_RECOVERY 1

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
#include "secp256k1_ellswift.h"
#include "secp256k1_recovery.h"

static secp256k1_context *schnorr_ctx = NULL;

static void ensure_ctx(void) {
    if (schnorr_ctx == NULL) {
        schnorr_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (schnorr_ctx == NULL) {
            caml_failwith("ensure_ctx: secp256k1_context_create failed");
        }
        /* Side-channel blinding: randomize the context with 32 bytes of
         * fresh entropy from /dev/urandom. Mirrors Bitcoin Core's
         * ECC_Start (key.cpp:578-584) and the libsecp256k1 docs'
         * "highly recommended" guidance for any context used with
         * secret keys. Closes W159 BUG-2 (side-channel-blinding-disabled).
         */
        unsigned char seed[32];
        FILE *f = fopen("/dev/urandom", "rb");
        if (f == NULL || fread(seed, 1, 32, f) != 32) {
            if (f) fclose(f);
            caml_failwith("ensure_ctx: failed to read /dev/urandom for context randomization");
        }
        fclose(f);
        if (!secp256k1_context_randomize(schnorr_ctx, seed)) {
            caml_failwith("ensure_ctx: secp256k1_context_randomize failed");
        }
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

/* caml_xonly_pubkey_tweak_add(internal_pk_32bytes, tweak_32bytes) -> bigarray(32 bytes)
   Computes Q = P + t*G where P is the internal pubkey and t is the tweak.
   Returns the x-only output pubkey. */
CAMLprim value caml_xonly_pubkey_tweak_add(value v_internal_pk, value v_tweak) {
    CAMLparam2(v_internal_pk, v_tweak);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_internal_pk);
    unsigned char *tweak_data = (unsigned char *)Caml_ba_data_val(v_tweak);

    secp256k1_xonly_pubkey internal_pk;
    if (!secp256k1_xonly_pubkey_parse(schnorr_ctx, &internal_pk, pk_data)) {
        caml_failwith("caml_xonly_pubkey_tweak_add: invalid pubkey");
    }

    /* Convert x-only to full pubkey, tweak, then extract x-only again */
    secp256k1_pubkey full_pk;
    if (!secp256k1_xonly_pubkey_tweak_add(schnorr_ctx, &full_pk, &internal_pk, tweak_data)) {
        caml_failwith("caml_xonly_pubkey_tweak_add: tweak failed");
    }

    /* Extract x-only from the tweaked pubkey */
    secp256k1_xonly_pubkey output_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(schnorr_ctx, &output_xonly, NULL, &full_pk)) {
        caml_failwith("caml_xonly_pubkey_tweak_add: xonly extraction failed");
    }

    unsigned char output32[32];
    if (!secp256k1_xonly_pubkey_serialize(schnorr_ctx, output32, &output_xonly)) {
        caml_failwith("caml_xonly_pubkey_tweak_add: serialization failed");
    }

    long dims[1] = { 32 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, output32, 32);
    CAMLreturn(result);
}

/* caml_xonly_pubkey_tweak_add_with_parity(internal_pk_32bytes, tweak_32bytes)
   -> (bigarray(32 bytes), int)
   Like caml_xonly_pubkey_tweak_add but also returns the output key parity. */
CAMLprim value caml_xonly_pubkey_tweak_add_with_parity(value v_internal_pk, value v_tweak) {
    CAMLparam2(v_internal_pk, v_tweak);
    CAMLlocal2(result_pair, result_key);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_internal_pk);
    unsigned char *tweak_data = (unsigned char *)Caml_ba_data_val(v_tweak);

    secp256k1_xonly_pubkey internal_pk;
    if (!secp256k1_xonly_pubkey_parse(schnorr_ctx, &internal_pk, pk_data)) {
        caml_failwith("caml_xonly_pubkey_tweak_add_with_parity: invalid pubkey");
    }

    secp256k1_pubkey full_pk;
    if (!secp256k1_xonly_pubkey_tweak_add(schnorr_ctx, &full_pk, &internal_pk, tweak_data)) {
        caml_failwith("caml_xonly_pubkey_tweak_add_with_parity: tweak failed");
    }

    secp256k1_xonly_pubkey output_xonly;
    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(schnorr_ctx, &output_xonly, &parity, &full_pk)) {
        caml_failwith("caml_xonly_pubkey_tweak_add_with_parity: xonly extraction failed");
    }

    unsigned char output32[32];
    if (!secp256k1_xonly_pubkey_serialize(schnorr_ctx, output32, &output_xonly)) {
        caml_failwith("caml_xonly_pubkey_tweak_add_with_parity: serialization failed");
    }

    long dims[1] = { 32 };
    result_key = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result_key);
    memcpy(result_data, output32, 32);

    result_pair = caml_alloc(2, 0);
    Store_field(result_pair, 0, result_key);
    Store_field(result_pair, 1, Val_int(parity));
    CAMLreturn(result_pair);
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

/* ============================================================================
   ECDSA Verification (Hardware-accelerated via libsecp256k1)
   ============================================================================ */

/* caml_ecdsa_verify(pubkey_bytes, msg_32bytes, sig_der_bytes) -> bool
   Fast ECDSA verification using libsecp256k1's optimized implementation.
   Pubkey can be 33 bytes (compressed) or 65 bytes (uncompressed).
   Signature must be DER-encoded. */
CAMLprim value caml_ecdsa_verify(value v_pubkey, value v_msg, value v_sig) {
    CAMLparam3(v_pubkey, v_msg, v_sig);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_pubkey);
    size_t pk_len = Caml_ba_array_val(v_pubkey)->dim[0];
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);
    unsigned char *sig_data = (unsigned char *)Caml_ba_data_val(v_sig);
    size_t sig_len = Caml_ba_array_val(v_sig)->dim[0];

    /* Parse public key */
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(schnorr_ctx, &pubkey, pk_data, pk_len)) {
        CAMLreturn(Val_false);
    }

    /* Parse DER signature */
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(schnorr_ctx, &sig, sig_data, sig_len)) {
        CAMLreturn(Val_false);
    }

    /* Verify */
    int result = secp256k1_ecdsa_verify(schnorr_ctx, &sig, msg_data, &pubkey);
    CAMLreturn(Val_bool(result));
}

/* caml_ecdsa_verify_normalized(pubkey_bytes, msg_32bytes, sig_der_bytes) -> bool
   Same as caml_ecdsa_verify but normalizes the signature to low-S before verification.
   This matches Bitcoin's BIP-62 rule 5 enforcement. */
CAMLprim value caml_ecdsa_verify_normalized(value v_pubkey, value v_msg, value v_sig) {
    CAMLparam3(v_pubkey, v_msg, v_sig);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_pubkey);
    size_t pk_len = Caml_ba_array_val(v_pubkey)->dim[0];
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);
    unsigned char *sig_data = (unsigned char *)Caml_ba_data_val(v_sig);
    size_t sig_len = Caml_ba_array_val(v_sig)->dim[0];

    /* Parse public key */
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(schnorr_ctx, &pubkey, pk_data, pk_len)) {
        CAMLreturn(Val_false);
    }

    /* Parse DER signature */
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(schnorr_ctx, &sig, sig_data, sig_len)) {
        CAMLreturn(Val_false);
    }

    /* Normalize to low-S */
    secp256k1_ecdsa_signature_normalize(schnorr_ctx, &sig, &sig);

    /* Verify */
    int result = secp256k1_ecdsa_verify(schnorr_ctx, &sig, msg_data, &pubkey);
    CAMLreturn(Val_bool(result));
}

/* ============================================================================
   Lax DER Signature Parsing (for Bitcoin script verification)
   ============================================================================

   Bitcoin Core uses a "lax" DER parser for signature verification when the
   DERSIG/STRICTENC flags are not set. This allows some non-standard DER
   encodings that were accepted by OpenSSL but not by libsecp256k1's strict
   parser. This is a direct port of Bitcoin Core's ecdsa_signature_parse_der_lax
   from pubkey.cpp. */

static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}

/* caml_ecdsa_verify_lax(pubkey_bytes, msg_32bytes, sig_der_bytes) -> bool
   Same as caml_ecdsa_verify but uses lax DER parsing for legacy Bitcoin
   signature verification (pre-DERSIG/STRICTENC enforcement). */
CAMLprim value caml_ecdsa_verify_lax(value v_pubkey, value v_msg, value v_sig) {
    CAMLparam3(v_pubkey, v_msg, v_sig);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_pubkey);
    size_t pk_len = Caml_ba_array_val(v_pubkey)->dim[0];
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);
    unsigned char *sig_data = (unsigned char *)Caml_ba_data_val(v_sig);
    size_t sig_len = Caml_ba_array_val(v_sig)->dim[0];

    /* Parse public key */
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(schnorr_ctx, &pubkey, pk_data, pk_len)) {
        CAMLreturn(Val_false);
    }

    /* Parse DER signature with lax parsing */
    secp256k1_ecdsa_signature sig;
    if (!ecdsa_signature_parse_der_lax(schnorr_ctx, &sig, sig_data, sig_len)) {
        CAMLreturn(Val_false);
    }

    /* Normalize to low-S (Bitcoin Core always normalizes before verification) */
    secp256k1_ecdsa_signature_normalize(schnorr_ctx, &sig, &sig);

    /* Verify */
    int result = secp256k1_ecdsa_verify(schnorr_ctx, &sig, msg_data, &pubkey);
    CAMLreturn(Val_bool(result));
}

/* ============================================================================
   Batch Schnorr Verification
   ============================================================================

   Batch verification allows verifying multiple Schnorr signatures in parallel,
   which is faster than verifying them one by one due to amortized costs in the
   multi-scalar multiplication. This is particularly useful for validating
   taproot transactions in a block.

   Note: libsecp256k1 doesn't have a public batch verification API yet, so we
   implement a parallel verification wrapper that processes signatures in chunks
   using OCaml domains or Lwt threads. */

/* caml_schnorr_verify_batch(pubkeys_array, msgs_array, sigs_array, count) -> bool
   Verifies multiple Schnorr signatures. Returns true only if ALL signatures verify.
   Each pubkey is 32 bytes (x-only), each msg is 32 bytes, each sig is 64 bytes. */
CAMLprim value caml_schnorr_verify_batch(value v_pubkeys, value v_msgs, value v_sigs, value v_count) {
    CAMLparam4(v_pubkeys, v_msgs, v_sigs, v_count);
    ensure_ctx();

    int count = Int_val(v_count);
    if (count <= 0) {
        CAMLreturn(Val_true);  /* Empty batch is trivially valid */
    }

    unsigned char *pk_base = (unsigned char *)Caml_ba_data_val(v_pubkeys);
    unsigned char *msg_base = (unsigned char *)Caml_ba_data_val(v_msgs);
    unsigned char *sig_base = (unsigned char *)Caml_ba_data_val(v_sigs);

    /* Verify each signature sequentially (libsecp256k1 lacks public batch API) */
    for (int i = 0; i < count; i++) {
        unsigned char *pk_data = pk_base + (i * 32);
        unsigned char *msg_data = msg_base + (i * 32);
        unsigned char *sig_data = sig_base + (i * 64);

        secp256k1_xonly_pubkey xonly_pk;
        if (!secp256k1_xonly_pubkey_parse(schnorr_ctx, &xonly_pk, pk_data)) {
            CAMLreturn(Val_false);
        }

        if (!secp256k1_schnorrsig_verify(schnorr_ctx, sig_data, msg_data, 32, &xonly_pk)) {
            CAMLreturn(Val_false);
        }
    }

    CAMLreturn(Val_true);
}

/* ============================================================================
   Public Key Operations
   ============================================================================ */

/* caml_pubkey_parse(pubkey_bytes) -> bool
   Check if pubkey bytes can be parsed as a valid secp256k1 public key.
   Useful for fast validation without full verification. */
CAMLprim value caml_pubkey_parse_check(value v_pubkey) {
    CAMLparam1(v_pubkey);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_pubkey);
    size_t pk_len = Caml_ba_array_val(v_pubkey)->dim[0];

    secp256k1_pubkey pubkey;
    int result = secp256k1_ec_pubkey_parse(schnorr_ctx, &pubkey, pk_data, pk_len);
    CAMLreturn(Val_bool(result));
}

/* caml_pubkey_serialize_compressed(pubkey_bytes) -> bigarray(33 bytes)
   Parse an uncompressed pubkey (65 bytes) and return compressed form (33 bytes). */
CAMLprim value caml_pubkey_serialize_compressed(value v_pubkey) {
    CAMLparam1(v_pubkey);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_pubkey);
    size_t pk_len = Caml_ba_array_val(v_pubkey)->dim[0];

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(schnorr_ctx, &pubkey, pk_data, pk_len)) {
        caml_failwith("caml_pubkey_serialize_compressed: invalid pubkey");
    }

    unsigned char output[33];
    size_t output_len = 33;
    if (!secp256k1_ec_pubkey_serialize(schnorr_ctx, output, &output_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        caml_failwith("caml_pubkey_serialize_compressed: serialization failed");
    }

    long dims[1] = { 33 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, output, 33);
    CAMLreturn(result);
}

/* ============================================================================
   BIP-324 ElligatorSwift (libsecp256k1 ellswift module)
   ============================================================================

   These stubs back the BIP-324 v2 transport handshake. They wrap two
   libsecp256k1 calls:

   - secp256k1_ellswift_create:  derive a 64-byte ElligatorSwift encoding of
                                 the public key for a given 32-byte secret
                                 key, optionally salted with 32 bytes of
                                 auxiliary randomness.

   - secp256k1_ellswift_xdh:     compute the BIP-324 32-byte ECDH shared
                                 secret given our seckey and both parties'
                                 ElligatorSwift encodings, using the
                                 secp256k1_ellswift_xdh_hash_function_bip324
                                 hasher (tagged-hash variant).

   Result is a Bigstring/Bigarray (UINT8/C_LAYOUT) for zero-copy interop with
   the OCaml side, matching the convention used by the rest of this file. */

/* caml_ellswift_create(seckey_32bytes, auxrand_32bytes_or_empty) -> bigarray(64 bytes)

   If auxrand has length 0, NULL is passed for auxrand32 (libsecp256k1 then
   uses just the seckey as entropy); otherwise auxrand must be exactly 32
   bytes. Raises Failure on invalid inputs. */
CAMLprim value caml_ellswift_create(value v_seckey, value v_auxrand) {
    CAMLparam2(v_seckey, v_auxrand);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);
    size_t sk_len = Caml_ba_array_val(v_seckey)->dim[0];
    unsigned char *aux_data = (unsigned char *)Caml_ba_data_val(v_auxrand);
    size_t aux_len = Caml_ba_array_val(v_auxrand)->dim[0];

    if (sk_len != 32) {
        caml_failwith("caml_ellswift_create: seckey must be 32 bytes");
    }
    if (aux_len != 0 && aux_len != 32) {
        caml_failwith("caml_ellswift_create: auxrand must be 0 or 32 bytes");
    }

    unsigned char ell64[64];
    int ret = secp256k1_ellswift_create(schnorr_ctx, ell64, sk_data,
                                        aux_len == 32 ? aux_data : NULL);
    if (!ret) {
        caml_failwith("caml_ellswift_create: ellswift_create failed (invalid seckey?)");
    }

    long dims[1] = { 64 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, ell64, 64);
    CAMLreturn(result);
}

/* caml_ellswift_xdh(our_seckey_32, their_ellswift_64, our_ellswift_64, initiator_bool)
       -> bigarray(32 bytes)

   Computes the BIP-324 ECDH shared secret using
   secp256k1_ellswift_xdh_hash_function_bip324. The party byte is derived
   from the initiator flag per BIP-324: initiator -> party=0 (party A),
   responder -> party=1 (party B), with ell_a64/ell_b64 ordered so that
   ell_?64 corresponding to our seckey is on the matching side. */
CAMLprim value caml_ellswift_xdh(value v_our_sk,
                                 value v_their_ell,
                                 value v_our_ell,
                                 value v_initiator) {
    CAMLparam4(v_our_sk, v_their_ell, v_our_ell, v_initiator);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_our_sk);
    size_t sk_len = Caml_ba_array_val(v_our_sk)->dim[0];
    unsigned char *their_data = (unsigned char *)Caml_ba_data_val(v_their_ell);
    size_t their_len = Caml_ba_array_val(v_their_ell)->dim[0];
    unsigned char *our_data = (unsigned char *)Caml_ba_data_val(v_our_ell);
    size_t our_len = Caml_ba_array_val(v_our_ell)->dim[0];
    int initiator = Bool_val(v_initiator);

    if (sk_len != 32) {
        caml_failwith("caml_ellswift_xdh: seckey must be 32 bytes");
    }
    if (their_len != 64 || our_len != 64) {
        caml_failwith("caml_ellswift_xdh: ellswift encodings must be 64 bytes");
    }

    /* BIP-324: party=0 means we are party A (initiator), party=1 means party B
       (responder). ell_a64 must be the initiator's encoding, ell_b64 the
       responder's. seckey32 must correspond to our party's encoding. */
    int party = initiator ? 0 : 1;
    const unsigned char *ell_a = initiator ? our_data : their_data;
    const unsigned char *ell_b = initiator ? their_data : our_data;

    unsigned char shared[32];
    int ret = secp256k1_ellswift_xdh(schnorr_ctx, shared, ell_a, ell_b,
                                     sk_data, party,
                                     secp256k1_ellswift_xdh_hash_function_bip324,
                                     NULL);
    if (!ret) {
        caml_failwith("caml_ellswift_xdh: ellswift_xdh failed");
    }

    long dims[1] = { 32 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, shared, 32);
    CAMLreturn(result);
}

/* ============================================================================
   Recoverable ECDSA (Bitcoin Core "signmessage" / "verifymessage" format)

   Both stubs use the vendored libsecp256k1 directly so that the sign and
   recover paths are guaranteed to use the same implementation.  Mixing the
   secp256k1-internal opam package's bundled lib with the vendored copy
   under --allow-multiple-definition can route sign and recover to mutually
   inconsistent function bodies — these stubs side-step that.
   ============================================================================ */

/* caml_ecdsa_sign_compact(seckey_32, msg_32, compressed_int)
     -> bigarray(65 bytes)  (Bitcoin compact: header || R || S)
   header = 27 + recid + (compressed ? 4 : 0) */
CAMLprim value caml_ecdsa_sign_compact(value v_seckey, value v_msg,
                                       value v_compressed) {
    CAMLparam3(v_seckey, v_msg, v_compressed);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);
    int compressed = Int_val(v_compressed);

    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_sign_recoverable(schnorr_ctx, &rsig, msg_data,
                                          sk_data, NULL, NULL)) {
        caml_failwith("caml_ecdsa_sign_compact: signing failed");
    }
    unsigned char rs[64];
    int recid = -1;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(schnorr_ctx,
            rs, &recid, &rsig)) {
        caml_failwith("caml_ecdsa_sign_compact: serialize_compact failed");
    }

    long dims[1] = { 65 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *out = (unsigned char *)Caml_ba_data_val(result);
    out[0] = (unsigned char)(27 + recid + (compressed ? 4 : 0));
    memcpy(out + 1, rs, 64);
    CAMLreturn(result);
}

/* caml_ecdsa_recover_compact(sig_65, msg_32) -> bigarray | none
   Returns:
     dim=33 → compressed pubkey on success (header bit 4 set)
     dim=65 → uncompressed pubkey on success (header bit 4 clear)
     dim=0  → recovery failed (caller treats as None) */
CAMLprim value caml_ecdsa_recover_compact(value v_sig, value v_msg) {
    CAMLparam2(v_sig, v_msg);
    ensure_ctx();

    unsigned char *sig_data = (unsigned char *)Caml_ba_data_val(v_sig);
    size_t sig_len = Caml_ba_array_val(v_sig)->dim[0];
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);

    long fail_dims[1] = { 0 };

    if (sig_len != 65) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }

    int header = sig_data[0];
    if (header < 27 || header > 34) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }
    int recid = (header - 27) & 3;
    int compressed = ((header - 27) & 4) != 0;

    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(schnorr_ctx,
            &rsig, sig_data + 1, recid)) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }

    secp256k1_pubkey pk;
    if (!secp256k1_ecdsa_recover(schnorr_ctx, &pk, &rsig, msg_data)) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }

    unsigned char pub[65];
    size_t publen = compressed ? 33 : 65;
    if (!secp256k1_ec_pubkey_serialize(schnorr_ctx, pub, &publen, &pk,
            compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }

    long ok_dims[1] = { (long)publen };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                 ok_dims);
    unsigned char *out = (unsigned char *)Caml_ba_data_val(result);
    memcpy(out, pub, publen);
    CAMLreturn(result);
}

/* ============================================================================
   Generic ECDSA: derive pubkey, sign (DER+low-S), DER-low-S check, seckey tweak

   These stubs replace the OCaml secp256k1-internal binding's Key/Sign API.
   Camlcoin previously linked both the vendored libsecp256k1 and the binding's
   bundled copy under -Wl,--allow-multiple-definition, which routed otherwise-
   identical symbols to inconsistent function bodies. Routing every secp256k1
   call through C stubs against the vendored copy gives a single source of
   truth for sign / verify / derive.
   ============================================================================ */

/* caml_ec_pubkey_create(seckey_32, compressed_int) -> bigarray (33 or 65 bytes)
   Raises Failure on invalid seckey. */
CAMLprim value caml_ec_pubkey_create(value v_seckey, value v_compressed) {
    CAMLparam2(v_seckey, v_compressed);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);
    size_t sk_len = Caml_ba_array_val(v_seckey)->dim[0];
    int compressed = Int_val(v_compressed);

    if (sk_len != 32) {
        caml_failwith("caml_ec_pubkey_create: seckey must be 32 bytes");
    }

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(schnorr_ctx, &pk, sk_data)) {
        caml_failwith("caml_ec_pubkey_create: invalid seckey");
    }

    unsigned char pub[65];
    size_t publen = compressed ? 33 : 65;
    if (!secp256k1_ec_pubkey_serialize(schnorr_ctx, pub, &publen, &pk,
            compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
        caml_failwith("caml_ec_pubkey_create: pubkey_serialize failed");
    }

    long dims[1] = { (long)publen };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *out = (unsigned char *)Caml_ba_data_val(result);
    memcpy(out, pub, publen);
    CAMLreturn(result);
}

/* caml_ecdsa_sign_der(seckey_32, msg_32) -> bigarray (DER, low-S normalized)
   Returns the DER serialization of the signature with low-S enforced
   (BIP-62 rule 5).  Raises Failure on signing error. */
CAMLprim value caml_ecdsa_sign_der(value v_seckey, value v_msg) {
    CAMLparam2(v_seckey, v_msg);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);
    size_t sk_len = Caml_ba_array_val(v_seckey)->dim[0];
    unsigned char *msg_data = (unsigned char *)Caml_ba_data_val(v_msg);
    size_t msg_len = Caml_ba_array_val(v_msg)->dim[0];

    if (sk_len != 32) {
        caml_failwith("caml_ecdsa_sign_der: seckey must be 32 bytes");
    }
    if (msg_len != 32) {
        caml_failwith("caml_ecdsa_sign_der: msg must be 32 bytes");
    }

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(schnorr_ctx, &sig, msg_data, sk_data, NULL, NULL)) {
        caml_failwith("caml_ecdsa_sign_der: signing failed");
    }

    /* Normalize to low-S per BIP-62 rule 5. */
    secp256k1_ecdsa_signature_normalize(schnorr_ctx, &sig, &sig);

    unsigned char der[72];
    size_t der_len = sizeof(der);
    if (!secp256k1_ecdsa_signature_serialize_der(schnorr_ctx, der, &der_len, &sig)) {
        caml_failwith("caml_ecdsa_sign_der: serialize_der failed");
    }

    long dims[1] = { (long)der_len };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *out = (unsigned char *)Caml_ba_data_val(result);
    memcpy(out, der, der_len);
    CAMLreturn(result);
}

/* caml_ecdsa_signature_is_low_s(sig_der_bytes) -> bool
   Parses a DER-encoded ECDSA signature (no hash type byte) and returns true
   iff its S value is already in low-S form.  Returns false if the signature
   cannot be parsed. Mirrors libsecp256k1_internal's Sign.normalize semantics:
   normalize returns Some _ when the input was high-S, None when already low-S;
   we use signature_normalize's return value in the same way. */
CAMLprim value caml_ecdsa_signature_is_low_s(value v_sig) {
    CAMLparam1(v_sig);
    ensure_ctx();

    unsigned char *sig_data = (unsigned char *)Caml_ba_data_val(v_sig);
    size_t sig_len = Caml_ba_array_val(v_sig)->dim[0];

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(schnorr_ctx, &sig, sig_data, sig_len)) {
        CAMLreturn(Val_false);
    }

    /* signature_normalize returns 1 if sig was modified (was high-S), 0 if
       already low-S. We want is_low_s = (was already low-S) = !was_modified. */
    int was_modified = secp256k1_ecdsa_signature_normalize(schnorr_ctx, NULL, &sig);
    CAMLreturn(Val_bool(!was_modified));
}

/* caml_ec_seckey_tweak_add(seckey_32, tweak_32) -> bigarray (32 bytes)
   Raises Failure on invalid seckey or tweak overflow. */
CAMLprim value caml_ec_seckey_tweak_add(value v_seckey, value v_tweak) {
    CAMLparam2(v_seckey, v_tweak);
    ensure_ctx();

    unsigned char *sk_data = (unsigned char *)Caml_ba_data_val(v_seckey);
    size_t sk_len = Caml_ba_array_val(v_seckey)->dim[0];
    unsigned char *tweak_data = (unsigned char *)Caml_ba_data_val(v_tweak);
    size_t tweak_len = Caml_ba_array_val(v_tweak)->dim[0];

    if (sk_len != 32) {
        caml_failwith("caml_ec_seckey_tweak_add: seckey must be 32 bytes");
    }
    if (tweak_len != 32) {
        caml_failwith("caml_ec_seckey_tweak_add: tweak must be 32 bytes");
    }

    unsigned char out[32];
    memcpy(out, sk_data, 32);
    if (!secp256k1_ec_seckey_tweak_add(schnorr_ctx, out, tweak_data)) {
        caml_failwith("caml_ec_seckey_tweak_add: tweak overflow / invalid result");
    }

    long dims[1] = { 32 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, out, 32);
    CAMLreturn(result);
}

/* caml_ec_pubkey_tweak_add(pubkey_bytes, tweak_32) -> bigarray (33 bytes,
   compressed)
   Pubkey input may be 33 or 65 bytes. Output is always 33-byte compressed.
   Raises Failure on invalid pubkey or tweak overflow. Used by BIP-32 public
   derivation: child_pubkey = parent_pubkey + tweak * G. */
CAMLprim value caml_ec_pubkey_tweak_add(value v_pubkey, value v_tweak) {
    CAMLparam2(v_pubkey, v_tweak);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_pubkey);
    size_t pk_len = Caml_ba_array_val(v_pubkey)->dim[0];
    unsigned char *tweak_data = (unsigned char *)Caml_ba_data_val(v_tweak);
    size_t tweak_len = Caml_ba_array_val(v_tweak)->dim[0];

    if (tweak_len != 32) {
        caml_failwith("caml_ec_pubkey_tweak_add: tweak must be 32 bytes");
    }

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(schnorr_ctx, &pk, pk_data, pk_len)) {
        caml_failwith("caml_ec_pubkey_tweak_add: invalid pubkey");
    }

    if (!secp256k1_ec_pubkey_tweak_add(schnorr_ctx, &pk, tweak_data)) {
        caml_failwith("caml_ec_pubkey_tweak_add: tweak overflow");
    }

    unsigned char out[33];
    size_t out_len = 33;
    if (!secp256k1_ec_pubkey_serialize(schnorr_ctx, out, &out_len, &pk,
            SECP256K1_EC_COMPRESSED)) {
        caml_failwith("caml_ec_pubkey_tweak_add: serialize failed");
    }

    long dims[1] = { 33 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, out, 33);
    CAMLreturn(result);
}

/* caml_ec_pubkey_decompress(compressed_pubkey_33) -> bigarray
   Parses a 33-byte compressed secp256k1 public key (0x02 / 0x03 prefix +
   32-byte x-coord) and returns the 65-byte uncompressed encoding (0x04 +
   X || Y).  Used by Bitcoin Core's ScriptCompression::DecompressScript for
   nSize == 0x04 / 0x05 (uncompressed P2PK rebuilt from the compressed wire
   form).  Returns a length-0 bigarray on failure (invalid x / not on curve)
   so the OCaml caller can map that to an Option/None without raising. */
CAMLprim value caml_ec_pubkey_decompress(value v_compressed) {
    CAMLparam1(v_compressed);
    ensure_ctx();

    unsigned char *pk_data = (unsigned char *)Caml_ba_data_val(v_compressed);
    size_t pk_len = Caml_ba_array_val(v_compressed)->dim[0];

    long fail_dims[1] = { 0 };

    if (pk_len != 33) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(schnorr_ctx, &pk, pk_data, 33)) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }

    unsigned char out[65];
    size_t out_len = 65;
    if (!secp256k1_ec_pubkey_serialize(schnorr_ctx, out, &out_len, &pk,
            SECP256K1_EC_UNCOMPRESSED)) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }
    if (out_len != 65) {
        value fail = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                   fail_dims);
        CAMLreturn(fail);
    }

    long ok_dims[1] = { 65 };
    value result = caml_ba_alloc(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL,
                                 ok_dims);
    unsigned char *result_data = (unsigned char *)Caml_ba_data_val(result);
    memcpy(result_data, out, 65);
    CAMLreturn(result);
}
