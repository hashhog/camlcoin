#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <string.h>
#include <openssl/sha.h>

static int hw_level = 0;

#ifdef __x86_64__
#include <cpuid.h>
__attribute__((constructor))
static void detect_hw(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1 << 29)) hw_level = 2;
        else if (ebx & (1 << 5)) hw_level = 1;
    }
}
#endif

CAMLprim value caml_sha256_accel(value v_data) {
    CAMLparam1(v_data);
    CAMLlocal1(v_result);
    v_result = caml_alloc_string(32);
    SHA256((const unsigned char *)String_val(v_data),
           caml_string_length(v_data),
           (unsigned char *)Bytes_val(v_result));
    CAMLreturn(v_result);
}

CAMLprim value caml_sha256d_accel(value v_data) {
    CAMLparam1(v_data);
    CAMLlocal1(v_result);
    unsigned char tmp[32];
    SHA256((const unsigned char *)String_val(v_data),
           caml_string_length(v_data), tmp);
    v_result = caml_alloc_string(32);
    SHA256(tmp, 32, (unsigned char *)Bytes_val(v_result));
    CAMLreturn(v_result);
}

CAMLprim value caml_sha256_hw_info(value v_unit) {
    CAMLparam1(v_unit);
    if (hw_level == 2) CAMLreturn(caml_copy_string("sha_ni"));
    if (hw_level == 1) CAMLreturn(caml_copy_string("avx2"));
    CAMLreturn(caml_copy_string("generic"));
}
