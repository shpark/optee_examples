global-incdirs-y += include

srcs-y += cose_samples_ta.c
srcs-y += cose_samples_ta_crypto_test.c
srcs-y += cose_samples_ta_cbor_test.c
srcs-y += cose_samples_test_util.c

# QCBOR
global-incdirs-y += third_party/QCBOR/inc

cflags-y += -DQCBOR_DISABLE_FLOAT_HW_USE

srcs-y += third_party/QCBOR/src/ieee754.c
srcs-y += third_party/QCBOR/src/qcbor_encode.c
srcs-y += third_party/QCBOR/src/qcbor_decode.c
srcs-y += third_party/QCBOR/src/qcbor_err_to_str.c
srcs-y += third_party/QCBOR/src/UsefulBuf.c

# t_cose
global-incdirs-y += third_party/t_cose/inc
global-incdirs-y += third_party/t_cose/src
global-incdirs-y += third_party/t_cose/test

cflags-y += -DT_COSE_USE_GP_TEE_CRYPTO=1

cflags-y += -DT_COSE_DISABLE_SHORT_CIRCUIT_SIGN
cflags-y += -DT_COSE_USE_OPENSSL_CRYPTO=0
cflags-y += -DT_COSE_USE_B_CON_SHA256=0

srcs-y += third_party/t_cose/src/t_cose_parameters.c
srcs-y += third_party/t_cose/src/t_cose_sign1_verify.c
srcs-y += third_party/t_cose/src/t_cose_sign1_sign.c
srcs-y += third_party/t_cose/src/t_cose_util.c
srcs-y += third_party/t_cose/crypto_adapters/t_cose_gp_tee_crypto.c