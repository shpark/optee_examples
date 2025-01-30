// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Seonghyun Park
 */

#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>

#include <trace.h>

#include <t_cose/t_cose_common.h>
#include <t_cose/t_cose_sign1_sign.h>
#include <t_cose/t_cose_sign1_verify.h>
#include <t_cose_standard_constants.h>
#include <t_cose_make_test_pub_key.h>

#include "cose_samples_ta_test.h"
#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"

/**
 * @brief Encode and sign a COSE_Sign1 object using t_cose APIs
 */
static inline enum t_cose_err_t encode_cose_sign1_simple(
	struct t_cose_key signing_key,
	struct q_useful_buf_c payload,
	struct q_useful_buf cose_buffer,
	struct q_useful_buf_c *cose)
{
	struct t_cose_sign1_sign_ctx sign_ctx = { };
	enum t_cose_err_t status = 0;

	t_cose_sign1_sign_init(&sign_ctx, /*option_flags=*/ 0,
			       T_COSE_ALGORITHM_ES256);

	t_cose_sign1_set_signing_key(&sign_ctx, signing_key,
				     NULL_Q_USEFUL_BUF_C);

	status = t_cose_sign1_sign(&sign_ctx, payload, cose_buffer, cose);

	return status;
}

/**
 * @brief Verify a COSE_Sign1 object using t_cose APIs
 */
static inline enum t_cose_err_t verify_cose_sign1_simple(
	struct t_cose_key verification_key,
	struct q_useful_buf_c payload,
	struct q_useful_buf_c cose)
{
	struct t_cose_sign1_verify_ctx verify_ctx = { };

	/* NOTE: No need to pre-allocate buffer to hold returned payload */
	struct q_useful_buf_c returned_payload = { };
	struct t_cose_parameters parameters = { };
	enum t_cose_err_t status = 0;

	t_cose_sign1_verify_init(&verify_ctx, 0);

	t_cose_sign1_set_verification_key(&verify_ctx, verification_key);

	/*
	 * NOTE: `parameters` can be NULL, and in that case, this function
	 * won't return `parameters` from 
	 */
	status = t_cose_sign1_verify(&verify_ctx,
				     cose,
				     &returned_payload,
				     &parameters);
	if (status != 0)
		return status;

	/* TODO: Check parameters */
	(void)parameters.cose_algorithm_id;

	/* Compare payload */
	if (payload.len != returned_payload.len ||
	    memcmp(payload.ptr, returned_payload.ptr, payload.len)) {
		status = T_COSE_ERR_FAIL;
	}

	return status;
}

static inline struct q_useful_buf_c encode_protected_parameters(
	int32_t cose_algorithm_id,
	struct q_useful_buf protected_parameters_buffer)
{
	QCBOREncodeContext encode_ctx = { };
	struct q_useful_buf_c protected_parameters = NULL_Q_USEFUL_BUF_C;
	QCBORError qcbor_result = 0;

	QCBOREncode_Init(&encode_ctx, protected_parameters_buffer);

	QCBOREncode_OpenMap(&encode_ctx);
	QCBOREncode_AddInt64ToMapN(&encode_ctx,
				   COSE_HEADER_PARAM_ALG,
				   cose_algorithm_id);
	QCBOREncode_CloseMap(&encode_ctx);
	
	qcbor_result = QCBOREncode_Finish(&encode_ctx,
					  &protected_parameters);
	if (qcbor_result != QCBOR_SUCCESS)
		return NULL_Q_USEFUL_BUF_C;

	/* XXX: How to do error check? */

	return protected_parameters;
}

/**
 * @brief Encode and sign a COSE_Sign1 object with `create_tbs()` function
 */
static inline enum t_cose_err_t encode_cose_sign1_with_create_tbs(
	struct t_cose_key signing_key,
	struct q_useful_buf_c protected_parameters,
	struct q_useful_buf_c payload,
	struct q_useful_buf cose_buffer,
	struct q_useful_buf_c *cose)
{
	Q_USEFUL_BUF_MAKE_STACK_UB(tbs_buffer, 512);
	struct q_useful_buf_c tbs = NULL_Q_USEFUL_BUF_C;
	Q_USEFUL_BUF_MAKE_STACK_UB(tbs_hash_buffer, 32);
	struct q_useful_buf_c tbs_hash = NULL_Q_USEFUL_BUF_C;
	enum t_cose_err_t status = 0;
	QCBORError qcbor_result = 0;

	/* Prepare TBS and compute hash */
	status = create_tbs(protected_parameters, NULL_Q_USEFUL_BUF_C, payload,
			    tbs_buffer, &tbs);
	if (status != 0)
		return status;

	struct t_cose_crypto_hash hash_ctx = { };
	t_cose_crypto_hash_start(&hash_ctx, COSE_ALGORITHM_SHA_256);
	t_cose_crypto_hash_update(&hash_ctx, tbs);
	t_cose_crypto_hash_finish(&hash_ctx, tbs_hash_buffer, &tbs_hash);

	IMSG("TBS hash:");
	hexdump1(tbs_hash.ptr, tbs_hash.len);

	/* Sign TBS hash */
	Q_USEFUL_BUF_MAKE_STACK_UB(sig_buffer, 64);
	struct q_useful_buf_c sig = NULL_Q_USEFUL_BUF_C;

	DMSG("yoink 001");

	status = t_cose_crypto_sign(COSE_ALGORITHM_ES256,
				    signing_key,
				    tbs_hash,
				    sig_buffer,
				    &sig);
	if (status != 0) {
		/* FIXME?: Maybe need to do some clean-ups */
		return status;
	}

	DMSG("yoink 002");

	/* Now put things together into a COSE_Sign1 object... */
	QCBOREncodeContext encode_ctx = { };

	QCBOREncode_Init(&encode_ctx, cose_buffer);

	/* XXX: Omit tag for simplicity... */

	QCBOREncode_OpenArray(&encode_ctx);

	/* Protected parameters */
	QCBOREncode_AddBytes(&encode_ctx, protected_parameters);

	/* Unprotected parameters (empty) */
	QCBOREncode_OpenMap(&encode_ctx);
	QCBOREncode_CloseMap(&encode_ctx);

	/* Payload */
	QCBOREncode_AddBytes(&encode_ctx, payload);

	/* Signature */
	QCBOREncode_AddBytes(&encode_ctx, sig);

	QCBOREncode_CloseArray(&encode_ctx);

	DMSG("yoink 003");

	qcbor_result = QCBOREncode_Finish(&encode_ctx, cose);
	if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
		return T_COSE_ERR_TOO_SMALL;
	} else if (qcbor_result != QCBOR_SUCCESS) {
		return T_COSE_ERR_SIG_FAIL;
	}

	return T_COSE_SUCCESS;
}

/**
 * @brief Encode and sign a COSE_Sign1 object mostly sticking to QCBOR APIs
 */
static inline enum t_cose_err_t encode_cose_sign1_with_qcbor(
	struct t_cose_key signing_key,
	int64_t alg,
	struct q_useful_buf_c payload,
	struct q_useful_buf tbs_buffer,
	struct q_useful_buf cose_buffer,
	struct q_useful_buf_c *cose)
{
	/*
	 * Sig_structure = [
	 *    context : "Signature" / "Signature1" / "CounterSignature",
	 *    body_protected : empty_or_serialized_map,
	 *    ? sign_protected : empty_or_serialized_map,
	 *    external_aad : bstr,
	 *    payload : bstr
	 * ]
	 */

	QCBOREncodeContext encode_ctx;
	struct q_useful_buf_c protected_parameters = NULL_Q_USEFUL_BUF_C;
	struct q_useful_buf_c tbs = NULL_Q_USEFUL_BUF_C;
	Q_USEFUL_BUF_MAKE_STACK_UB(tbs_hash_buffer, 32);
	struct q_useful_buf_c tbs_hash = NULL_Q_USEFUL_BUF_C;
	Q_USEFUL_BUF_MAKE_STACK_UB(sig_buffer, 64);
	struct q_useful_buf_c sig = NULL_Q_USEFUL_BUF_C;
	enum t_cose_err_t status = 0;
	QCBORError qcbor_result = 0;

	DMSG("yikes 001");

	QCBOREncode_Init(&encode_ctx, tbs_buffer);

	QCBOREncode_OpenArray(&encode_ctx);

	/* Context ("Signature1") */
	QCBOREncode_AddSZString(&encode_ctx,
				COSE_SIG_CONTEXT_STRING_SIGNATURE1);

	/* Protected header (Now let's only add `alg` to the header...) */
	QCBOREncode_BstrWrap(&encode_ctx);
	QCBOREncode_OpenMap(&encode_ctx);
	QCBOREncode_AddInt64ToMapN(&encode_ctx,
				   COSE_HEADER_PARAM_ALG, alg);
	QCBOREncode_CloseMap(&encode_ctx);
	QCBOREncode_CloseBstrWrap(&encode_ctx, &protected_parameters);

	DMSG("yikes 002");

	/* AAD (XXX: Is this enough for adding empty AAD?) */
	QCBOREncode_AddBytes(&encode_ctx, NULL_Q_USEFUL_BUF_C);

	DMSG("yikes 003");

	/* Payload */
	QCBOREncode_AddBytes(&encode_ctx, payload);

	QCBOREncode_CloseArray(&encode_ctx);

	DMSG("yikes 004");

	QCBORError cbor_error = QCBOREncode_Finish(&encode_ctx, &tbs);
	if (cbor_error == QCBOR_ERR_BUFFER_TOO_SMALL) {
		return T_COSE_ERR_TOO_SMALL;
	} else if (cbor_error != QCBOR_SUCCESS) {
		return T_COSE_ERR_CBOR_FORMATTING;
	}

	IMSG("TBS:");
	hexdump1(tbs.ptr, tbs.len);

	/* Compute hash */
	struct t_cose_crypto_hash hash_ctx = { };

	status = t_cose_crypto_hash_start(&hash_ctx,
					  COSE_ALGORITHM_SHA_256);
	if (status != 0) {
		EMSG("t_cose_crypto_hash_start() status=%x", status);
		return status;
	}

	DMSG("yikes 005");

	t_cose_crypto_hash_update(&hash_ctx, tbs);

	status = t_cose_crypto_hash_finish(&hash_ctx, tbs_hash_buffer,
					   &tbs_hash);
	if (status != 0) {
		EMSG("t_cose_crypto_hash_finish() status=%x", status);
		return status;
	}

	DMSG("yikes 006");

	/* Sign TBS hash */
	status = t_cose_crypto_sign(COSE_ALGORITHM_ES256,
				    signing_key, tbs_hash,
				    sig_buffer, &sig);
	if (status != 0) {
		EMSG("t_cose_crypto_sign() status=%x", status);
		return status;
	}

	/* XXX: Seems it okay to re-use QCBOREndodeContext */
	QCBOREncode_Init(&encode_ctx, cose_buffer);

	QCBOREncode_OpenArray(&encode_ctx);

	/* Protected parameters */
	/*
	 * NOTE: The following won't work. It has extra leading bytes...
	 *
	 *     QCBOREncode_AddBytes(&encode_ctx, protected_parameters);
	 */
	QCBOREncode_BstrWrap(&encode_ctx);
	QCBOREncode_OpenMap(&encode_ctx);
	QCBOREncode_AddInt64ToMapN(&encode_ctx,
				   COSE_HEADER_PARAM_ALG, alg);
	QCBOREncode_CloseMap(&encode_ctx);
	QCBOREncode_CloseBstrWrap(&encode_ctx, NULL /* This can be NULL! */);

	/* Unprotected parameters */
	QCBOREncode_OpenMap(&encode_ctx);
	QCBOREncode_CloseMap(&encode_ctx);

	/* Payload */
	QCBOREncode_AddBytes(&encode_ctx, payload);

	/* Signature */
	QCBOREncode_AddBytes(&encode_ctx, sig);
	QCBOREncode_CloseArray(&encode_ctx);

	DMSG("yikes 007");

	qcbor_result = QCBOREncode_Finish(&encode_ctx, cose);
	if (qcbor_result != QCBOR_SUCCESS) {
		return T_COSE_ERR_FAIL;
	}

	IMSG("Cose_Sign1:");
	hexdump1(cose->ptr, cose->len);

	return T_COSE_SUCCESS;
}

/**
 * @brief Verify a COSE_Sign1 object by manually reconstructing Sig_structure
 */
static inline enum t_cose_err_t verify_cose_sign1_by_building_tbs(
	struct t_cose_key verification_key,
	struct q_useful_buf_c payload,
	struct q_useful_buf_c cose)
{
	(void)payload;

	QCBORDecodeContext decode_ctx = { };
	struct q_useful_buf_c protected_parameters = NULL_Q_USEFUL_BUF_C;
	QCBORItem unprotected_parameters = { };
	struct q_useful_buf_c payload_from_cose = NULL_Q_USEFUL_BUF_C;
	struct q_useful_buf_c sig = NULL_Q_USEFUL_BUF_C;

	/* To hold and store TBS hash */
	Q_USEFUL_BUF_MAKE_STACK_UB(tbs_hash_buffer, 32);
	struct q_useful_buf_c tbs_hash = NULL_Q_USEFUL_BUF_C;

	QCBORError qcbor_result = QCBOR_SUCCESS;
	enum t_cose_err_t status = 0;

	QCBORDecode_Init(&decode_ctx, cose, QCBOR_DECODE_MODE_NORMAL);

	QCBORDecode_EnterArray(&decode_ctx, NULL);

	/* Protected parameters */
	QCBORDecode_EnterBstrWrapped(&decode_ctx,
				     QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
				     &protected_parameters);

#if 0
	/* XXX: This attempt to retrieve `alg` didn't work! */
	int64_t alg = 0;
	QCBORDecode_GetInt64InMapN(&decode_ctx,
				   COSE_HEADER_PARAM_ALG,
				   &alg);

	IMSG("alg: %ld", alg); /* alg: 0 (although expected -7) */
#endif

	IMSG("protected parameters:");
	hexdump1(protected_parameters.ptr, protected_parameters.len);

	QCBORDecode_ExitBstrWrapped(&decode_ctx);

	/* Unproected parameters */
	QCBORDecode_GetNext(&decode_ctx, &unprotected_parameters);

	/*
	 * TODO: How to handle QCBORItem? For example, what should do with
	 * QCBORItem if I know that's a *map* and I'd like to get values out
	 * of it?
	 */

	/* Payload */
	QCBORDecode_EnterBstrWrapped(&decode_ctx,
				     QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
				     &payload_from_cose);

	QCBORDecode_ExitBstrWrapped(&decode_ctx);

	IMSG("payload:");
	hexdump1(payload_from_cose.ptr, payload_from_cose.len);

	/* Signature */
	QCBORDecode_GetByteString(&decode_ctx, &sig);

	IMSG("sig:");
	hexdump1(sig.ptr, sig.len);

	QCBORDecode_ExitArray(&decode_ctx);

	qcbor_result = QCBORDecode_Finish(&decode_ctx);
	if (qcbor_result != QCBOR_SUCCESS) {
		EMSG("QCBORDecode(cose) qcbor_result=%x", qcbor_result);
		return T_COSE_ERR_FAIL;
	}

	DMSG("more steps to go...");

	/* Create TBS with retrieved components */
	status = create_tbs_hash(T_COSE_ALGORITHM_ES256,
				 protected_parameters,
				 NULL_Q_USEFUL_BUF_C,
				 payload_from_cose,
				 tbs_hash_buffer,
				 &tbs_hash);
	if (status != 0) {
		EMSG("create_tbs_hash() status=%x", status);
		return status;
	}

	IMSG("TBS hash");
	hexdump1(tbs_hash.ptr, tbs_hash.len);

#if 0
	/* XXX: What if I tamper with a single byte within signature? */
	/* Verification fails :) */
	*((char *)sig.ptr + 32) ^= 0xff;
#endif

	/* Verify TBS hash against the signature... */
	status = t_cose_crypto_verify(T_COSE_ALGORITHM_ES256,
				      verification_key,
				      NULL_Q_USEFUL_BUF_C,
				      tbs_hash,
				      sig);
	if (status != 0) {
		EMSG("t_cose_crypto_verify() status=%x", status);
		return status;
	}

	IMSG("COSE_Sign1 verification successful!");

	return T_COSE_SUCCESS;
}

static unsigned char q_buf[2 * 32] = { };

#define PAYLOAD		"This is content."

TEE_Result run_cbor_cose_tests(void)
{
	struct t_cose_key signing_key = { };
	struct t_cose_key verification_key = { };
	enum t_cose_err_t status = 0;

	struct q_useful_buf_c payload = Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD);

	/* For `encode_cose_sign1_simple()` */
	Q_USEFUL_BUF_MAKE_STACK_UB(cose_buffer1, 512);
	struct q_useful_buf_c cose1 = NULL_Q_USEFUL_BUF_C;

	/* For `encode_cose_sign1_with_create_tbs()` */
	Q_USEFUL_BUF_MAKE_STACK_UB(cose_buffer2, 512);
	struct q_useful_buf_c cose2 = NULL_Q_USEFUL_BUF_C;

	/* Set up keys (FIXME: redundant tasks...) */
	status = make_key_pair(T_COSE_ALGORITHM_ES256, &signing_key);
	if (status != 0) {
		EMSG("make_key_pair() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	status = public_key_from(signing_key, &verification_key, q_buf,
				 sizeof(q_buf));
	if (status != 0) {
		EMSG("public_key_from() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	/* Encode a COSE_Sign1 object with t_cose API */
	status = encode_cose_sign1_simple(signing_key,
					  payload,
					  cose_buffer1,
					  &cose1);
	if (status != 0) {
		EMSG("encode_cose_sign1_simple() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	/* Print encoded COSE_Sign1 object in hex string... */
	hexdump1(cose1.ptr, cose1.len);

	/* Verify `cose1` with t_cose APIs */
	status = verify_cose_sign1_simple(verification_key, payload, cose1);
	if (status != 0) {
		EMSG("verify_cose_sign1_simple(cose1) status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	/* Encode/sign and verify COSE_Sign1 object with create_tbs() */
	struct q_useful_buf_c protected_params = { };
	UsefulBuf_MAKE_STACK_UB(protected_params_buffer, 64);
	QCBOREncodeContext encode_ctx = { };
	
	QCBOREncode_Init(&encode_ctx, protected_params_buffer);

	protected_params = encode_protected_parameters(T_COSE_ALGORITHM_ES256,
						       protected_params_buffer);
	if (q_useful_buf_c_is_null(protected_params)) {
		return TEE_ERROR_GENERIC;
	}

	status = encode_cose_sign1_with_create_tbs(signing_key,
						   protected_params,
						   payload,
						   cose_buffer2, &cose2);
	if (status != 0) {
		EMSG("encode_cose_sign1_with_create_tbs() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	IMSG("Cose_Sign1 created with create_tbs() helper function...");
	hexdump1(cose2.ptr, cose2.len);

	/*
	 * Verify COSE_Sign1 by manually decoding it using QCBOR APIs and
	 * reconstructing TBS hash from it with `create_tbs_hash()` helper
	 * function.
	 */
	status = verify_cose_sign1_by_building_tbs(verification_key,
						   payload,
						   cose1);
	if (status != 0) {
		EMSG("verify_cose_sign1_by_building_tbs() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	/* Can we do some more manual work? */
	Q_USEFUL_BUF_MAKE_STACK_UB(tbs_buffer, 512);
	Q_USEFUL_BUF_MAKE_STACK_UB(cose_buffer3, 512);
	struct q_useful_buf_c cose3 = NULL_Q_USEFUL_BUF_C;

	status = encode_cose_sign1_with_qcbor(signing_key,
					      COSE_ALGORITHM_ES256,
					      payload,
					      tbs_buffer,
					      cose_buffer3,
					      &cose3);
	if (status != 0) {
		EMSG("encode_cose_sign1_with_qcbor() status=%x", status);
		return status;
	}

	status = verify_cose_sign1_simple(verification_key, payload, cose3);
	if (status != 0) {
		EMSG("verify_cose_sign1_simple() status=%x", status);
		return status;
	}

	IMSG("run_cbor_cose_tests: Good bye!");

	return TEE_SUCCESS;
}