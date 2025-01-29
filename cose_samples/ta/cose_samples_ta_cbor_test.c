// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Seonghyun Park
 */

#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>

#include <trace.h>

#include <t_cose/t_cose_common.h>
#include <t_cose_make_test_pub_key.h>

#include "compiler.h"
#include "cose_samples_ta_test.h"
#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor_encode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
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
 * @brief Verify a COSE_Sign1 object usint t_cose APIs
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

static enum t_cose_err_t __maybe_unused encode_protected_parameters(
	int32_t cose_algorithm_id,
	QCBOREncodeContext *ctx)
{
	(void)cose_algorithm_id;
	(void)ctx;

	return T_COSE_ERR_FAIL;
}

/**
 * @brief Encode and sign a COSE_Sign1 object mostly sticking to QCBOR APIs
 */
static inline __maybe_unused enum t_cose_err_t encode_cose_sign1_more_steps(
	struct t_cose_key signing_key,
	struct q_useful_buf_c payload,
	struct q_useful_buf cose_buffer,
	struct q_useful_buf_c *cose)
{
	(void)signing_key;
	(void)payload;
	(void)cose_buffer;
	(void)cose;

	return T_COSE_ERR_FAIL;
}

static unsigned char q_buf[2 * 32] = { };

#define PAYLOAD_STRING	"This is content."

TEE_Result run_cbor_cose_tests(void)
{
	struct t_cose_key signing_key = { };
	struct t_cose_key verification_key = { };
	enum t_cose_err_t status = 0;

	struct q_useful_buf_c payload = {
		PAYLOAD_STRING,
		strlen(PAYLOAD_STRING)
	};

	/* For COSE_Sign1 object created by `encode_cose_sign1_simple()` */
	Q_USEFUL_BUF_MAKE_STACK_UB(cose_buffer1, 512);
	struct q_useful_buf_c cose1 = NULL_Q_USEFUL_BUF_C;

	/* For COSE_Sign1 object created by `encode_cose_sign1_more_steps()` */
	/* TODO */

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

	status = verify_cose_sign1_simple(verification_key, payload, cose1);
	if (status != 0) {
		EMSG("verify_cose_sign1_simple() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	/* TODO: Verify `cose1` with t_cose APIs */

	/* Create a TBS hash */

	/*
	 * NOTE: `protected_parameters` has to be a a `bstr`.
	 */

	/*
	create_tbs(struct q_useful_buf_c protected_parameters,
		   struct q_useful_buf_c aad,
		   struct q_useful_buf_c payload,
		   struct q_useful_buf buffer_for_tbs,
		   struct q_useful_buf_c *tbs)
	*/

	/* Prepare protected parameters */
	/* See `encode_protected_parameters(alg, cbor_encode_ctx)` */

	/* Sign TBS hash and output a COSE_Sign1 object */

	/* Try to reconstruct TBS hash from a COSE_Sign1 object */


	IMSG("run_cbor_cose_tests: Good bye!");

	return TEE_SUCCESS;
}