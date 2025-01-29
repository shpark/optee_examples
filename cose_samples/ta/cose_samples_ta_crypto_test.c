// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Seonghyun Park
 */

#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <utee_defines.h>

#include <trace.h>

#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>

#include <t_cose_util.h>
#include <t_cose_crypto.h>
#include <t_cose/t_cose_common.h>
#include <t_cose/t_cose_sign1_sign.h>
#include <t_cose/t_cose_sign1_verify.h>
#include <t_cose_make_test_pub_key.h>

#include "cose_samples_ta_test.h"

/* P-256 public key in uncompressed format */
extern unsigned char point[1 + 2 * 32];

/* EC key private value */
extern unsigned char d[32];

extern unsigned char private_key_pem[];

extern unsigned char public_key_pem[];

extern size_t public_key_pem_len;

static TEE_Result mbedtls_parse_pubkey_pem_test(void)
{
	mbedtls_pk_context pk = { };
	int status = 0;

	status = mbedtls_pk_parse_public_key(&pk,
					     public_key_pem,
					     public_key_pem_len);
	if (status != 0) {
		EMSG("mbedtls_pk_parse_public_key() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	IMSG("pk type=%d", mbedtls_pk_get_type(&pk));

	mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(pk);

	IMSG("group id=%d", mbedtls_ecp_keypair_get_group_id(ecp));

	mbedtls_ecp_group group = { };
	mbedtls_ecp_point q = { };

	status = mbedtls_ecp_export(ecp, &group, NULL, &q);
	if (status != 0) {
		EMSG("mbedtls_ecp_export status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	unsigned char q_buffer[1 + 2 * 32] = { };
	size_t olen = 0;

	status = mbedtls_ecp_point_write_binary(&group, &q,
						MBEDTLS_ECP_PF_UNCOMPRESSED,
						&olen,
						q_buffer, sizeof(q_buffer));
	if (status != 0) {
		EMSG("mbedtls_ecp_point_write_binary() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("Q:");
	hexdump((const char *)q_buffer, sizeof(q_buffer));

	return TEE_SUCCESS;
}


static enum t_cose_err_t t_cose_hash_test(struct q_useful_buf_c data_to_hash,
					  struct q_useful_buf hash_buffer,
					  struct q_useful_buf_c *hash_result)
{
	struct t_cose_crypto_hash hash_ctx = { };
	enum t_cose_err_t status = T_COSE_ERR_FAIL;

	status = t_cose_crypto_hash_start(&hash_ctx, COSE_ALGORITHM_SHA_256);
	if (status != 0)
		return status;

	t_cose_crypto_hash_update(&hash_ctx, data_to_hash);

	status = t_cose_crypto_hash_finish(&hash_ctx,
					   hash_buffer,
					   hash_result);

	return status;
}

static enum t_cose_err_t t_cose_sign_test(int32_t alg,
					  struct t_cose_key signing_key,
					  struct q_useful_buf_c digest,
					  struct q_useful_buf sig_buffer,
					  struct q_useful_buf_c *sig_result)
{
	return t_cose_crypto_sign(alg, signing_key,
				  digest, sig_buffer, sig_result);
}

static enum t_cose_err_t t_cose_verify_test(int32_t alg,
					    struct t_cose_key verification_key,
					    struct q_useful_buf_c digest,
					    struct q_useful_buf_c sig)
{
	return t_cose_crypto_verify(alg, verification_key,
				    /* kid=*/ NULL_Q_USEFUL_BUF_C,
				   digest, sig);
}

TEE_Result run_crypto_tests(void)
{
	TEE_Result res = TEE_SUCCESS;
	struct t_cose_key signing_key = { };
	struct t_cose_key verification_key = { };
	enum t_cose_err_t status = T_COSE_ERR_FAIL;
	unsigned char public_key_buffer[2 * 32] =  { };

	DMSG("yo 000");

	status = mbedtls_parse_pubkey_pem_test();
	if (status != 0) {
		EMSG("mbedtls_parse_pubkey_pem_test() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("yo 001");

	status = make_key_pair(T_COSE_ALGORITHM_ES256, &signing_key);
	if (status != 0) {
		EMSG("make_key_pair() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("yo 002");

	status = public_key_from(signing_key, &verification_key,
				 public_key_buffer, sizeof(public_key_buffer));
	if (status != 0) {
		EMSG("public_key_from() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	size_t sig_size = 0;
	status = t_cose_crypto_sig_size(T_COSE_ALGORITHM_ES256, signing_key, &sig_size);
	if (status != 0 || sig_size != 2 * 32) {
		EMSG("t_cose_crypto_sig_size() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	/* Simple t_cose_hash_* test */
	const char msg[] = "hello, world!";
	unsigned char hash_buffer[TEE_SHA256_HASH_SIZE] = { };
	struct q_useful_buf_c digest = NULL_Q_USEFUL_BUF_C;
	status = t_cose_hash_test((struct q_useful_buf_c) { msg, strlen(msg) },
				  (struct q_useful_buf) { hash_buffer,
							  TEE_SHA256_HASH_SIZE },
				  &digest);
	if (res != TEE_SUCCESS) {
		EMSG("t_cose_hash_test() res=%x", res);
		return TEE_ERROR_GENERIC;
	}

	IMSG("sha256(\"hello, world!\"):");
	hexdump((const char *)hash_buffer, sizeof(hash_buffer));

	/* Simple signing and verification test */
	unsigned char sig_buffer[64] = { };
	struct q_useful_buf_c sig = NULL_Q_USEFUL_BUF_C;
	status = t_cose_sign_test(T_COSE_ALGORITHM_ES256, signing_key, digest,
				  (struct q_useful_buf) { sig_buffer, 64 },
				  &sig);
	if (status != 0) {
		EMSG("t_cose_sign_test() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	IMSG("ES256(\"hello, world!\"):");
	hexdump((const char*)sig.ptr, sig.len);

	status = t_cose_verify_test(T_COSE_ALGORITHM_ES256, verification_key,
				    digest, sig);
	if (status != 0) {
		EMSG("t_cose_verify_test() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	IMSG("run_crypto_tests: Good bye!");

	return res;
}