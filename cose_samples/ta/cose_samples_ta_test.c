// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Seonghyun Park
 */

#include <stdint.h>
#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

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
#include "qcbor/UsefulBuf.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_standard_constants.h"
#include "tee_api_compat.h"
#include "utee_defines.h"

/*
 * SEQUENCE
 *   INTEGER 01
 *   OCTETSTRING 4798dc6731dbfb75f75530c5be7a21fc82e4415600b85bdcc3b229f624f681d9
 *   [0]
 *     ObjectIdentifier P-256 (1 2 840 10045 3 1 7)
 *   [1]
 *     BITSTRING 0004eeed407f55375be5fc74f296447c..(total 66bytes)..f4b5859f8341cc1f9987e76d91a1faf1
 */
#define PRIVATE_KEY_prime256v1_PEM						\
	"-----BEGIN EC PRIVATE KEY-----\n"					\
	"MHcCAQEEIEeY3Gcx2/t191Uwxb56IfyC5EFWALhb3MOyKfYk9oHZoAoGCCqGSM49"	\
	"AwEHoUQDQgAE7u1Af1U3W+X8dPKWRHzymYp+oaJRiH37OUUKvc9cD839VZYDB4uv"	\
	"5LYj9XsF0qca9LWFn4NBzB+Zh+dtkaH68Q=="					\
	"-----END EC PRIVATE KEY-----"

static const unsigned char private_key_pem[] = PRIVATE_KEY_prime256v1_PEM;

/**
 * @brief A hex dump utility
 *
 * A hex dump utility. Assumes that `len` is divided by 8
 */
static void hexdump(const char *buf, size_t len)
{
	size_t ofs = 0;
	for (; ofs < len; ofs += 8) {
		IMSG("%02x %02x %02x %02x %02x %02x %02x %02x",
		     buf[ofs], buf[ofs + 1], buf[ofs + 2], buf[ofs + 3],
		     buf[ofs + 4], buf[ofs + 5], buf[ofs + 6], buf[ofs + 7]);
	}
}

/**
 * @brief A (too much?) simplified altenative to mbedtls_entropy_func
 *
 * Seems like there's an issue with mbedtls_entropy_func() on OP-TEE.
 * See https://github.com/Mbed-TLS/mbedtls/issues/5352 for further
 * information.
 */
static int my_entropy(void *data, unsigned char *seed, size_t seed_len)
{
	(void)data;

	DMSG("what?");

	TEE_GenerateRandom(seed, seed_len);

	DMSG("huh?");

	return 0;
}

static TEE_Result pem_to_mbedtls_pk(mbedtls_pk_context *pk,
				    unsigned char *point_buf,
				    size_t point_buf_len,
				    unsigned char *d_buf,
				    size_t d_buf_len)
{
	mbedtls_ctr_drbg_context ctr_dbrg;
	mbedtls_ecp_keypair *ecp;
	int status;

	mbedtls_ctr_drbg_init(&ctr_dbrg);

	DMSG("ugh 000a");

	status = mbedtls_ctr_drbg_seed(&ctr_dbrg,
				       my_entropy,
				       NULL,
				       NULL, 0);
	if (status != 0) {
		EMSG("mbedtls_ctr_drbg_seed() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("ugh 000c");

	mbedtls_pk_init(pk);

	DMSG("ugh 001");

	status = mbedtls_pk_parse_key(pk,
				      private_key_pem,
				      sizeof(private_key_pem),
				      /*pwd=*/ NULL, /*pwd_len=*/ 0,
				      mbedtls_ctr_drbg_random,
				      &ctr_dbrg);
	if (status != 0) {
		EMSG("mbedtls_pk_parse_key() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("ugh 002");

	/* Check PEM key type */
	/*
	 * NOTE: among different seemingly legitimate key types (e.g.,
	 * MBEDTLS_PK_ECDSA, MBEDTLS_PK_ECKEY_DH), mbedtls_pk_parse_key()
	 * sets the key type to MBEDTLS_PK_ECKEY when parsing the above
	 * PEM string.
	 */
	if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_ECKEY) {
		EMSG("mbedtls_pk_get_type() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("ugh 003");

	ecp = mbedtls_pk_ec(*pk);

	/* Check ECP group id */
	if (mbedtls_ecp_keypair_get_group_id(ecp) != MBEDTLS_ECP_DP_SECP256R1) {
		EMSG("mbedtls_ecp_keypair_get_group_id() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("ugh 004");

	/* Export the private key */
	mbedtls_ecp_group grp = { };
	mbedtls_mpi d = { };
	mbedtls_ecp_point q = { };

	/* XXX: what would happen if `ecp` doesn't have `d` (i.e., pubkey)? */
	status = mbedtls_ecp_export(ecp, &grp, &d, &q);
	if (status != 0) {
		EMSG("mbedtls_ecp_export() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("ugh 005");

	size_t olen = 0;
	status = mbedtls_ecp_point_write_binary(&grp, &q,
						MBEDTLS_ECP_PF_UNCOMPRESSED,
						&olen,
						point_buf, point_buf_len);
	if (status) {
		EMSG("mbedtls_ecp_point_write_binary() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("ugh 006");

	status = mbedtls_mpi_write_binary(&d, d_buf, d_buf_len);
	if (status) {
		EMSG("mbedtls_mpi_write_binary() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("d:");

	hexdump((const char *)d_buf, d_buf_len);

	DMSG("Q:");

	hexdump((const char *)point_buf + 1, point_buf_len - 1);

	/* TODO: error handling and graceful clean up (should I? hehehe) */

	return TEE_SUCCESS;
}

enum t_cose_err_t make_key_pair(int32_t cose_algorithm_id,
				struct t_cose_key *key_pair)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Attribute attrs[4] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	switch (cose_algorithm_id) {
	case T_COSE_ALGORITHM_ES256:
		TEE_InitValueAttribute(&attrs[3], TEE_ATTR_ECC_CURVE,
				       TEE_ECC_CURVE_NIST_P256, 0);
		break; 
	default:
		/* TODO: Support different algorithms... */
		EMSG("alg (%x) currently not supported", cose_algorithm_id);
		return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &obj);
	if (res != TEE_SUCCESS)
		return T_COSE_ERR_FAIL;

	mbedtls_pk_context pk = { };

	DMSG("eek 001");

	/* Set buffer attributes of `obj` with values stored in `pk` */
	unsigned char point[1 + 2 * 32] = { }; /* uncompressed P-256 point */
	unsigned char d[32] = { };

	res = pem_to_mbedtls_pk(&pk, point, sizeof(point), d, sizeof(d));
	if (res != TEE_SUCCESS) {
		EMSG("pem_to_mbedtls_pk()");
		return T_COSE_ERR_FAIL;
	}

	DMSG("eek 002");

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PRIVATE_VALUE, d,
			     sizeof(d));

	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			     &point[1], 32);

	TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     &point[1 + 32], 32);

	res = TEE_PopulateTransientObject(obj, attrs, 4);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopoulateTransientObject() res=%x", res);
		return T_COSE_ERR_FAIL;
	}

	key_pair->k.key_obj = obj;

	mbedtls_pk_free(&pk);

	return T_COSE_SUCCESS;
}

static enum t_cose_err_t public_key_from(struct t_cose_key signing_key,
					 struct t_cose_key *out_public_key)
{
	TEE_ObjectHandle keypair = signing_key.k.key_obj;
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectInfo info = { };
	uint32_t curve;
	TEE_Attribute attrs[3] = { };
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	DMSG("ding 001");

	res = TEE_GetObjectInfo1(keypair, &info);

	if (info.objectType != TEE_TYPE_ECDSA_KEYPAIR)
		return T_COSE_ERR_INVALID_ARGUMENT;

	DMSG("ding 002");

	res = TEE_GetObjectValueAttribute(keypair, TEE_ATTR_ECC_CURVE, &curve,
					  NULL);
	if (res != TEE_SUCCESS)
		return T_COSE_ERR_INVALID_ARGUMENT;

	DMSG("ding 003");

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY,
					  info.maxKeySize,
					  &obj);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * XXX: this buffer resides in stack, and its content may be clobbered
	 * later, leading the signature verification fail...
	 *
	 * Even worse, attribute X and Y are pointing to the same buffer now.
	 * Yet I am too tired to fix this now. I will fix it later.
	 *
	 * How to fix? Allocate a buffer that lives long enough and make the
	 * attribute buffer pointer points to that buffer...
	 */
	unsigned char buf[32] = { }; /* FIXME: Don't use fixed size buffer... */
	uint32_t size = sizeof(buf);

	DMSG("ding 004");

	res = TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   buf, &size);
	if (size != sizeof(buf))
		res = TEE_ERROR_BAD_STATE;
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, buf, size);

	res = TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
					   buf, &size);
	if (size != sizeof(buf))
		res = TEE_ERROR_BAD_STATE;
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, buf, size);

	TEE_InitValueAttribute(&attrs[2], TEE_ATTR_ECC_CURVE, curve, 0);

	res = TEE_PopulateTransientObject(obj, attrs, 3);
	if (res != TEE_SUCCESS)
		goto out;

	out_public_key->k.key_obj = obj;

	return T_COSE_SUCCESS;

out:
	TEE_FreeTransientObject(obj);
	return res == TEE_SUCCESS ? T_COSE_SUCCESS : T_COSE_ERR_FAIL;
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

TEE_Result run_tests(void)
{
	TEE_Result res = TEE_SUCCESS;
	struct t_cose_key signing_key = { };
	struct t_cose_key verification_key = { };
	enum t_cose_err_t status = T_COSE_ERR_FAIL;

	DMSG("yo 001");

	status = make_key_pair(T_COSE_ALGORITHM_ES256, &signing_key);
	if (status != 0) {
		EMSG("make_key_pair() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("yo 002");

	status = public_key_from(signing_key, &verification_key);
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

	IMSG("Good bye!");

	return res;
}