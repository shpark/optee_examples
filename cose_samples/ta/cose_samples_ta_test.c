// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Seonghyun Park
 */

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
	TEE_GenerateRandom(seed, seed_len);
	return 0;
}

static TEE_Result pem_to_mbedtls_pk(mbedtls_pk_context *pk) {
	mbedtls_ctr_drbg_context ctr_dbrg;
	mbedtls_entropy_context entropy;
	mbedtls_ecp_keypair *ecp;
	int status;

	mbedtls_ctr_drbg_init(&ctr_dbrg);
	mbedtls_entropy_init(&entropy);

	status = mbedtls_ctr_drbg_seed(&ctr_dbrg,
				       my_entropy,
				       &entropy,
				       NULL, 0);
	if (status != 0) {
		EMSG("mbedtls_ctr_drbg_seed() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	mbedtls_pk_init(pk);

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

	ecp = mbedtls_pk_ec(*pk);

	/* Check ECP group id */
	if (mbedtls_ecp_keypair_get_group_id(ecp) != MBEDTLS_ECP_DP_SECP256R1) {
		EMSG("mbedtls_ecp_keypair_get_group_id() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	/* Export the private key */
	mbedtls_ecp_group grp = { };
	mbedtls_mpi d = { };
	mbedtls_ecp_point q = { };

	status = mbedtls_ecp_export(ecp, &grp, &d, &q);
	if (status != 0) {
		EMSG("mbedtls_ecp_export() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	unsigned char point[1 + 2 * 32] = { };
	size_t olen = 0;

	status = mbedtls_ecp_point_write_binary(&grp, &q,
						MBEDTLS_ECP_PF_UNCOMPRESSED,
						&olen,
						point, sizeof(point));
	if (status) {
		EMSG("mbedtls_ecp_point_write_binary() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	unsigned char d_buf[32] = { };

	status = mbedtls_mpi_write_binary(&d, d_buf, sizeof(d_buf));
	if (status) {
		EMSG("mbedtls_mpi_write_binary() status=%x", status);
		return TEE_ERROR_GENERIC;
	}

	DMSG("d:"); hexdump((const char *)d_buf, sizeof(d_buf));

	DMSG("Q:"); hexdump((const char *)point + 1, sizeof(point) - 1);

	/* TODO: error handling and graceful clean up (should I? hehehe) */

	return TEE_SUCCESS;
}

enum t_cose_err_t make_key_pair(int32_t            cose_algorithm_id,
				struct t_cose_key *key_pair) {
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Attribute curve = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	/* TODO: Support different algorithms, e.g., P-384 */
	(void)cose_algorithm_id;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &obj);
	if (res != TEE_SUCCESS)
		return T_COSE_ERR_FAIL;

	TEE_InitValueAttribute(&curve, TEE_ATTR_ECC_CURVE,
			       TEE_ECC_CURVE_NIST_P256, 0);

	res = TEE_GenerateKey(obj, 256, &curve, 1);
	if (res != TEE_SUCCESS)
		return T_COSE_ERR_FAIL;

	key_pair->k.key_obj = obj;

	return T_COSE_SUCCESS;
}

TEE_Result run_tests(void)
{
	TEE_Result res = TEE_SUCCESS;

	mbedtls_pk_context pk = {};

	res = pem_to_mbedtls_pk(&pk);
	if (res != TEE_SUCCESS) {
		EMSG("pem_to_mbedtsl_pk");
		return res;
	}

	/*
	 * TODO: set-up signer and verifier with pk originated from the test
	 * PEM string.
	 */
	struct t_cose_key signer = { };

	(void)signer;

	return TEE_SUCCESS;
}