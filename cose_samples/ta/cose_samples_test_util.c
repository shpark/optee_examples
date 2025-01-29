// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Seonghyun Park
 */

#include <stdio.h>
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
#include "tee_api_compat.h"

unsigned char private_key_pem[] = PRIVATE_KEY_prime256v1_PEM;

unsigned char public_key_pem[] = PUBLIC_KEY_primev256v1_PEM;

size_t public_key_pem_len = sizeof(public_key_pem);

/* P-256 public key in uncompressed format */
unsigned char point[1 + 2 * 32] = { };

/* EC key private value */
unsigned char d[32] = { };

void hexdump(const char *buf, size_t len)
{
	size_t ofs = 0;
	for (; ofs < len; ofs += 8) {
		IMSG("%02x %02x %02x %02x %02x %02x %02x %02x",
		     buf[ofs], buf[ofs + 1], buf[ofs + 2], buf[ofs + 3],
		     buf[ofs + 4], buf[ofs + 5], buf[ofs + 6], buf[ofs + 7]);
	}
}

#define NUM_BYTES_IN_ROW	80

void hexdump1(const char *buf, size_t len)
{
	size_t l = len;
	size_t bofs = 0;
	size_t sofs = 0;
	static char s[2 * NUM_BYTES_IN_ROW + 1] = { };

	TEE_MemFill(s, 0, sizeof(s));

	for (; bofs < l; bofs++) {
		snprintf((char *)s + sofs,
			 sizeof(s) - sofs,
			 "%02x", buf[bofs]);

		sofs += 2;

		if ((bofs + 1) % NUM_BYTES_IN_ROW  == 0) {
			IMSG("%s", s);
			TEE_MemFill(s, 0, sizeof(s));
			sofs = 0;
		}
	}

	if (sofs != 0)
		IMSG("%s", s);
}

int my_entropy(void *data, unsigned char *seed, size_t seed_len)
{
	(void)data;
	TEE_GenerateRandom(seed, seed_len);
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
	mbedtls_mpi ec_private_value = { };
	mbedtls_ecp_point q = { };

	/* XXX: what would happen if `ecp` doesn't have `d` (i.e., pubkey)? */
	status = mbedtls_ecp_export(ecp, &grp, &ec_private_value, &q);
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

	status = mbedtls_mpi_write_binary(&ec_private_value, d_buf, d_buf_len);
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

enum t_cose_err_t public_key_from(struct t_cose_key private_key,
				  struct t_cose_key *out_public_key,
				  unsigned char *point_buf,
				  size_t point_buf_len)
{
	TEE_ObjectHandle keypair = private_key.k.key_obj;
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectInfo info = { };
	uint32_t curve;
	TEE_Attribute attrs[3] = { };
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	DMSG("ding 001");

	/* FIXME: support different key size */
	if (point_buf_len < 2 * 32)
		return TEE_ERROR_SHORT_BUFFER;

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

	DMSG("ding 004");

	uint32_t size = 32; /* FIXME: support different key size */

	res = TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   point_buf, &size);
	if (size != 32)
		res = TEE_ERROR_BAD_STATE;
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, point_buf,
			     size);

	res = TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
					   &point_buf[32], &size);
	if (size != 32)
		res = TEE_ERROR_BAD_STATE;
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     &point_buf[32], size);

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
