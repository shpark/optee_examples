// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Seonghyun Park
 */

#ifndef COSE_SAPMLES_TA_TEST_H
#define COSE_SAPMLES_TA_TEST_H

#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#include <t_cose/t_cose_common.h>

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
	"5LYj9XsF0qca9LWFn4NBzB+Zh+dtkaH68Q==\n"				\
	"-----END EC PRIVATE KEY-----"

#define PUBLIC_KEY_primev256v1_PEM						\
	"-----BEGIN PUBLIC KEY-----\n"						\
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7u1Af1U3W+X8dPKWRHzymYp+oaJR"	\
	"iH37OUUKvc9cD839VZYDB4uv5LYj9XsF0qca9LWFn4NBzB+Zh+dtkaH68Q==\n"	\
	"-----END PUBLIC KEY-----"

/**
 * @brief A hex dump utility
 *
 * A hex dump utility. Assumes that `len` is divided by 8
 */
void hexdump(const char *buf, size_t len);

/**
 * @brief A hex dump utility
 *
 * A hex dump utility. Assumes that `len` is divided by 8
 */
void hexdump1(const char *buf, size_t len);

/**
 * @brief A (too much?) simplified altenative to mbedtls_entropy_func
 *
 * Seems like there's an issue with mbedtls_entropy_func() on OP-TEE.
 * See https://github.com/Mbed-TLS/mbedtls/issues/5352 for further
 * information.
 */
int my_entropy(void *data, unsigned char *seed, size_t seed_len);

/**
 * @brief Initialize a t_cose_key public key from a t_cose_key private key
 */
enum t_cose_err_t public_key_from(struct t_cose_key private_key,
				  struct t_cose_key *out_public_key,
				  unsigned char *point_buf,
				  size_t point_buf_len);

TEE_Result run_crypto_tests(void);

TEE_Result run_cbor_cose_tests(void);

#endif /* COSE_SAPMLES_TA_TEST_H */
