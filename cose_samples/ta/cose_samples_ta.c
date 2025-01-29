// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2025, Seonghyun Park
 */

#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#include <qcbor/qcbor_decode.h>

#include "cose_samples_ta.h"

#include "cose_samples_ta_test.h"

TEE_Result TA_CreateEntryPoint(void)
{
	run_crypto_tests();

	run_cbor_cose_tests();

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4],
				    void **session)
{
	(void)param_types;
	(void)params;
	(void)session;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	(void)session;
}

static TEE_Result cmd_gen_key(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	(void)param_types;
	(void)params;

	return TEE_SUCCESS;
}

static TEE_Result cmd_sign(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	(void)param_types;
	(void)params;

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	(void)session;

	switch (cmd) {
	case TA_COSE_SAMPLES_CMD_GEN_KEY:
		return cmd_gen_key(param_types, params);
	case TA_COSE_SAMPLES_CMD_SIGN:
		return cmd_sign(param_types, params);
	default:
		EMSG("Command ID %#" PRIx32 " is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
