// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2025, Seonghyun Park
 */

#ifndef __COSE_SAMPLES_TA_H__
#define __COSE_SAMPLES_TA_H__

/* UUID of the COSE example trusted application */
#define TA_COSE_SAMPLES_UUID \
	{ 0x59dd9aed, 0xa017, 0x5d37, \
		{ 0x84, 0xb4, 0x0f, 0xdb, 0xb9, 0x0d, 0xf5, 0x88 } }

/**
 * @enum COSE samples TA commands
 */
enum ta_coes_samples_cmd {
	/**
	 * @brief TBA
	 */
	TA_COSE_SAMPLES_CMD_GEN_KEY = 0,

	/**
	 * @brief TBA
	 */
	TA_COSE_SAMPLES_CMD_SIGN = 1,
};

#endif /* __COSE_SAMPLES_TA_H */
