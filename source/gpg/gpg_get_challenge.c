/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "gpg_types.h"
#include "gpg_dispatch.h"
#include "gpg_se_if.h"
#include "gpg_util.h"
#include "gpg_config.h"

uint8_t gpg_get_challenge(gpg_handle_struct_t *gpgHandle) {
	sss_status_t status;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	if(pio->P1 != 0x00 || pio->P2 != 0x00) {
		sendError(gpgHandle, SW_WRONG_P1P2);
	}
	if(pio->LC != 0x0000 || pio->LE > MAX_RAPDU_LEN) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	status = se_get_random(pio->rspData, pio->LE);
	if (status == kStatus_SSS_Success) {
		pio->rspDataLen = pio->LE;
		return sendRsp(gpgHandle);
	} else {
		return sendError(gpgHandle, SW_CONDITIONS_NOT_SATISFIED);
	}

}
