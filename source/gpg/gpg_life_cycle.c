/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>

#ifdef __cplusplus
}
#endif
#include "gpg_config.h"
#include "gpg_types.h"
#include "gpg_se_if.h"
#include "gpg_util.h"

uint8_t gpg_activate_file(gpg_handle_struct_t *gpgHandle) {
	smStatus_t status;
	sss_policy_t policy;
	uint8_t ZERO_256[256] = {0};
	uint8_t buff[8];
	uint8_t statusByte = 0;
	gpg_cmd_struct_t *pio = &gpgHandle->io;

	if(pio->P1 != 0x00 || pio->P2 != 0x00) {
		sendError(gpgHandle, SW_WRONG_P1P2);
	}
	if(pio->LC != 0x0000 || pio->LE != 0x0000) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	se_get_status_indicator(&statusByte);
	if(statusByte != 0x03) {
		sendError(gpgHandle, SW_COMMAND_NOT_ALLOWED);
	}

	/* Creating DOs*/
	policy = policy_do_rw_always_pw3; //copy needed because se_create will modify policy content
	se_create_do(0x005B, &policy, 39U, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x005E, &policy, EXT_CAP_DO_MAX_LEN, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x5F2D, &policy, 8U, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x5F35, &policy, 1U, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x5F50, &policy, EXT_CAP_DO_MAX_LEN, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x7F21, &policy, EXT_CAP_DO_MAX_LEN, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00C7, &policy, 20, &ZERO_256[0], 20);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00C8, &policy, 20, &ZERO_256[0], 20);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00C9, &policy, 20, &ZERO_256[0], 20);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00CA, &policy, 20, &ZERO_256[0], 20);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00CB, &policy, 20, &ZERO_256[0], 20);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00CC, &policy, 20, &ZERO_256[0], 20);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00CE, &policy, 4, &ZERO_256[0], 4);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00CF, &policy, 4, &ZERO_256[0], 4);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x00D0, &policy, 4, &ZERO_256[0], 4);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x7F21, &policy, EXT_CAP_CC_MAX_LEN, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x7F22, &policy, EXT_CAP_CC_MAX_LEN, NULL, 0);
	policy = policy_do_rw_always_pw3;
	se_create_do(0x7F23, &policy, EXT_CAP_CC_MAX_LEN, NULL, 0);
	policy = policy_do_cnt;
	se_create_cnt(0x0093, &policy, 3);

	status = se_set_pin(OBJ_ID_PW1, DEFAULTPW1, sizeof(DEFAULTPW1));
	if (status != SM_OK) {
		return sendError(gpgHandle, SW_CONDITIONS_NOT_SATISFIED);
	}

	status = se_set_pin(OBJ_ID_PW3, DEFAULTPW3, sizeof(DEFAULTPW3));
	if (status != SM_OK) {
		return sendError(gpgHandle, SW_CONDITIONS_NOT_SATISFIED);
	}

	se_get_random(buff, sizeof(buff));
	status = se_set_pin(OBJ_ID_RC, buff, sizeof(buff));
	if (status != SM_OK) {
		return sendError(gpgHandle, SW_CONDITIONS_NOT_SATISFIED);
	}

	policy = policy_nopolicy;
	se_create_do(0x00C4, &policy, (uint16_t) sizeof(pw_status_bytes_t), (uint8_t*) &pw_status_bytes, sizeof(pw_status_bytes_t));

	status = se_activate();
	if (status != SM_OK) {
		return sendError(gpgHandle, SW_UNKOWN);
	}
	return sendRsp(gpgHandle);
}

uint8_t gpg_terminate_df(gpg_handle_struct_t *gpgHandle) {
	smStatus_t status;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	if(pio->P1 != 0x00 || pio->P2 != 0x00) {
		sendError(gpgHandle, SW_WRONG_P1P2);
	}
	if(pio->LC != 0x0000 || pio->LE != 0x0000) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	se_close_all_sessions();
	status = se_terminate();
	if (status != SM_OK) {
		return sendError(gpgHandle, SW_CONDITIONS_NOT_SATISFIED);
	}
	return sendRsp(gpgHandle);
}
