/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "gpg_types.h"
#include "gpg_config.h"
#include "gpg_dispatch.h"
#include "gpg_se_if.h"
#include "gpg_util.h"

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"
#include "usb_device_class.h"
#include "iccd.h"

void gpg_init(gpg_handle_struct_t *gpgHandle, usb_device_iccd_control_request_struct_t inoutBuffer) {
	CHECK_TRAP(kStatus_SSS_Success, se_init_context());
	gpgHandle->activePin = 0x00;
}

sw_enum_t gpg_parse_cmd(gpg_handle_struct_t *gpgHandle, uint8_t *buffIn,
		size_t buffInLen) {

	gpgHandle->io.cmdDataOffset = 0;
	gpgHandle->io.rspData = &buffIn[0];
	gpgHandle->io.rspDataLen = 0;

	if (buffInLen < 4) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}
	gpgHandle->io.CLA = buffIn[CLA_OFFSET];
	gpgHandle->io.INS = buffIn[INS_OFFSET];
	gpgHandle->io.P1 = buffIn[P1_OFFSET];
	gpgHandle->io.P2 = buffIn[P2_OFFSET];

	if (buffInLen == 4) {
		gpgHandle->io.LC = 0x0000U;
		gpgHandle->io.LE = 0x0000U;
		gpgHandle->io.cmdData = NULL;
		gpgHandle->io.isExtended = FALSE;
		return 0x40;
	}
	if (buffIn[LC_OFFSET] == 0x00U) { //Either LE = 0 (with or without extended length) or LC with extended length
		if (buffInLen == LC_OFFSET + 1) { //LC = 0 and LE = 0 short length
			gpgHandle->io.LC = 0x0000U;
			gpgHandle->io.LE = 0x0100U;
			gpgHandle->io.cmdData = NULL;
			gpgHandle->io.isExtended = FALSE;
		} else if (buffInLen == LC_OFFSET + 3) { //LC = 0 and LE = 0 with extended length
			gpgHandle->io.LC = 0x0000U;
			gpgHandle->io.LE = (buffIn[LC_OFFSET + 1] << 8)
					| buffIn[LC_OFFSET + 2];
			if (gpgHandle->io.LE == 0x0000) {
				gpgHandle->io.LE = MAX_RAPDU_LEN;
			}
			gpgHandle->io.cmdData = NULL;
			gpgHandle->io.isExtended = TRUE;
		} else if (buffInLen > LC_OFFSET + 3) { //LC with extended length
			gpgHandle->io.LC = (buffIn[LC_OFFSET + 1] << 8)
					| buffIn[LC_OFFSET + 2];
			gpgHandle->io.cmdData = &buffIn[LC_OFFSET + 3];
			if (buffInLen == (gpgHandle->io.LC + 7)) {
				gpgHandle->io.LE = 0;
			} else if (buffInLen == (gpgHandle->io.LC + 9)) {
				gpgHandle->io.LE = (buffIn[LC_OFFSET + 3 + gpgHandle->io.LC]
						<< 8) | buffIn[LC_OFFSET + 4 + gpgHandle->io.LC];
				if (gpgHandle->io.LE == 0x0000) {
					gpgHandle->io.LE = MAX_RAPDU_LEN;
				}
			} else {
				return sendError(gpgHandle, SW_WRONG_LENGTH);
			}
		} else {
			return sendError(gpgHandle, SW_WRONG_LENGTH);
		}
	} else { //LC != 0 short len and LE short len
		if (buffInLen == LC_OFFSET + 1) {
			gpgHandle->io.LC = 0;
			gpgHandle->io.LE = buffIn[LC_OFFSET];
			if (gpgHandle->io.LE == 0x0000) {
				gpgHandle->io.LE = 0x100U;
			}
			gpgHandle->io.isExtended = FALSE;
		} else {
			gpgHandle->io.LC = buffIn[LC_OFFSET];
			gpgHandle->io.cmdData = &buffIn[LC_OFFSET + 1];
			if (buffInLen == LC_OFFSET + 1 + gpgHandle->io.LC) {
				gpgHandle->io.LE = 0x0000;
			} else if (buffInLen == LC_OFFSET + 2 + gpgHandle->io.LC) {
				gpgHandle->io.LE = buffIn[LC_OFFSET + 1 + gpgHandle->io.LC];
				if (gpgHandle->io.LE == 0x0000)
					gpgHandle->io.LE = 0x0100U;
			} else {
				return sendError(gpgHandle, SW_WRONG_LENGTH);
			}
			gpgHandle->io.isExtended = FALSE;
		}
	}

	if (gpgHandle->io.LC > (MAX_APDU_LEN - 7)) { //cannot send an LC too long
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}
	return 0x40;
}

uint8_t gpg_dispatch(gpg_handle_struct_t *gpgHandle) {
	uint16_t freeMem;

	if (gpgHandle->io.CLA != 0x00U)
		return sendError(gpgHandle, SW_CLA_NOT_SUPPORTED);

	//Check statusIndictorByte
	uint8_t statusIndicatorByte = 0x00;

	se_get_status_indicator(&statusIndicatorByte);
	switch (statusIndicatorByte) {
	case 0x03: //card terminated
		switch (gpgHandle->io.INS) {
		case INS_ACTIVATE_FILE:
		case INS_TERMINATE_DF: //Allow card reseting if activation has failed.
			break;
		default:
			return sendError(gpgHandle, SW_INS_NOT_SUPPORTED);
		}
		break;
	case 0xFF: //card locked
		switch (gpgHandle->io.INS) {
		case INS_RESUME_PIN_CHANGE:
			return gpg_resume_pin_change(gpgHandle);
			break;
		default:
			return sendError(gpgHandle, SW_INS_NOT_SUPPORTED);
		}
		break;
	default:
		break;
	}

	switch (gpgHandle->io.INS) {
	case INS_SELECT:
		if (gpgHandle->io.LC > sizeof(AID))
			gpgHandle->io.LC = sizeof(AID);
		if (!memcmp(gpgHandle->io.cmdData, AID, gpgHandle->io.LC))
			return sendRsp(gpgHandle);
		else
			return sendError(gpgHandle, SW_APPLET_SELECT_FAILED);
		break;
	case INS_GET_CHALLENGE:
		return gpg_get_challenge(gpgHandle);
		break;
	case INS_ACTIVATE_FILE:
		return gpg_activate_file(gpgHandle);
		break;
	case INS_TERMINATE_DF:
		return gpg_terminate_df(gpgHandle);
		break;
	case INS_SELECT_DATA:
		return sendError(gpgHandle, SW_INS_NOT_SUPPORTED);
		break;
	case INS_GET_DATA:
		return gpg_get_data(gpgHandle);
		break;
	case INS_GET_NEXT_DATA:
		return sendError(gpgHandle, SW_INS_NOT_SUPPORTED);
		break;
	case INS_VERIFY:
		return gpg_verify_pin(gpgHandle);
		break;
	case INS_CHANGE_REFERENCE_DATA:
		return gpg_change_reference_data(gpgHandle);
		break;
	case INS_RESET_RETRY_COUNTER:
		return gpg_reset_retry_counter(gpgHandle);
		break;
	case INS_PUTDATA_A:
		return gpg_put_data_a(gpgHandle);
		break;
	case INS_PUTDATA_B:
		return gpg_put_data_b(gpgHandle);
		break;
	case INS_GENERATE_ASYMMETRIC_KEY_PAIR:
		return gpg_gen_key(gpgHandle);
		break;
	case INS_PSO:
		return gpg_pso(gpgHandle);
		break;
	case INS_INTERNAL_AUTHENTICATE:
		return gpg_internal_auth(gpgHandle);
		break;
	case INS_MANAGE_SECURITY_EVIRONMENT:
		return sendError(gpgHandle, SW_INS_NOT_SUPPORTED);
		break;
#ifdef DEBUG
	case INS_GET_REMAINING_MEMORY:
		se_get_remaining_memory(&freeMem);
		io_add_u16(gpgHandle, freeMem);
		return sendRsp(gpgHandle);
		break;
#endif
	default:
		return sendError(gpgHandle, SW_INS_NOT_SUPPORTED);
	}
}
