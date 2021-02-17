/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_api.h>
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

sw_enum_t gpg_get_ptc(uint32_t pinID, uint8_t *ptc, uint8_t *maxptc) {
	pw_status_bytes_t pw_sb;
	size_t sz = sizeof(pw_sb);
	CHECK_TRAP(SW_SUCCESS, se_read_do(0x00C4, (uint8_t*) &pw_sb, &sz));
	if (ptc != NULL) {
		switch(pinID) {
		case OBJ_ID_PW1:
			*ptc = pw_sb.pw1_ptc;
			break;
		case OBJ_ID_PW3:
			*ptc = pw_sb.pw3_ptc;
			break;
		case OBJ_ID_RC:
			*ptc = pw_sb.rc_ptc;
			break;
		default:
			ERROR_TRAP();
		}
	}

	if (maxptc != NULL) {
		switch(pinID) {
		case OBJ_ID_PW1:
		case OBJ_ID_PW3:
		case OBJ_ID_RC:
			*maxptc = PINMAXATTEMPTS;
			break;
		default:
			ERROR_TRAP();
		}
	}
	return SW_SUCCESS;

}

void gpg_reset_ptc(uint32_t pinID) {
	pw_status_bytes_t pw_sb;
	size_t sz = sizeof(pw_sb);
	CHECK_TRAP(SW_SUCCESS, se_read_do(0x00C4, (uint8_t*) &pw_sb, &sz));
	switch(pinID) {
	case OBJ_ID_PW1:
		pw_sb.pw1_ptc = PINMAXATTEMPTS;
		break;
	case OBJ_ID_PW3:
		pw_sb.pw3_ptc = PINMAXATTEMPTS;
		break;
	case OBJ_ID_RC:
		pw_sb.rc_ptc = PINMAXATTEMPTS;
		break;
	default:
		ERROR_TRAP();
	}
	CHECK_TRAP(SW_SUCCESS, se_write_do(0x00C4, (uint8_t*) &pw_sb, sizeof(pw_sb)));
}

static uint8_t _gpg_dec_ptc(uint32_t pinID) {
	pw_status_bytes_t pw_sb;
	size_t sz = sizeof(pw_sb);
	CHECK_TRAP(SW_SUCCESS, se_read_do(0x00C4, (uint8_t*) &pw_sb, &sz));
	uint8_t ptc = 0;

	switch(pinID) {
	case OBJ_ID_PW1:
		if(pw_sb.pw1_ptc != 0) {
			pw_sb.pw1_ptc--;
		}
		ptc = pw_sb.pw1_ptc;
		break;
	case OBJ_ID_PW3:
		if(pw_sb.pw3_ptc != 0) {
			pw_sb.pw3_ptc--;
		}
		ptc =  pw_sb.pw3_ptc;
		break;
	case OBJ_ID_RC:
		if(pw_sb.rc_ptc != 0) {
			pw_sb.rc_ptc--;
		}
		ptc = pw_sb.rc_ptc;
		break;
	default:
		ERROR_TRAP();
	}

	CHECK_TRAP(SW_SUCCESS, se_write_do(0x00C4, (uint8_t*) &pw_sb, sizeof(pw_sb)));
	return ptc;
}

uint8_t gpg_verify_pin(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	sw_enum_t status;
	object_id_t pinId;
	uint8_t pinFlag;
	uint8_t ptc;

	// LC is checked in se_open_session

	if(pio->LE != 0x0000) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	switch (pio->P2) {
	case 0x81:
		pinFlag = PW1_81_ACTIVE;
		pinId = OBJ_ID_PW1;
		break;
	case 0x82:
		pinFlag = PW1_82_ACTIVE;
		pinId = OBJ_ID_PW1;
		break;
	case 0x83:
		pinFlag = PW3_ACTIVE;
		pinId = OBJ_ID_PW3;
		break;
	default:
		return sendError(gpgHandle, SW_WRONG_P1P2);
	}

	switch (pio->P1) {
	case 0x00: //Verify PIN
		status = gpg_get_ptc(pinId, &ptc, NULL);
		if (status != SW_SUCCESS) {
			LOG_W("Cant read PTC");
			return sendError(gpgHandle, status);
		}
		if (ptc == 0) {
			return sendError(gpgHandle, SW_PIN_BLOCKED);
		}
		if (pio->LC == 0) {
			return sendError(gpgHandle, 0x63C0 | (ptc & 0x0f));
		} else {
			if (SW_SUCCESS != se_open_session(pinId, &pio->cmdData[0], pio->LC)) {
				gpgHandle->activePin &= !pinFlag;
				ptc = _gpg_dec_ptc(pinId);
				return sendError(gpgHandle, 0x63C0 | (ptc & 0x0f));
			}
			if(ptc != PINMAXATTEMPTS) {
				gpg_reset_ptc(pinId);
			}
			gpgHandle->activePin |= pinFlag;
			return sendRsp(gpgHandle);
		}
		break;
	case 0xFF: //reset PIN
		gpgHandle->activePin &= !pinFlag;
		/* Close session if PW3 disabled or both PW1_81 et PW1_82 disabled */
		if ((pinFlag == PW3_ACTIVE)
				|| ((gpgHandle->activePin & (PW1_81_ACTIVE | PW1_82_ACTIVE)) == 0)) {
			se_close_session(pinId);
		}
		return sendRsp(gpgHandle);
		break;
	default:
		return sendError(gpgHandle, SW_WRONG_P1P2);
	}
}

uint8_t gpg_change_reference_data(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	sw_enum_t status;
	object_id_t pinId;
	uint8_t *oldpinValue;
	size_t oldpinLen;
	uint8_t *newpinValue;
	size_t newpinLen;
	uint8_t *lockpinValue;
	size_t lockpinLen;
	uint8_t ptc;

	if (pio->P1 != 0) {
		return sendError(gpgHandle, SW_WRONG_P1P2);
	}

	switch (pio->P2) {
	case 0x81:
		pinId = OBJ_ID_PW1;
		if(pio->LC != 12U) {
			return sendError(gpgHandle, SW_WRONG_LENGTH);
		}
		break;
	case 0x83:
		pinId = OBJ_ID_PW3;
		if(pio->LC != 16U) {
			return sendError(gpgHandle, SW_WRONG_LENGTH);
		}
		break;
	default:
		return sendError(gpgHandle, SW_WRONG_P1P2);
	}

	if(pio->LC != 0x0006 || pio->LC != 0x0)

	if(pio->LE != 0x0000){
	 return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	oldpinValue = &pio->cmdData[0];
	oldpinLen = pio->LC / 2;
	newpinValue = &pio->cmdData[pio->LC / 2];
	newpinLen = pio->LC / 2;
	lockpinValue = &pio->cmdData[pio->LC / 2];
	lockpinLen = pio->LC / 2;

	status = gpg_get_ptc(pinId, &ptc, NULL);
	if (status != SW_SUCCESS) {
		LOG_W("Cant read PTC");
		return sendError(gpgHandle, status);
	}
	if (ptc == 0) {
		return sendError(gpgHandle, SW_PIN_BLOCKED);
	}

	se_close_all_sessions();
	if (SW_SUCCESS != se_open_session(pinId, oldpinValue, oldpinLen)) {
		ptc = _gpg_dec_ptc(pinId);
		return sendError(gpgHandle, 0x63C0 | (ptc & 0x0f));
	}
	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_NA,
			kSE05x_LockState_LOCKED));
	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen,
			kSE05x_LockIndicator_TRANSIENT_LOCK, kSE05x_LockState_NA));

	if (SW_SUCCESS != se_set_pin(pinId, newpinValue, newpinLen)) {
		LOG_E("Can't write pin object");
		ERROR_TRAP();
	}
	LOG_I("PIN changed");

	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_NA,
			kSE05x_LockState_NA));
	gpg_get_ptc(pinId, &ptc, NULL);
	if(ptc != PINMAXATTEMPTS) {
		gpg_reset_ptc(pinId);
	}
	return sendRsp(gpgHandle);
}

uint8_t gpg_reset_retry_counter(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	sw_enum_t status;
	object_id_t pinID;
	uint8_t *oldpinValue;
	size_t oldpinLen;
	uint8_t *newpinValue;
	size_t newpinLen;
	uint8_t *lockpinValue;
	size_t lockpinLen;
	uint8_t ptc;

	switch (pio->P1) {
	case 0x00:
		if(pio->LC != 14U) {
			sendError(gpgHandle, SW_WRONG_LENGTH);
		}
		break;
	case 0x02:
		if(pio->LC != 6U) {
			sendError(gpgHandle, SW_WRONG_LENGTH);
		}
		break;
	default:
		return sendError(gpgHandle, SW_INCORRECT_P1P2);
		break;
	}

	if (pio->P2 != 0x81) {
		return sendError(gpgHandle, SW_INCORRECT_P1P2);
	}

	if(pio->LE != 0x0000) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	se_close_session(OBJ_ID_PW1);
	pinID = OBJ_ID_PW1;

	switch (pio->P1) {
	case 0x00:
		oldpinValue = &pio->cmdData[0];
		oldpinLen = 8;
		newpinValue = &pio->cmdData[8];
		newpinLen = pio->LC-8;
		lockpinValue = &pio->cmdData[8];
		lockpinLen = pio->LC-8;
		if (SW_SUCCESS != se_open_session(OBJ_ID_RC, oldpinValue, oldpinLen)) {
			ptc = _gpg_dec_ptc(OBJ_ID_RC);
			if(ptc == 0) {
				return sendError(gpgHandle, SW_PIN_BLOCKED);
			} else {
				return sendError(gpgHandle, 0x63C0 | (ptc & 0x0f));
			}
		}
		gpg_get_ptc(OBJ_ID_RC, &ptc, NULL);
		if(ptc != PINMAXATTEMPTS) {
			gpg_reset_ptc(OBJ_ID_RC);
		}
		break;
	case 0x02:
		newpinValue = &pio->cmdData[0];
		newpinLen = pio->LC;
		lockpinValue = &pio->cmdData[0];
		lockpinLen = pio->LC;
		if (kStatus_SSS_Success != se_switch_session(OBJ_ID_PW3)) {
			return sendError(gpgHandle, SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		break;
	default:
		ERROR_TRAP();
		break;
	}


	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_NA, kSE05x_LockState_LOCKED));
	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_TRANSIENT_LOCK, kSE05x_LockState_NA));

	CHECK_TRAP(SW_SUCCESS, se_set_pin(pinID, newpinValue, newpinLen));

	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_NA, kSE05x_LockState_NA));
	gpg_get_ptc(pinID, &ptc, NULL);
	if(ptc != PINMAXATTEMPTS) {
		gpg_reset_ptc(pinID);
	}
	LOG_I("PIN changed");
	return sendRsp(gpgHandle);
}

uint8_t gpg_resume_pin_change(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	sw_enum_t status;
	uint8_t *newpinValue;
	size_t newpinLen;
	uint8_t *lockpinValue;
	size_t lockpinLen;

	if (pio->P2 != 0x00 || pio->P1 != 0x00) {
		return sendError(gpgHandle, SW_INCORRECT_P1P2);
	}

	if(pio->LE != 0x0000) {
		sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	newpinValue = &pio->cmdData[0];
	newpinLen = pio->LC;
	lockpinValue = &pio->cmdData[0];
	lockpinLen = pio->LC;

	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen,
			kSE05x_LockIndicator_TRANSIENT_LOCK, kSE05x_LockState_NA));

	if (SW_SUCCESS != se_set_pin(OBJ_ID_PW1, newpinValue, newpinLen)) {
		LOG_I("PW1 does not need to be restored");
	} else {
		gpg_reset_ptc(OBJ_ID_PW1);
		LOG_I("PW1 restored");
	}

	if (SW_SUCCESS != se_set_pin(OBJ_ID_PW3, newpinValue, newpinLen)) {
		LOG_I("PW3 does not need to be restored");
	} else {
		gpg_reset_ptc(OBJ_ID_PW3);
		LOG_I("PW3 restored");
	}

	CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_NA,
			kSE05x_LockState_NA));

	return sendRsp(gpgHandle);
}
