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

#include "gpg_types.h"
#include "gpg_config.h"
#include "gpg_util.h"
#include "gpg_se_if.h"

static uint16_t current_do_tag = 0;
static uint8_t current_do_occurrence = 0;

uint8_t gpg_select_data(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t tag;
	size_t len;

	if((pio->P1 > 0x02U) || (pio->P2 != 0x04)) {
		return sendError(gpgHandle, SW_WRONG_P1P2);
	}

	io_fetch_tl(gpgHandle, &tag, &len);
	CHECK_TAG(tag, 0x0060);
	io_fetch_tl(gpgHandle, &tag, &len);
	CHECK_TAG(tag, 0x005C);

	switch(len) {
	case 0x01:
		current_do_tag = io_fetch_u8(gpgHandle);
		break;
	case 0x02:
		current_do_tag = io_fetch_u16(gpgHandle);
		break;
	default:
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}
	CHECK_CMD_OFFSET(pio);
	current_do_occurrence = pio->P1;

	return sendRsp(gpgHandle);
}

uint8_t gpg_get_data(gpg_handle_struct_t *gpgHandle) {
	sw_enum_t status = SM_OK;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t tag = (pio->P1<<8) | pio->P2;
	uint8_t buffer[256] = {0};
	size_t idx;

	if(tag != current_do_tag) {
		current_do_tag = tag;
		current_do_occurrence = 0;
	}

	if(pio->LC != 0x0000) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	switch(tag){
	case 0x004F: //AID
		io_add_array(gpgHandle, AID, sizeof(AID));
		break;
	case 0x5F52: //Historical bytes
		io_add_array(gpgHandle, (uint8_t*) &historical_bytes, sizeof(historical_bytes));
		se_get_status_indicator(&pio->rspData[pio->rspDataLen++]);
		io_add_u16(gpgHandle, SW_SUCCESS);
		break;
	case 0x7F66: //Extended length information
		io_add_tlv(gpgHandle, 0x7F66, extended_length, sizeof(extended_length));
		break;
	case 0x005E: //Login Data
		io_add_varray_from_se(gpgHandle, 0x005E, EXT_CAP_DO_MAX_LEN);
		break;
	case 0x5F50: //URL
		io_add_varray_from_se(gpgHandle, 0x5F50, EXT_CAP_DO_MAX_LEN);
		break;
	case 0x0065: //Card holder related data
		//Name
		io_begin_constructed_field(gpgHandle, 0x5B);
		io_add_varray_from_se(gpgHandle, 0x5B, 39);
		io_end_constructed_field(gpgHandle);
		//Language
		io_begin_constructed_field(gpgHandle, 0x5F2D);
		io_add_varray_from_se(gpgHandle, 0x5F2D, 8);
		io_end_constructed_field(gpgHandle);
		//Sex
		io_begin_constructed_field(gpgHandle, 0x5F35);
		io_add_varray_from_se(gpgHandle, 0x5F35, 1);
		io_end_constructed_field(gpgHandle);
		break;
	case 0x006E:
		io_add_tlv(gpgHandle, 0x004F, AID, sizeof(AID));
		io_add_tlv(gpgHandle, 0x5F52, (uint8_t*) &historical_bytes, sizeof(historical_bytes));
		io_add_tlv(gpgHandle, 0x7F66, extended_length, sizeof(extended_length));

		io_begin_constructed_field(gpgHandle, 0x0073);
		io_add_tlv(gpgHandle, 0x00C0, (uint8_t*) &extended_capabilities, sizeof(extended_capabilities));
		io_add_tlv(gpgHandle, 0x00C1, (uint8_t*) &sig_attributes, sizeof(sig_attributes));
		io_add_tlv(gpgHandle, 0x00C2, (uint8_t*) &dec_attributes, sizeof(dec_attributes));
		io_add_tlv(gpgHandle, 0x00C3, (uint8_t*) &auth_attributes, sizeof(auth_attributes));

		/* Read PTC */
		io_add_tl(gpgHandle, 0x00C4, sizeof(pw_status_bytes_t));
		io_add_array_from_se(gpgHandle, 0x00C4, sizeof(pw_status_bytes_t));

		io_add_tl(gpgHandle, 0x00C5, 60);
		io_add_array_from_se(gpgHandle, 0x00C7, 20);
		io_add_array_from_se(gpgHandle, 0x00C8, 20);
		io_add_array_from_se(gpgHandle, 0x00C9, 20);

		io_add_tl(gpgHandle, 0x00C6, 60);
		io_add_array_from_se(gpgHandle, 0x00CA, 20);
		io_add_array_from_se(gpgHandle, 0x00CB, 20);
		io_add_array_from_se(gpgHandle, 0x00CC, 20);

		io_add_tl(gpgHandle, 0x00CD, 12);
		io_add_array_from_se(gpgHandle, 0x00CE, 4);
		io_add_array_from_se(gpgHandle, 0x00CF, 4);
		io_add_array_from_se(gpgHandle, 0x00D0, 4);

		io_add_tl(gpgHandle, 0x00DE, 6);
		buffer[0] = 1;
		se_get_origin(OBJ_ID_SIG_KEY, &buffer[1]);
		buffer[2] = 2;
		se_get_origin(OBJ_ID_ENC_KEY, &buffer[3]);
		buffer[4] = 3;
		se_get_origin(OBJ_IDAUTH_KEY, &buffer[5]);
		io_add_array(gpgHandle, &buffer[0], 6);
		io_end_constructed_field(gpgHandle);
		break;
	case 0x007A:
		io_add_tl(gpgHandle, 0x0093, 3);
		idx = 3; se_read_cnt(0x0093, &buffer[0], &idx);
		io_add_array(gpgHandle, &buffer[0], 3);
		break;
	case 0x7F21:
		switch(current_do_occurrence) {
		case 0x00:
			io_add_varray_from_se(gpgHandle, 0x7F21, 39);
			break;
		case 0x01:
			io_add_varray_from_se(gpgHandle, 0x7F22, 39);
			break;
		case 0x02:
			io_add_varray_from_se(gpgHandle, 0x7F23, 39);
			break;
		default:
			return sendError(gpgHandle, SW_RECORD_NOT_FOUND);
		}
		break;
	case 0x00C4:
		io_add_array_from_se(gpgHandle, 0x00C4, sizeof(pw_status_bytes_t));
		break;
	case 0x00DE:
		buffer[0] = 1;
		CHECK_TRAP(SW_SUCCESS, se_get_origin(OBJ_ID_SIG_KEY, &buffer[1]));
		buffer[2] = 2;
		CHECK_TRAP(SW_SUCCESS, se_get_origin(OBJ_ID_ENC_KEY, &buffer[3]));
		buffer[4] = 3;
		CHECK_TRAP(SW_SUCCESS, se_get_origin(OBJ_IDAUTH_KEY, &buffer[5]));
		io_add_array(gpgHandle, &buffer[0], 6);
		break;
	default:
		sendError(gpgHandle, SW_REFERENCED_DATA_NOT_FOUND);
		return 0x20;
		break;
	}
	if(status != SW_SUCCESS) {
		sendError(gpgHandle, status);
		return 0x20;
	} else {
		sendRsp(gpgHandle);
		return 0x10;
	}
}

uint8_t gpg_get_next_data(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t tag = (pio->P1<<8) | pio->P2;

	if(pio->LC != 0x0000) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}
	if((tag != 0x7F21) || current_do_tag != 0x7F21) {
		return sendError(gpgHandle, SW_CONDITIONS_NOT_SATISFIED);
	}
	if(current_do_occurrence > 2) {
		return sendError(gpgHandle, SW_RECORD_NOT_FOUND);
	}
	current_do_occurrence++;
	return gpg_get_data(gpgHandle);
}

uint8_t gpg_put_data_a(gpg_handle_struct_t *gpgHandle) {
	sw_enum_t status = SW_UNKOWN;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t tag = (pio->P1<<8) | pio->P2;
	uint8_t *newpinValue;
	size_t newpinLen;
	uint8_t *lockpinValue;
	size_t lockpinLen;
	uint8_t ptc;
	pw_status_bytes_t pw_sb;
	size_t pw_sb_len = sizeof(pw_status_bytes_t);

	if (kStatus_SSS_Success != se_switch_session(OBJ_ID_PW3)) {
		return sendError(gpgHandle, SW_SECURITY_STATUS_NOT_SATISFIED);
	}

	switch(tag)
	{
	case 0xC4:
		CHECK_RETURN_SW(se_read_do(0x00C4, (uint8_t*) &pw_sb, &pw_sb_len));
		if(pio->LC == 0x01) {
			pw_sb.pw1_validity = io_fetch_u8(gpgHandle);
			if(pw_sb.pw1_validity > 1U) {
				sendError(gpgHandle, SW_WRONG_DATA);
			}
		} else {
			sendError(gpgHandle, SW_WRONG_LENGTH);
		}
		CHECK_RETURN_SW(se_write_do(0x00C4, (uint8_t*) &pw_sb, sizeof(pw_status_bytes_t)));
		break;
	case 0xD3:
		newpinValue = &pio->cmdData[0];
		newpinLen = pio->LC;
		lockpinValue = &pio->cmdData[0];
		lockpinLen = pio->LC;

		CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_NA, kSE05x_LockState_LOCKED));
		CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_TRANSIENT_LOCK, kSE05x_LockState_NA));

		CHECK_TRAP(SW_SUCCESS, se_set_pin(OBJ_ID_RC, newpinValue, newpinLen));
		LOG_I("PIN changed");

		CHECK_RETURN_SW(se_set_lockstate(lockpinValue, lockpinLen, kSE05x_LockIndicator_NA, kSE05x_LockState_NA));
		gpg_get_ptc(OBJ_ID_RC, &ptc, NULL);
		if(ptc != PINMAXATTEMPTS) {
			gpg_reset_ptc(OBJ_ID_RC);
		}
		break;
	default:
		CHECK_RETURN_SW(se_write_do(tag, pio->cmdData, pio->LC));
		break;
	}

	return sendRsp(gpgHandle);
}

uint8_t gpg_put_data_b(gpg_handle_struct_t *gpgHandle) {
	sw_enum_t status = SW_UNKOWN;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t tag = (pio->P1<<8) | pio->P2;
	key_struct_t key;
	sss_policy_t policy;

	se_switch_session(OBJ_ID_PW3); //Writing requires verification of PW3

	if(tag != 0x3FFF) {
		return sendError(gpgHandle, SW_WRONG_P1P2);
	}

	CHECK_RETURN_SW(parse_extended_header_list(gpgHandle, &key));

	policy = policy_asymmkey;
	CHECK_RETURN_SW(se_import_rsa_key_pair(key. id, &key, &policy));

	if(key.id == OBJ_ID_SIG_KEY) {
		policy = policy_do_cnt;
		se_create_cnt(0x0093, &policy, 3);
	}

	return sendRsp(gpgHandle);
}



