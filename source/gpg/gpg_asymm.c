/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "gpg_config.h"
#include "gpg_se_if.h"
#include "gpg_util.h"

static uint8_t _gpg_pso_cds(gpg_handle_struct_t *gpgHandle) {
	sss_status_t status;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint8_t *digestInfo = pio->cmdData;
	size_t digestInfoLen = pio->LC;
	uint8_t dsi[512];
	size_t dsiLen;
	uint8_t plain[512];
	size_t plainLen = sizeof(plain);
	pw_status_bytes_t pw_sb;
	size_t pw_sb_len = sizeof(pw_status_bytes_t);

	if ((gpgHandle->activePin & PW1_81_ACTIVE) == 0) {
		return sendError(gpgHandle, SW_SECURITY_STATUS_NOT_SATISFIED);
	}

	if (digestInfoLen > (size_t)(RSA_KEY_LEN/8*0.4f)) { //digestInfoLen cannot be greater than 40% of RSA_KEY_LEN
		return sendError(gpgHandle, SW_WRONG_DATA);
	}

	CHECK_RETURN_SW(se_read_do(0x00C4, (uint8_t*) &pw_sb, &pw_sb_len));

	dsiLen = 0;
	dsi[dsiLen++] = 0x00;
	dsi[dsiLen++] = 0x01; //CDS type
	while (dsiLen < (RSA_KEY_LEN / 8 - 1 - digestInfoLen)) {
		dsi[dsiLen++] = 0xFF;
	}
	dsi[dsiLen++] = 0x00;
	memcpy(&dsi[dsiLen], &digestInfo[0], digestInfoLen);
	dsiLen += digestInfoLen;

	status = se_rsa_decrypt(OBJ_ID_SIG_KEY, dsi, dsiLen, plain, &plainLen);
	if(pw_sb.pw1_validity == 0x00) {
		gpgHandle->activePin &= ~PW1_81_ACTIVE;
	}
	if (status == kStatus_SSS_Success) {
		memcpy(pio->rspData, plain, plainLen);
		pio->rspDataLen = plainLen;
		se_inc_cnt(0x0093);
		return sendRsp(gpgHandle);
	} else {
		return sendError(gpgHandle, SW_ERR_ACCESS_DENIED_BASED_ON_POLICY);
	}
}

static uint8_t _gpg_pso_dec(gpg_handle_struct_t *gpgHandle) {
	sss_status_t status;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint8_t paddingByte;
	uint8_t *cipher;
	size_t cipherLen;
	size_t idx;
	uint8_t plain[RSA_KEY_LEN/8];
	size_t plainLen = sizeof(plain);
	const uint32_t keyId = OBJ_ID_ENC_KEY;

	if ((gpgHandle->activePin & PW1_82_ACTIVE) == 0) {
		return sendError(gpgHandle, SW_SECURITY_STATUS_NOT_SATISFIED);
	}

	if (pio->LC != (RSA_KEY_LEN/8+1)) { //data length should match padding byte + modulus length
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	paddingByte = pio->cmdData[0];
	if(paddingByte != 0x00) { //must be RSA pading (0x00)
		return sendError(gpgHandle, SW_WRONG_DATA);
	}
	cipherLen = pio->LC-1;
	cipher = &pio->cmdData[1];

	status = se_rsa_decrypt(keyId, cipher, cipherLen, plain, &plainLen);
	if (status != kStatus_SSS_Success) {
		return sendError(gpgHandle, SW_SECURITY_STATUS_NOT_SATISFIED);
	}

	idx = 0;
	if(plain[idx++] != 0x00) return sendError(gpgHandle, SW_WRONG_DATA);
	if(plain[idx++] != 0x02) return sendError(gpgHandle, SW_WRONG_DATA); //wrong type
	for(;(plain[idx] != 0) && (idx < plainLen); idx++);
	if(idx < 10) return sendError(gpgHandle, SW_WRONG_DATA); //padding to short
	if(idx >= plainLen) return sendError(gpgHandle, SW_WRONG_DATA); //no message
	idx++; //now idx point to first byte of message
	memcpy(pio->rspData, &plain[idx], plainLen-idx);
	pio->rspDataLen = plainLen-idx;
	return sendRsp(gpgHandle);
}

uint8_t gpg_pso(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t P1P2 = (pio->P1 << 8) | pio->P2;

	se_switch_session(OBJ_ID_PW1);

	switch (P1P2) {
	case 0x9E9A: //PSO CDS
		return _gpg_pso_cds(gpgHandle);
		break;
	case 0x8086: //PSO DECIPHER
		return _gpg_pso_dec(gpgHandle);
		break;
	default:
		return sendError(gpgHandle, SW_INCORRECT_P1P2);
	}
}

uint8_t gpg_internal_auth(gpg_handle_struct_t *gpgHandle) {
	sss_status_t status;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint8_t *authenticationInput = pio->cmdData;
	size_t authenticationInputLen = pio->LC;
	uint8_t signature[512];
	size_t signatureLen;
	uint8_t plain[512];
	size_t plainLen = sizeof(plain);
	uint32_t keyId;

	se_switch_session(OBJ_ID_PW1);

	if (pio->P1 != 0x00 || pio->P2 != 0x00) {
		return sendError(gpgHandle, SW_INCORRECT_P1P2);
	}

	if (authenticationInputLen > (size_t)(RSA_KEY_LEN/8*0.4f)) { //authenticationInputLen cannot be greater than 40% of RSA_KEY_LEN
		return sendError(gpgHandle, SW_WRONG_DATA);
	}

	keyId = OBJ_IDAUTH_KEY;
	signatureLen = 0;
	signature[signatureLen++] = 0x00;
	signature[signatureLen++] = 0x01;
	while (signatureLen < (RSA_KEY_LEN / 8 - 1 - authenticationInputLen)) {
		signature[signatureLen++] = 0xFF;
	}
	signature[signatureLen++] = 0x00;
	memcpy(&signature[signatureLen], &authenticationInput[0],
			authenticationInputLen);
	signatureLen += authenticationInputLen;

	status = se_rsa_decrypt(keyId, signature, signatureLen, plain, &plainLen);
	if (status == kStatus_SSS_Success) {
		memcpy(pio->rspData, plain, plainLen);
		pio->rspDataLen = plainLen;
		return sendRsp(gpgHandle);
	} else {
		return sendError(gpgHandle, SW_ERR_ACCESS_DENIED_BASED_ON_POLICY);
	}
}

uint8_t gpg_gen_key(gpg_handle_struct_t *gpgHandle) {
	sw_enum_t status;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t P1P2 = (pio->P1 << 8) | pio->P2;
	uint16_t CRT = pio->cmdData[0] << 8 | pio->cmdData[1];
	uint32_t keyId;
	uint8_t modulus[RSA_KEY_LEN/8];
	size_t modLen = sizeof(modulus);
	uint8_t exponent[4];
	size_t expLen = sizeof(exponent);
	sss_policy_t policy;

	se_switch_session(OBJ_ID_PW3);

	if(pio->LC != 2U) {
		return sendError(gpgHandle, SW_WRONG_LENGTH);
	}

	switch (CRT) {
	case 0xB600:
		keyId = OBJ_ID_SIG_KEY;
		break;
	case 0xB800:
		keyId = OBJ_ID_ENC_KEY;
		break;
	case 0xA400:
		keyId = OBJ_IDAUTH_KEY;
		break;
	default:
		return sendError(gpgHandle, SW_WRONG_DATA);
	}

	switch (P1P2) {
	case 0x8000:
		policy = policy_asymmkey;
		status = se_generate_rsa_key_pair(keyId, RSA_KEY_LEN, &policy);
		if (status != SW_SUCCESS) {
			return sendError(gpgHandle, status);
		}
		if (CRT == 0xB600) {
			policy = policy_do_cnt;
			se_create_cnt(0x0093, &policy, 3);
		}
		status = se_read_rsa_pub_key(keyId, modulus, &modLen, exponent,
				&expLen);
		if (status != SW_SUCCESS) {
			return sendError(gpgHandle, status);
		}
		break;
	case 0x8100:
		status = se_read_rsa_pub_key(keyId, modulus, &modLen, exponent,
				&expLen);
		if (status != SW_SUCCESS) {
			return sendError(gpgHandle, status);
		}
		break;
	default:
		return sendError(gpgHandle, SW_WRONG_P1P2);
	}

	io_add_tl(gpgHandle, 0x7F49, (modLen + expLen + 6));
	io_add_tlv(gpgHandle, 0x0081, modulus, modLen);
	io_add_tlv(gpgHandle, 0x0082, exponent, expLen);
	return sendRsp(gpgHandle);

}

