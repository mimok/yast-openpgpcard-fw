/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "gpg_config.h"

const uint8_t AID[16] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};

const uint8_t extended_length[8] = {0x02, 0x02, SHORT(MAX_APDU_LEN), 0x02, 0x02, SHORT(MAX_APDU_LEN)};

const uint8_t DEFAULTPW1[6] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
const uint8_t DEFAULTPW3[8] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

const size_t RSA_KEY_LEN = 2048;

const historical_bytes_t historical_bytes = {
		.category_indicator = 0x00,
		.TL_card_capabilities = 0x73,
		.selection = 0x00,
		.coding = 0x00,
		.max_logical_channel = 0,
		.logical_channel_number = 0,
		.extended_length_info = 0,
		.extended_lc_le = 1,
		.command_chaining = 0,
		.TL_service_data = 0x31,
		.card_without_MF = 1,
		.DOs_access_services = 0,
		.DOs_available_EFATR_INFO = 0,
		.DOs_available_EFDIR = 0,
		.select_partial_DF = 1,
		.select_full_DF = 0,
};

const extended_capabilities_t extended_capabilities = {
		.KDF_DO_available = 0,
		.PSO_AES = 0,
		.alg_attr_changeable = 0,
		.privateDO_available = 0,
		.PWStatus_editable = 0,
		.Kimport_supported = 1,
		.GC_supported = 1,
		.SM_supported = 0,
		.sm_type = (sm_type_t) SM_NONE,
		.GC_max_len = SWAP16(MAX_RAPDU_LEN),
		.CC_max_len = SWAP16(EXT_CAP_CC_MAX_LEN),
		.DO_max_len = SWAP16(EXT_CAP_DO_MAX_LEN),
		.pinblock2_suported = 1,
		.MSE_cmd_key2_key3 = 0
};

const rsa_attributes_t sig_attributes = {
		.algorithm = 0x01,
		.m_size = SWAP16(RSA_KEY_LEN),
		.e_size = SWAP16(0x20),
		.pk_format = 0x03
};

const rsa_attributes_t dec_attributes = {
		.algorithm = 0x01,
		.m_size = SWAP16(RSA_KEY_LEN),
		.e_size = SWAP16(0x20),
		.pk_format = 0x03
};

const rsa_attributes_t auth_attributes = {
		.algorithm = 0x01,
		.m_size = SWAP16(RSA_KEY_LEN),
		.e_size = SWAP16(0x20),
		.pk_format = 0x03
};

const pw_status_bytes_t pw_status_bytes = {
		.pw1_validity = 0x01,
		.pw1_length = 0x06,
		.pw1_format = 0,
		.rc_length = 0x08,
		.pw3_length = 0x08,
		.pw3_format = 0,
		.pw1_ptc = PINMAXATTEMPTS,
		.rc_ptc = 0x00,
		.pw3_ptc = PINMAXATTEMPTS
};
