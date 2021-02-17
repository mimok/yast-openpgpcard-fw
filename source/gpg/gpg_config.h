/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "gpg_types.h"

#ifndef GPG_GPG_CONFIG_H_
#define GPG_GPG_CONFIG_H_

#define MAX_APDU_LEN 3072U
#define MAX_RAPDU_LEN MAX_APDU_LEN-2
#define EXT_CAP_CC_MAX_LEN 2560U
#define EXT_CAP_DO_MAX_LEN 255U
#define PINMAXATTEMPTS 3

#define SHORT(x) ((x)>>8)&0xFF, (x)&0xFF
#define SWAP16(x) (((x)<<8)&0xff00) | (((x)>>8)&0xff)
#define SWAP32(x) (((x)>>24)&0xff) | (((x)<<8)&0xff0000) | (((x)>>8)&0xff00) | (((x)<<24)&0xff000000)

typedef enum {
	OBJ_ID_SIG_KEY = 0x510000B6,
	OBJ_ID_ENC_KEY = 0x510000B8,
	OBJ_IDAUTH_KEY = 0x510000A4,
	OBJ_ID_PW1 = 0x51000082,
	OBJ_ID_RC = 0x5100008C,
	OBJ_ID_PW3 = 0x51000083,
	OBJ_PW_SB = 0x51000080,
	OBJ_ID_FACTORY_RESET = 0x7FFF0205,
	OBJ_ID_LOCKSTATE = 0x7FFF0200,
} object_id_t;

extern const uint8_t AID[16];
extern const uint8_t extended_length[8];
extern const size_t RSA_KEY_LEN;
extern const uint8_t DEFAULTPW1[6];
extern const uint8_t DEFAULTPW3[8];
extern const historical_bytes_t historical_bytes;
extern const extended_capabilities_t extended_capabilities;
extern const rsa_attributes_t sig_attributes;
extern const rsa_attributes_t dec_attributes;
extern const rsa_attributes_t auth_attributes;
extern const pw_status_bytes_t pw_status_bytes;

#endif /* GPG_GPG_CONFIG_H_ */
