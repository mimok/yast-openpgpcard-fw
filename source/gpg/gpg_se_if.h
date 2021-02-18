/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include <fsl_sss_api.h>
#include <fsl_sss_policy.h>
#include <gpg_types.h>
#include <se05x_enums.h>
#include <se05x_tlv.h>
#include <stddef.h>
#include <sys/_stdint.h>

#ifndef GPG_GPG_SE_IF_H_
#define GPG_GPG_SE_IF_H_

#define MAX_ACTIVE_SESSIONS 2
typedef struct _se_sessions_t{
	uint32_t activeAuthObjId;
	uint8_t nbActiveSessions;
	uint32_t objID[2];
	uint8_t sessionId[2][8];
} se_sessions_t;

extern const sss_policy_t policy_do_rw_never_pw3;
extern const sss_policy_t policy_do_rw_always_pw3;
extern const sss_policy_t policy_asymmkey;
extern const sss_policy_t policy_PW1;
extern const sss_policy_t policy_PW3;
extern const sss_policy_t policy_LS;
extern const sss_policy_t policy_do_cnt;
extern const sss_policy_t policy_nopolicy;

sss_status_t se_init_context();
void se_close_context();
sw_enum_t se_open_session(uint32_t pinID, uint8_t const *pinValue, uint8_t pinLen);
void se_close_all_sessions();
void se_close_session(uint32_t pinID);
void se_close_current_session() ;
sw_enum_t se_read_do(uint16_t tag, uint8_t *buff, size_t *buffLen);
sw_enum_t se_write_do(uint16_t tag, uint8_t *buff, size_t buffLen);
sw_enum_t se_create_do(uint16_t tag, sss_policy_t *policy, uint16_t maxLen, uint8_t *data, size_t dataLen);
sw_enum_t se_set_pin(uint32_t pinID, uint8_t const *pinValue, size_t pinLen);
sw_enum_t se_terminate();
sss_status_t se_get_random(uint8_t *buff, uint16_t size);
sw_enum_t se_generate_rsa_key_pair(uint32_t keyId, size_t keylen, sss_policy_t *policy);
sw_enum_t se_read_rsa_pub_key (uint32_t keyId, uint8_t *modulus, size_t *modLen, uint8_t *exponent, size_t *expLen);
sw_enum_t se_rsa_decrypt(uint32_t keyId, uint8_t *cipher, size_t cipherLen, uint8_t* plain, size_t *plainLen);
void se_get_status_indicator(uint8_t *status);
sw_enum_t se_activate();
sw_enum_t se_get_origin(uint32_t objectID, uint8_t *origin);
sw_enum_t se_set_lockstate(uint8_t const *pinValue, size_t pinLen, SE05x_LockIndicator_t lockindicator, SE05x_LockState_t lockstate);
sw_enum_t se_inc_cnt(uint32_t tag);
sss_status_t se_switch_session(uint32_t pinID);
sw_enum_t se_create_cnt(uint32_t tag, sss_policy_t *policy, size_t len);
sw_enum_t se_read_cnt(uint32_t tag, uint8_t *buff, size_t* buffLen);
sw_enum_t se_import_rsa_key_pair(uint32_t keyId, key_struct_t *key, sss_policy_t *policy);
#endif /* GPG_GPG_SE_IF_H_ */
