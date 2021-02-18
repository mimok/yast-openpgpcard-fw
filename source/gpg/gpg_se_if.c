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
#include <se05x_tlv.h>
#include <fsl_sss_se05x_policy.h>

#include "sm_timer.h"
#include "ksdk_mbedtls.h"
#include "mbedtls/sha256.h"


#ifdef __cplusplus
}
#endif

#include "gpg_config.h"
#include "gpg_types.h"
#include "gpg_se_if.h"
#include "gpg_util.h"

#define ID(t) (0x50000000 | (t))

static se_sessions_t se_sessions;
static sss_se05x_session_t session;

#define PSESSION ((sss_se05x_session_t*)&session)
#define PSESSION_CTX ((pSe05xSession_t)&(PSESSION->s_ctx))


#include "PlugAndTrust_Pkg_Ver.h"
#include "string.h" /* memset */

sss_status_t se_init_context() {
	sss_status_t status;
	SE_Connect_Ctx_t ConnectCtx = {0};
    ConnectCtx.connType = kType_SE_Conn_Type_T1oI2C;
    ConnectCtx.portName = NULL;

	CRYPTO_InitHardware();
	sm_initSleep();

	LOG_I(PLUGANDTRUST_PROD_NAME_VER_FULL);

	memset((PSESSION), 0, sizeof(*(PSESSION)));

	status = sss_se05x_session_open(PSESSION,
			kType_SSS_SE_SE05x,
		    0,
			kSSS_ConnectionType_Plain,
		    &ConnectCtx);
    return status;
}

void se_close_context() {
#ifdef EX_SSS_BOOT_PCONTEXT
	ex_sss_session_close((EX_SSS_BOOT_PCONTEXT));
#endif
}

sw_enum_t se_get_remaining_memory(uint16_t *pfreeMem){
	smStatus_t status;
	status = Se05x_API_GetFreeMemory(PSESSION_CTX, kSE05x_MemoryType_PERSISTENT, pfreeMem);
	return status;
}

sw_enum_t se_read_do(uint16_t tag, uint8_t *buff, size_t *buffLen) {
	sw_enum_t status = SW_UNKOWN;
	uint8_t lengthField[2] = { 0 };
	size_t lengthFieldLen = sizeof(lengthField);
	size_t length;

	LOG_I("Reading DO %X", tag);

	/* Read length of stored data */
	CHECK_RETURN(SM_OK,
			Se05x_API_ReadObject(PSESSION_CTX,
			ID(tag),
			0, 2,
			lengthField,
			&lengthFieldLen));

	/* Length checks */
	length = (lengthField[0] << 8) | lengthField[1];
	if (length == 0) {
		LOG_I("Empty DO");
		*buffLen = 0;
		return SW_SUCCESS;
	}
	if (*buffLen < length) {
		LOG_E("Too many data have to be read to fit in buff");
		ERROR_TRAP();
	}

	/* Read stored data */
	CHECK_TRAP(SM_OK,
			Se05x_API_ReadObject(PSESSION_CTX,
			ID(tag),
			2,
			length,
			buff,
			buffLen));

	LOG_I("Done");

	return status;
}

sw_enum_t se_write_do(uint16_t tag, uint8_t *buff, size_t buffLen) {
	smStatus_t status = SM_NOT_OK;
	SE05x_Result_t isDoExisting = kSE05x_Result_FAILURE;
	uint8_t lengthField[2];

	LOG_I("Write DO %X", tag);

	CHECK_TRAP(SM_OK,
			Se05x_API_CheckObjectExists(PSESSION_CTX,
			ID(tag),
			&isDoExisting));
	if (isDoExisting != kSE05x_Result_SUCCESS) {
		LOG_E("DO does not exist");
		return SW_FILE_NOT_FOUND;
	}

	lengthField[0] = (buffLen >> 8) & 0xFF;
	lengthField[1] = (buffLen) & 0xFF;

	CHECK_RETURN(SM_OK,
			Se05x_API_WriteBinary(PSESSION_CTX, NULL, ID(tag), 0, 0, lengthField, 2));

	CHECK_RETURN(SM_OK,
			Se05x_API_WriteBinary(PSESSION_CTX, NULL, ID(tag), 2, 0, buff, buffLen));

	LOG_I("Done");

	return status;
}

sw_enum_t se_create_do(uint16_t tag, sss_policy_t *policy, uint16_t maxLen, uint8_t *data, size_t dataLen) {
	smStatus_t status = SM_NOT_OK;
	Se05xPolicy_t policySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];
	const uint8_t DEFAULTVALUE[] = { 0x00, 0x00 };
	uint8_t buffer[MAX_APDU_LEN];

	SE05x_Result_t isDoExisting = kSE05x_Result_FAILURE;
	CHECK_TRAP(SM_OK,
			Se05x_API_CheckObjectExists(PSESSION_CTX, ID(tag), &isDoExisting));
	if (isDoExisting != kSE05x_Result_FAILURE) {
		LOG_E("Can't create DO because it already exists");
		return SW_CONDITIONS_NOT_SATISFIED;
	}

	if (policy == NULL) {
		LOG_E("Policy must be defined to create a DO");
		ERROR_TRAP();
	}
	CHECK_TRAP(kStatus_SSS_Success,
			sss_se05x_create_object_policy_buffer(policy,
					&policies_buff[0],
					&valid_policy_buff_len));
	policySet.value = policies_buff;
	policySet.value_len = valid_policy_buff_len;

	if(data != NULL && dataLen > 0) {
		if(dataLen > MAX_APDU_LEN){
			return SW_WRONG_LENGTH;
		}
		buffer[0] = (dataLen&0xFF00)>>8;
		buffer[1] = dataLen&0xFF;
		memcpy(&buffer[2], data, dataLen);
		status = Se05x_API_WriteBinary(PSESSION_CTX, &policySet, ID(tag), 0,
				maxLen + 2U, &buffer[0], dataLen + 2U);
	} else {
		status = Se05x_API_WriteBinary(PSESSION_CTX, &policySet, ID(tag), 0,
				maxLen + 2U, DEFAULTVALUE, sizeof(DEFAULTVALUE));
	}
	if (status != SM_OK) {
		LOG_E("Can't write empty DO");
		ERROR_TRAP();
	}

	return status;
}

sw_enum_t se_create_cnt(uint32_t tag, sss_policy_t *policy, size_t len) {
	smStatus_t status = SM_NOT_OK;
	Se05xPolicy_t policySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];
	SE05x_Result_t isCntExisting = kSE05x_Result_FAILURE;

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(PSESSION_CTX, ID(tag), &isCntExisting));
	if (isCntExisting == kSE05x_Result_SUCCESS) {
		status = Se05x_API_DeleteSecureObject(PSESSION_CTX, ID(tag));
		if (status != SM_OK) {
			LOG_W("Can't delete counter object");
			return (sw_enum_t) status;
		}
	}

	if (policy == NULL) {
		LOG_E("Policy must be defined to create a CNT");
		ERROR_TRAP();
	}
	CHECK_TRAP(kStatus_SSS_Success, sss_se05x_create_object_policy_buffer(policy, &policies_buff[0],
					&valid_policy_buff_len));
	policySet.value = policies_buff;
	policySet.value_len = valid_policy_buff_len;

	CHECK_TRAP(SM_OK, Se05x_API_CreateCounter(PSESSION_CTX, &policySet, ID(tag), len));

	return SW_SUCCESS;
}

sw_enum_t se_inc_cnt(uint32_t tag) {
	return (sw_enum_t) Se05x_API_SetCounterValue(PSESSION_CTX, ID(tag), 3, 0);
}

sw_enum_t se_read_cnt(uint32_t tag, uint8_t *buff, size_t* buffLen) {
	return (sw_enum_t) Se05x_API_ReadObject(PSESSION_CTX, ID(tag), 0, 0, buff, buffLen);
}

static sss_status_t check_pin_format(uint32_t pinID, size_t pinLen) {
	//PIN ID not valid
	if ((pinID != OBJ_ID_PW1) &&
		(pinID != OBJ_ID_PW3) &&
		(pinID != OBJ_ID_LOCKSTATE) &&
		(pinID != OBJ_ID_FACTORY_RESET) &&
		(pinID != OBJ_ID_RC)) {
		return kStatus_SSS_Fail;
	}

	//Wrong PIN length
	if ((pinID == OBJ_ID_PW1 && pinLen != 6) ||
			(pinID == OBJ_ID_PW3 && pinLen != 8) ||
			(pinID == OBJ_ID_RC && pinLen != 8)) {
		return kStatus_SSS_Fail;
	}

	return kStatus_SSS_Success;
}

sss_status_t se_switch_session(uint32_t pinID) {
	if(se_sessions.activeAuthObjId == pinID){
		return kStatus_SSS_Success;
	}
	for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
		if(pinID == se_sessions.objID[i]){
			PSESSION_CTX->hasSession = 1;
			se_sessions.activeAuthObjId = pinID;
			memcpy(PSESSION_CTX->value, se_sessions.sessionId[i], 8);
			return kStatus_SSS_Success;
		}
	}
	return kStatus_SSS_Fail;
}

sw_enum_t se_open_session(uint32_t pinID, uint8_t const *pinValue,
		uint8_t pinLen) {
	smStatus_t status = SW_UNKOWN;
	size_t sessionIdLen = 8;

	LOG_I("Trying to open session %X", pinID);

	if (kStatus_SSS_Success != check_pin_format(pinID, pinLen)) {
		return SW_WRONG_DATA;
	}

	/* Close already open session with same PIN */
	se_close_session(pinID);

	if(se_sessions.nbActiveSessions >= MAX_ACTIVE_SESSIONS) {
		LOG_E("Trying to open toot many sessions");
		ERROR_TRAP();
	}

	PSESSION_CTX->hasSession = 0;
	CHECK_RETURN(SM_OK, Se05x_API_CreateSession(
			PSESSION_CTX,
			pinID,
			PSESSION_CTX->value,
			&sessionIdLen));

	PSESSION_CTX->hasSession = 1;
	status = Se05x_API_VerifySessionUserID(PSESSION_CTX, pinValue, pinLen);
	if (status != SM_OK) {
		LOG_W("Cant verify userID");
		PSESSION_CTX->hasSession = 0;
		return (sw_enum_t) status;
	}
	for(uint8_t i = 0; i<MAX_ACTIVE_SESSIONS; i++) {
		if(se_sessions.objID[i] == 0){
			se_sessions.activeAuthObjId = pinID;
			se_sessions.objID[i] = pinID;
			memcpy(se_sessions.sessionId[i], PSESSION_CTX->value, 8);
			se_sessions.nbActiveSessions++;
			LOG_I("Done");
			return SW_SUCCESS;
		}
	}
	/* Should not reach this line */
	ERROR_TRAP();
	return SW_UNKOWN;
}

void se_close_current_session() {
	if(PSESSION_CTX->hasSession == 1) {
		for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
			if(se_sessions.activeAuthObjId == se_sessions.objID[i]){
				Se05x_API_CloseSession(PSESSION_CTX);
				PSESSION_CTX->hasSession = 0;
				se_sessions.activeAuthObjId = 0;
				se_sessions.objID[i] = 0;
				memset(&se_sessions.sessionId[i], 0, 8);
				se_sessions.nbActiveSessions--;
			}
		}
	}
}

void se_close_session(uint32_t pinID) {
	for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
		if(pinID == se_sessions.objID[i]){
			PSESSION_CTX->hasSession = 1;
			memcpy(PSESSION_CTX->value, se_sessions.sessionId[i], 8);
			Se05x_API_CloseSession(PSESSION_CTX);
			PSESSION_CTX->hasSession = 0;
			se_sessions.objID[i] = 0;
			memset(&se_sessions.sessionId[i], 0, 8);
			if(pinID == se_sessions.activeAuthObjId) {
				se_sessions.activeAuthObjId = 0;
			}
			se_sessions.nbActiveSessions--;
		}
	}
}

void se_close_all_sessions() {
	for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
		PSESSION_CTX->hasSession = 1;
		memcpy(PSESSION_CTX->value, se_sessions.sessionId[i], 8);
		Se05x_API_CloseSession(PSESSION_CTX);
		PSESSION_CTX->hasSession = 0;
		se_sessions.objID[i] = 0;
		memset(&se_sessions.sessionId[i], 0, 8);
	}
	se_sessions.activeAuthObjId = 0;
	se_sessions.nbActiveSessions = 0;
}

sw_enum_t se_set_lockstate(uint8_t const *pinValue, size_t pinLen, SE05x_LockIndicator_t lockindicator, SE05x_LockState_t lockstate) {
	smStatus_t status;
	SE05x_Result_t exists;

	LOG_I("Changing lockstate %X %X", lockindicator, lockstate);

	if(pinLen != 6U && pinLen != 8U) {
		return SW_WRONG_DATA;
	}

	status = Se05x_API_CheckObjectExists(PSESSION_CTX, OBJ_ID_LOCKSTATE, &exists);
	if (status == SM_OK && exists != kSE05x_Result_SUCCESS) {
		LOG_I("Creating lockstate PIN");
		CHECK_TRAP(SM_OK, se_set_pin(OBJ_ID_LOCKSTATE, pinValue, pinLen));
	} else {
		LOG_I("SE probably locked");
	}

	uint8_t oldsessionId[8];
	uint8_t oldhasSession;
	uint32_t oldactiveAuthObjId;
	memcpy(oldsessionId, PSESSION_CTX->value, 8);
	oldhasSession = PSESSION_CTX->hasSession;
	oldactiveAuthObjId = se_sessions.activeAuthObjId;

	PSESSION_CTX->hasSession = 0;
	size_t sessionIdLen = 8;
	CHECK_TRAP(SM_OK, Se05x_API_CreateSession(
			PSESSION_CTX,
			OBJ_ID_LOCKSTATE,
			PSESSION_CTX->value,
			&sessionIdLen));

	PSESSION_CTX->hasSession = 1;
	status = Se05x_API_VerifySessionUserID(PSESSION_CTX, pinValue, pinLen);
	if (status != SM_OK) {
		LOG_E("Cant verify userID");
		return SW_SECURITY_STATUS_NOT_SATISFIED;
	}

	CHECK_TRAP(SM_OK, Se05x_API_SetLockState(PSESSION_CTX, lockindicator, lockstate));

	if((lockindicator == kSE05x_LockIndicator_NA) && (lockstate == kSE05x_LockState_NA)) {//unlock persistent
		CHECK_TRAP(SM_OK, Se05x_API_DeleteSecureObject(PSESSION_CTX, OBJ_ID_LOCKSTATE));
		memcpy(PSESSION_CTX->value, oldsessionId, 8);
		PSESSION_CTX->hasSession = oldhasSession;
		se_sessions.activeAuthObjId = oldactiveAuthObjId;
		LOG_I("Done");
		return SM_OK; //Session automatically closed after PIN delete
	}

	Se05x_API_CloseSession(PSESSION_CTX);
	memcpy(PSESSION_CTX->value, oldsessionId, 8);
	PSESSION_CTX->hasSession = oldhasSession;
	se_sessions.activeAuthObjId = oldactiveAuthObjId;
	LOG_I("Done");
	return SM_OK;
}

sw_enum_t se_set_pin(uint32_t pinID, uint8_t const *pinValue, size_t pinLen) {
	//PIN derived into an AES-128 key using hash
	smStatus_t status;
	SE05x_Result_t exists;
	uint8_t maxAttempts;
	sss_policy_t policy;
	Se05xPolicy_t policySet, *pPolicySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];

	LOG_I("Setting PIN %X", pinID);

	if (kStatus_SSS_Success != check_pin_format(pinID, pinLen)) {
		return SW_WRONG_DATA;
	}

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(PSESSION_CTX, pinID, &exists));
	if (exists == kSE05x_Result_SUCCESS) {
		LOG_I("Pin object already exists, deleting");
		status = Se05x_API_DeleteSecureObject(PSESSION_CTX, pinID);
		if (status != SM_OK) {
			LOG_E("Cant delete PIN");
			return (sw_enum_t) status;
		}
		if(se_sessions.activeAuthObjId == pinID) {
			PSESSION_CTX->hasSession = 0; //session automatically closed after PIN deletion
		}
	}

	LOG_I("Pin object does not exist, creating");
	maxAttempts = PINMAXATTEMPTS;
	switch (pinID) {
	case OBJ_ID_RC:
		policy = policy_PW3;
		break;
	case OBJ_ID_PW1:
		policy = policy_PW1;
		break;
	case OBJ_ID_PW3:
		policy = policy_PW3;
		break;
	case OBJ_ID_LOCKSTATE:
		policy = policy_LS;
		break;
	default:
		return SM_NOT_OK;
	}
	CHECK_TRAP(kStatus_SSS_Success,
			sss_se05x_create_object_policy_buffer(&policy,
					&policies_buff[0],
					&valid_policy_buff_len));
	policySet.value = policies_buff;
	policySet.value_len = valid_policy_buff_len;
	pPolicySet = &policySet;

	CHECK_TRAP(SM_OK,
			Se05x_API_WriteUserID(PSESSION_CTX,
					pPolicySet,
					maxAttempts,
					pinID,
					pinValue,
					pinLen,
					kSE05x_AttestationType_AUTH));

	LOG_I("Done");
	return SW_SUCCESS;
}

void se_get_status_indicator(uint8_t *status) {
	SE05x_Result_t exists;
	*status = 0x00;

	if (SM_OK
			!= Se05x_API_CheckObjectExists(PSESSION_CTX, OBJ_ID_FACTORY_RESET,
					&exists)) {
		LOG_I("Can't check if activated exists, card is probably locked");
		*status = 0xFF;
	}
	if (exists == kSE05x_Result_SUCCESS) {
		*status = 0x05;
	} else {
		*status = 0x03;
	}
}

sw_enum_t se_activate() {
	const uint8_t userId[] = { '1', '2', '3', '4', '5', '6' }; //DELETE_ALL_UserID_VALUE;

	LOG_I("Activating");

	CHECK_TRAP(SM_OK,
		Se05x_API_WriteUserID(PSESSION_CTX,
			NULL,
			0,
			OBJ_ID_FACTORY_RESET,
			userId,
			sizeof(userId),
			kSE05x_AttestationType_AUTH));

	LOG_I("Done");
	return SW_SUCCESS;
}

sw_enum_t se_terminate() {
	smStatus_t status;
	const uint8_t userId[] = { '1', '2', '3', '4', '5', '6' }; //DELETE_ALL_UserID_VALUE;

	LOG_I("Terminating card");

	/* Trying to create ID if previous activation failed */
	status = Se05x_API_WriteUserID(PSESSION_CTX,
	NULL, 0, OBJ_ID_FACTORY_RESET, userId, sizeof(userId),
			kSE05x_AttestationType_AUTH);
	if (status != SM_OK) {
		LOG_W("Can't create RESERVED_ID_FACTORY_RESET user ID");
	}

	CHECK_TRAP(SW_SUCCESS, se_open_session(OBJ_ID_FACTORY_RESET, userId, sizeof(userId)));
	CHECK_TRAP(SM_OK, Se05x_API_DeleteAll(PSESSION_CTX));

	LOG_I("Done");

	se_close_all_sessions();
	return SW_SUCCESS;
}

sss_status_t se_get_random(uint8_t *buff, uint16_t size) {
	sss_status_t status = kStatus_SSS_Fail;
	sss_se05x_rng_context_t rng_ctx;
	CHECK_RETURN(kStatus_SSS_Success, sss_se05x_rng_context_init(&rng_ctx, PSESSION));
	CHECK_RETURN(kStatus_SSS_Success, sss_se05x_rng_get_random(&rng_ctx, buff, size));
	return kStatus_SSS_Success;
}

sw_enum_t se_generate_rsa_key_pair(uint32_t keyId, size_t keylen,
		sss_policy_t *policy) {

	smStatus_t status = SW_UNKOWN;
	SE05x_Result_t exists;
	Se05xPolicy_t policySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];

	LOG_I("Generating RSA key pair %X", keyId);

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(PSESSION_CTX, keyId, &exists));
	if (exists == kSE05x_Result_SUCCESS) { //overwrite existing key
		LOG_I("Key object already exists");
		policySet.value = NULL;
		policySet.value_len = 0;
		keylen = 0;
	} else {
		CHECK_TRAP(kStatus_SSS_Success, sss_se05x_create_object_policy_buffer(
				policy,
				&policies_buff[0],
				&valid_policy_buff_len));
		policySet.value = policies_buff;
		policySet.value_len = valid_policy_buff_len;
	}


	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			&policySet,
			keyId,
			keylen,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	LOG_I("Done");
	return SW_SUCCESS;
}

sw_enum_t se_import_rsa_key_pair(uint32_t keyId, key_struct_t *key, sss_policy_t *policy) {

	smStatus_t status = SW_UNKOWN;
	SE05x_Result_t exists;
	uint16_t keylen = RSA_KEY_LEN;
	Se05xPolicy_t policySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(PSESSION_CTX, keyId, &exists));
	if (exists == kSE05x_Result_SUCCESS) { //overwrite existing key
		LOG_I("Key object already exists");
		policySet.value = NULL;
		policySet.value_len = 0;
		keylen = 0;
	} else {
		CHECK_TRAP(kStatus_SSS_Success, sss_se05x_create_object_policy_buffer(
				policy,
				&policies_buff[0],
				&valid_policy_buff_len));
		policySet.value = policies_buff;
		policySet.value_len = valid_policy_buff_len;
	}

	CHECK_TRAP(kStatus_SSS_Success,
			sss_se05x_create_object_policy_buffer(policy,
					&policies_buff[0],
					&valid_policy_buff_len));
	policySet.value = policies_buff;
	policySet.value_len = valid_policy_buff_len;


	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			&policySet,
			keyId,
			keylen,
			key->rsa.p.data, key->rsa.p.dataLen,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			NULL, 0, NULL, 0, NULL, 0,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			NULL,
			keyId,
			0,
			NULL, 0,
			key->rsa.q.data, key->rsa.q.dataLen,
			NULL, 0, NULL, 0, NULL, 0,
			NULL, 0, NULL, 0, NULL, 0,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			NULL,
			keyId,
			0,
			NULL, 0, NULL, 0,
			key->rsa.dp1.data, key->rsa.dp1.dataLen,
			NULL, 0, NULL, 0,
			NULL, 0, NULL, 0, NULL, 0,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			NULL,
			keyId,
			0,
			NULL, 0, NULL, 0, NULL, 0,
			key->rsa.dq1.data, key->rsa.dq1.dataLen,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			NULL,
			keyId,
			0,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			key->rsa.pq1.data, key->rsa.pq1.dataLen,
			NULL, 0, NULL, 0, NULL, 0,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			NULL,
			keyId,
			0,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			NULL, 0,
			key->rsa.e.data, key->rsa.e.dataLen,
			NULL, 0, NULL, 0,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			PSESSION_CTX,
			NULL,
			keyId,
			0,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			NULL, 0, NULL, 0, NULL, 0,
			key->rsa.n.data, key->rsa.n.dataLen,
			0,
			kSE05x_P1_KEY_PAIR,
			kSE05x_P2_DEFAULT));

	return SW_SUCCESS;
}

sw_enum_t se_read_rsa_pub_key(uint32_t keyId, uint8_t *modulus, size_t *modLen, uint8_t *exponent, size_t *expLen) {

	SE05x_Result_t exists;

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(PSESSION_CTX, keyId, &exists));
	if (exists != kSE05x_Result_SUCCESS) {
		LOG_W("Key object does not exist");
		return SW_FILE_NOT_FOUND;
	}

	CHECK_TRAP(SM_OK,
			Se05x_API_ReadRSA(PSESSION_CTX, keyId, 0, 0,
			kSE05x_RSAPubKeyComp_MOD, modulus, modLen));

	CHECK_TRAP(SM_OK, Se05x_API_ReadRSA(PSESSION_CTX, keyId, 0, 0,
			kSE05x_RSAPubKeyComp_PUB_EXP, exponent, expLen));

	return SW_SUCCESS;
}

sw_enum_t se_get_origin(uint32_t objectID, uint8_t *statusByte) {
	smStatus_t retStatus = SM_NOT_OK;
	tlvHeader_t hdr = { { kSE05x_CLA, kSE05x_INS_READ_With_Attestation,
			kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT } };
	uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
	size_t cmdbufLen = 0;
	uint8_t *pCmdbuf = &cmdbuf[0];
	int tlvRet = 0;
	uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
	uint8_t *pRspbuf = &rspbuf[0];
	size_t rspbufLen = ARRAY_SIZE(rspbuf);
	uint32_t attestID = 0xF0000012;
	uint8_t random[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	SE05x_AttestationAlgo_t attestAlgo = kSE05x_AttestationAlgo_EC_SHA_512;
	uint8_t attribute[128];
	size_t attributeLen = sizeof(attribute);

	SE05x_Result_t isDoExisting = kSE05x_Result_FAILURE;
	retStatus = Se05x_API_CheckObjectExists(PSESSION_CTX, objectID,
			&isDoExisting);
	if (retStatus != SM_OK) {
		LOG_W("Can't check if DO exists");
		return retStatus;
	}
	if (isDoExisting != kSE05x_Result_SUCCESS) {
		LOG_W("DO does not exist");
		*statusByte = 0x00;
		return retStatus;
	}

	tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1,
			objectID)
	;
	if (0 != tlvRet) {
		goto cleanup;
	}
	tlvRet = TLVSET_U32("attestID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5,
			attestID)
	;
	if (0 != tlvRet) {
		goto cleanup;
	}
	tlvRet =
			TLVSET_AttestationAlgo("attestAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_6, attestAlgo)
	;
	if (0 != tlvRet) {
		goto cleanup;
	}
	tlvRet = TLVSET_u8bufOptional("random", &pCmdbuf, &cmdbufLen, kSE05x_TAG_7,
			random, sizeof(random))
	;
	if (0 != tlvRet) {
		goto cleanup;
	}
	retStatus = DoAPDUTxRx_s_Case4(PSESSION_CTX, &hdr, cmdbuf, cmdbufLen, rspbuf,
			&rspbufLen);
	if (retStatus == SM_OK) {
		size_t rspIndex = 0;
		tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_2,
				attribute, &attributeLen); /*  */
		if (0 != tlvRet) {
			ERROR_TRAP();
		}
		if (attribute[attributeLen - 1] < 0x01
				|| attribute[attributeLen - 1] > 0x03) {
			ERROR_TRAP();
		}
		switch (attribute[attributeLen - 1]) {
		case ORIGIN_EXTERNAL:
			*statusByte = 0x02;
			break;
		case ORIGIN_INTERNAL:
			*statusByte = 0x01;
			break;
		default:
			ERROR_TRAP();
		}
	}
	cleanup: return (sw_enum_t)retStatus;

}

sw_enum_t se_rsa_decrypt(uint32_t keyId, uint8_t *cipher, size_t cipherLen,
		uint8_t *plain, size_t *plainLen) {

	LOG_I("RSA decrypt with %X", keyId);

	return Se05x_API_RSADecrypt(
		PSESSION_CTX,
		keyId,
		kSE05x_RSAEncryptionAlgo_NO_PAD,
		cipher, cipherLen,
		plain, plainLen);
}
