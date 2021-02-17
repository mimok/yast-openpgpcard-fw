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
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <fsl_sss_se05x_policy.h>

#include "sm_timer.h"
#include "ax_reset.h"

#if (SSS_HAVE_MBEDTLS)
#include "ksdk_mbedtls.h"
#include "mbedtls/sha256.h"
#endif

#ifdef __cplusplus
}
#endif

#include "gpg_config.h"
#include "gpg_types.h"
#include "gpg_se_if.h"
#include "gpg_util.h"

#define ID(t) (0x50000000 | (t))

static ex_sss_boot_ctx_t gex_sss_boot_ctx;
static se_sessions_t se_sessions;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)

#include "PlugAndTrust_Pkg_Ver.h"
#include "string.h" /* memset */

#ifdef EX_SSS_BOOT_PCONTEXT
#define PCONTEXT EX_SSS_BOOT_PCONTEXT
#else
#define PCONTEXT (NULL)
#endif

#if !defined(EX_SSS_BOOT_OPEN_HOST_SESSION)
#define EX_SSS_BOOT_OPEN_HOST_SESSION 1
#endif

sss_status_t se_init_context() {
	const char *portName;
	sss_status_t status;

#if (SSS_HAVE_MBEDTLS)
	CRYPTO_InitHardware();
#if defined(FSL_FEATURE_SOC_SHA_COUNT) && (FSL_FEATURE_SOC_SHA_COUNT > 0)
	    CLOCK_EnableClock(kCLOCK_Sha0);
	    RESET_PeripheralReset(kSHA_RST_SHIFT_RSTn);
	#endif /* SHA */
#endif /* defined(MBEDTLS) */
#ifdef USE_SERGER_RTT
	    nInit_segger_Log();
	#endif

	sm_initSleep();

	LOG_I(PLUGANDTRUST_PROD_NAME_VER_FULL);

#ifdef EX_SSS_BOOT_PCONTEXT
	memset((EX_SSS_BOOT_PCONTEXT), 0, sizeof(*(EX_SSS_BOOT_PCONTEXT)));
#endif

	status = ex_sss_boot_connectstring(0, NULL, &portName);
	if (kStatus_SSS_Success != status) {
		LOG_E("ex_sss_boot_connectstring Failed");
		goto cleanup;
	}

#if defined(EX_SSS_BOOT_SKIP_SELECT_APPLET) && \
        (EX_SSS_BOOT_SKIP_SELECT_APPLET == 1)
        (PCONTEXT)->se05x_open_ctx.skip_select_applet = 1;
    #endif

#if !defined(EX_SSS_BOOT_RTOS_STACK_SIZE)
#define EX_SSS_BOOT_RTOS_STACK_SIZE 8500
#endif

	status = ex_sss_boot_open(PCONTEXT, portName);
	if (kStatus_SSS_Success != status) {
		LOG_E("ex_sss_session_open Failed");
		goto cleanup;
	}

	if (kType_SSS_SubSystem_NONE == ((PCONTEXT)->session.subsystem)) {
		/* Nothing to do. Device is not opened
		 * This is needed for the case when we open a generic communication
		 * channel, without being specific to SE05X
		 */
	} else {
		status = ex_sss_kestore_and_object_init((PCONTEXT));
		if (kStatus_SSS_Success != status) {
			LOG_E("ex_sss_kestore_and_object_init Failed");
			goto cleanup;
		}
	}

#if EX_SSS_BOOT_OPEN_HOST_SESSION
	ex_sss_boot_open_host_session((PCONTEXT));
#endif

	cleanup: return status;
}

void se_close_context() {
#ifdef EX_SSS_BOOT_PCONTEXT
	ex_sss_session_close((EX_SSS_BOOT_PCONTEXT));
#endif
}

sw_enum_t se_get_remaining_memory(uint16_t *pfreeMem){
	sss_se05x_session_t *psession = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t pSe05x_ctx = &psession->s_ctx;
	smStatus_t status;
	status = Se05x_API_GetFreeMemory(pSe05x_ctx, kSE05x_MemoryType_PERSISTENT, pfreeMem);
	return status;
}

sw_enum_t se_read_do(uint16_t tag, uint8_t *buff, size_t *buffLen) {
	sss_se05x_session_t *psession = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t pSe05x_ctx = &psession->s_ctx;
	sw_enum_t status = SW_UNKOWN;
	uint8_t lengthField[2] = { 0 };
	size_t lengthFieldLen = sizeof(lengthField);
	size_t length;

	LOG_I("Reading DO %X", tag);

	/* Read length of stored data */
	CHECK_RETURN(SM_OK,
			Se05x_API_ReadObject(pSe05x_ctx,
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
			Se05x_API_ReadObject(pSe05x_ctx,
			ID(tag),
			2,
			length,
			buff,
			buffLen));

	LOG_I("Done");

	return status;
}

sw_enum_t se_write_do(uint16_t tag, uint8_t *buff, size_t buffLen) {
	sss_se05x_session_t *psession = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t pSe05x_ctx = &psession->s_ctx;
	smStatus_t status = SM_NOT_OK;
	SE05x_Result_t isDoExisting = kSE05x_Result_FAILURE;
	uint8_t lengthField[2];

	LOG_I("Write DO %X", tag);

	CHECK_TRAP(SM_OK,
			Se05x_API_CheckObjectExists(pSe05x_ctx,
			ID(tag),
			&isDoExisting));
	if (isDoExisting != kSE05x_Result_SUCCESS) {
		LOG_E("DO does not exist");
		return SW_FILE_NOT_FOUND;
	}

	lengthField[0] = (buffLen >> 8) & 0xFF;
	lengthField[1] = (buffLen) & 0xFF;

	CHECK_RETURN(SM_OK,
			Se05x_API_WriteBinary(pSe05x_ctx, NULL, ID(tag), 0, 0, lengthField, 2));

	CHECK_RETURN(SM_OK,
			Se05x_API_WriteBinary(pSe05x_ctx, NULL, ID(tag), 2, 0, buff, buffLen));

	LOG_I("Done");

	return status;
}

sw_enum_t se_create_do(uint16_t tag, sss_policy_t *policy, uint16_t maxLen, uint8_t *data, size_t dataLen) {
	sss_se05x_session_t *psession = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t pSe05x_ctx = &psession->s_ctx;
	smStatus_t status = SM_NOT_OK;
	Se05xPolicy_t policySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];
	const uint8_t DEFAULTVALUE[] = { 0x00, 0x00 };
	uint8_t buffer[MAX_APDU_LEN];

	SE05x_Result_t isDoExisting = kSE05x_Result_FAILURE;
	CHECK_TRAP(SM_OK,
			Se05x_API_CheckObjectExists(pSe05x_ctx, ID(tag), &isDoExisting));
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
		status = Se05x_API_WriteBinary(pSe05x_ctx, &policySet, ID(tag), 0,
				maxLen + 2U, &buffer[0], dataLen + 2U);
	} else {
		status = Se05x_API_WriteBinary(pSe05x_ctx, &policySet, ID(tag), 0,
				maxLen + 2U, DEFAULTVALUE, sizeof(DEFAULTVALUE));
	}
	if (status != SM_OK) {
		LOG_E("Can't write empty DO");
		ERROR_TRAP();
	}

	return status;
}

sw_enum_t se_create_cnt(uint32_t tag, sss_policy_t *policy, size_t len) {
	sss_se05x_session_t *psession = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t pSe05x_ctx = &psession->s_ctx;
	smStatus_t status = SM_NOT_OK;
	Se05xPolicy_t policySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];
	SE05x_Result_t isCntExisting = kSE05x_Result_FAILURE;

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(pSe05x_ctx, ID(tag), &isCntExisting));
	if (isCntExisting == kSE05x_Result_SUCCESS) {
		status = Se05x_API_DeleteSecureObject(pSe05x_ctx, ID(tag));
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

	CHECK_TRAP(SM_OK, Se05x_API_CreateCounter(pSe05x_ctx, &policySet, ID(tag), len));

	return SW_SUCCESS;
}

sw_enum_t se_inc_cnt(uint32_t tag) {
	sss_se05x_session_t *psession = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t pSe05x_ctx = &psession->s_ctx;
	return (sw_enum_t) Se05x_API_SetCounterValue(pSe05x_ctx, ID(tag), 3, 0);
}

sw_enum_t se_read_cnt(uint32_t tag, uint8_t *buff, size_t* buffLen) {
	sss_se05x_session_t *psession = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t pSe05x_ctx = &psession->s_ctx;
	return (sw_enum_t) Se05x_API_ReadObject(pSe05x_ctx, ID(tag), 0, 0, buff, buffLen);
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
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
	if(se_sessions.activeAuthObjId == pinID){
		return kStatus_SSS_Success;
	}
	for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
		if(pinID == se_sessions.objID[i]){
			session_ctx->hasSession = 1;
			se_sessions.activeAuthObjId = pinID;
			memcpy(session_ctx->value, se_sessions.sessionId[i], 8);
			return kStatus_SSS_Success;
		}
	}
	return kStatus_SSS_Fail;
}

sw_enum_t se_open_session(uint32_t pinID, uint8_t const *pinValue,
		uint8_t pinLen) {
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
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

	session_ctx->hasSession = 0;
	CHECK_RETURN(SM_OK, Se05x_API_CreateSession(
			session_ctx,
			pinID,
			session_ctx->value,
			&sessionIdLen));

	session_ctx->hasSession = 1;
	status = Se05x_API_VerifySessionUserID(session_ctx, pinValue, pinLen);
	if (status != SM_OK) {
		LOG_W("Cant verify userID");
		session_ctx->hasSession = 0;
		return (sw_enum_t) status;
	}
	for(uint8_t i = 0; i<MAX_ACTIVE_SESSIONS; i++) {
		if(se_sessions.objID[i] == 0){
			se_sessions.activeAuthObjId = pinID;
			se_sessions.objID[i] = pinID;
			memcpy(se_sessions.sessionId[i], session_ctx->value, 8);
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
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;

	if(session_ctx->hasSession == 1) {
		for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
			if(se_sessions.activeAuthObjId == se_sessions.objID[i]){
				Se05x_API_CloseSession(session_ctx);
				session_ctx->hasSession = 0;
				se_sessions.activeAuthObjId = 0;
				se_sessions.objID[i] = 0;
				memset(&se_sessions.sessionId[i], 0, 8);
				se_sessions.nbActiveSessions--;
			}
		}
	}
}

void se_close_session(uint32_t pinID) {
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;

	for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
		if(pinID == se_sessions.objID[i]){
			session_ctx->hasSession = 1;
			memcpy(session_ctx->value, se_sessions.sessionId[i], 8);
			Se05x_API_CloseSession(session_ctx);
			session_ctx->hasSession = 0;
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
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;

	for(uint8_t i = 0; i<se_sessions.nbActiveSessions; i++) {
		session_ctx->hasSession = 1;
		memcpy(session_ctx->value, se_sessions.sessionId[i], 8);
		Se05x_API_CloseSession(session_ctx);
		session_ctx->hasSession = 0;
		se_sessions.objID[i] = 0;
		memset(&se_sessions.sessionId[i], 0, 8);
	}
	se_sessions.activeAuthObjId = 0;
	se_sessions.nbActiveSessions = 0;
}

sw_enum_t se_set_lockstate(uint8_t const *pinValue, size_t pinLen, SE05x_LockIndicator_t lockindicator, SE05x_LockState_t lockstate) {
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
	smStatus_t status;
	SE05x_Result_t exists;

	LOG_I("Changing lockstate %X %X", lockindicator, lockstate);

	if(pinLen != 6U && pinLen != 8U) {
		return SW_WRONG_DATA;
	}

	status = Se05x_API_CheckObjectExists(session_ctx, OBJ_ID_LOCKSTATE, &exists);
	if (status == SM_OK && exists != kSE05x_Result_SUCCESS) {
		LOG_I("Creating lockstate PIN");
		CHECK_TRAP(SM_OK, se_set_pin(OBJ_ID_LOCKSTATE, pinValue, pinLen));
	} else {
		LOG_I("SE probably locked");
	}

	uint8_t oldsessionId[8];
	uint8_t oldhasSession;
	uint32_t oldactiveAuthObjId;
	memcpy(oldsessionId, session_ctx->value, 8);
	oldhasSession = session_ctx->hasSession;
	oldactiveAuthObjId = se_sessions.activeAuthObjId;

	session_ctx->hasSession = 0;
	size_t sessionIdLen = 8;
	CHECK_TRAP(SM_OK, Se05x_API_CreateSession(
			session_ctx,
			OBJ_ID_LOCKSTATE,
			session_ctx->value,
			&sessionIdLen));

	session_ctx->hasSession = 1;
	status = Se05x_API_VerifySessionUserID(session_ctx, pinValue, pinLen);
	if (status != SM_OK) {
		LOG_E("Cant verify userID");
		return SW_SECURITY_STATUS_NOT_SATISFIED;
	}

	CHECK_TRAP(SM_OK, Se05x_API_SetLockState(session_ctx, lockindicator, lockstate));

	if((lockindicator == kSE05x_LockIndicator_NA) && (lockstate == kSE05x_LockState_NA)) {//unlock persistent
		CHECK_TRAP(SM_OK, Se05x_API_DeleteSecureObject(session_ctx, OBJ_ID_LOCKSTATE));
		memcpy(session_ctx->value, oldsessionId, 8);
		session_ctx->hasSession = oldhasSession;
		se_sessions.activeAuthObjId = oldactiveAuthObjId;
		LOG_I("Done");
		return SM_OK; //Session automatically closed after PIN delete
	}

	Se05x_API_CloseSession(session_ctx);
	memcpy(session_ctx->value, oldsessionId, 8);
	session_ctx->hasSession = oldhasSession;
	se_sessions.activeAuthObjId = oldactiveAuthObjId;
	LOG_I("Done");
	return SM_OK;
}

sw_enum_t se_set_pin(uint32_t pinID, uint8_t const *pinValue, size_t pinLen) {
	//PIN derived into an AES-128 key using hash
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
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

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(session_ctx, pinID, &exists));
	if (exists == kSE05x_Result_SUCCESS) {
		LOG_I("Pin object already exists, deleting");
		status = Se05x_API_DeleteSecureObject(session_ctx, pinID);
		if (status != SM_OK) {
			LOG_E("Cant delete PIN");
			return (sw_enum_t) status;
		}
		if(se_sessions.activeAuthObjId == pinID) {
			session_ctx->hasSession = 0; //session automatically closed after PIN deletion
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
			Se05x_API_WriteUserID(session_ctx,
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
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
	SE05x_Result_t exists;
	*status = 0x00;

	if (SM_OK
			!= Se05x_API_CheckObjectExists(session_ctx, OBJ_ID_FACTORY_RESET,
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
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
	const uint8_t userId[] = { '1', '2', '3', '4', '5', '6' }; //DELETE_ALL_UserID_VALUE;

	LOG_I("Activating");

	CHECK_TRAP(SM_OK,
		Se05x_API_WriteUserID(session_ctx,
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
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
	const uint8_t userId[] = { '1', '2', '3', '4', '5', '6' }; //DELETE_ALL_UserID_VALUE;

	LOG_I("Terminating card");

	/* Trying to create ID if previous activation failed */
	status = Se05x_API_WriteUserID(session_ctx,
	NULL, 0, OBJ_ID_FACTORY_RESET, userId, sizeof(userId),
			kSE05x_AttestationType_AUTH);
	if (status != SM_OK) {
		LOG_W("Can't create RESERVED_ID_FACTORY_RESET user ID");
	}

	CHECK_TRAP(SW_SUCCESS, se_open_session(OBJ_ID_FACTORY_RESET, userId, sizeof(userId)));
	CHECK_TRAP(SM_OK, Se05x_API_DeleteAll(session_ctx));

	LOG_I("Done");

	se_close_all_sessions();
	return SW_SUCCESS;
}

sss_status_t se_get_random(uint8_t *buff, uint16_t size) {
	sss_status_t status = kStatus_SSS_Fail;
	sss_rng_context_t sss_rng_ctx;
	CHECK_RETURN(kStatus_SSS_Success, sss_rng_context_init(&sss_rng_ctx, &PCONTEXT->session));
	CHECK_RETURN(kStatus_SSS_Success, sss_rng_get_random(&sss_rng_ctx, buff, size));
	return kStatus_SSS_Success;
}

sw_enum_t se_generate_rsa_key_pair(uint32_t keyId, size_t keylen,
		sss_policy_t *policy) {

	sss_status_t status;
	sss_object_t key;
	SE05x_Result_t exists;
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;

	LOG_I("Generating RSA key pair %X", keyId);

	CHECK_TRAP(SM_OK,
			Se05x_API_CheckObjectExists(&session->s_ctx,
			keyId,
			&exists));
	if (exists == kSE05x_Result_SUCCESS) {
		LOG_I("Key object already exists");
		policy = NULL;
	}

	CHECK_TRAP(kStatus_SSS_Success,
			sss_key_object_init(&key,
			&PCONTEXT->ks));

	CHECK_TRAP(kStatus_SSS_Success,
			sss_key_object_allocate_handle(&key,
			keyId,
			kSSS_KeyPart_Pair,
			kSSS_CipherType_RSA_CRT,
			(keylen / 8),
			kKeyObject_Mode_Persistent));

	status = sss_key_store_generate_key(&PCONTEXT->ks, &key, keylen, policy);
	if (status != kStatus_SSS_Success) {
		LOG_E("Can't init key object");
		return SW_ERR_ACCESS_DENIED_BASED_ON_POLICY;
	}

	LOG_I("Done");
	return SW_SUCCESS;
}

sw_enum_t se_import_rsa_key_pair(uint32_t keyId, key_struct_t *key, sss_policy_t *policy) {

	smStatus_t status = SW_UNKOWN;
	SE05x_Result_t exists;
	uint16_t keylen = RSA_KEY_LEN;
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	Se05xPolicy_t policySet;
	size_t valid_policy_buff_len = 0;
	uint8_t policies_buff[MAX_POLICY_BUFFER_SIZE];

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(&session->s_ctx, keyId, &exists));
	if (exists == kSE05x_Result_SUCCESS) {
		LOG_I("Key object already exists");
		policy = NULL;
		keylen = 0;
	}

	CHECK_TRAP(kStatus_SSS_Success,
			sss_se05x_create_object_policy_buffer(policy,
					&policies_buff[0],
					&valid_policy_buff_len));
	policySet.value = policies_buff;
	policySet.value_len = valid_policy_buff_len;


	CHECK_RETURN(SM_OK, Se05x_API_WriteRSAKey(
			&session->s_ctx,
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
			&session->s_ctx,
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
			&session->s_ctx,
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
			&session->s_ctx,
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
			&session->s_ctx,
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
			&session->s_ctx,
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
			&session->s_ctx,
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
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;

	CHECK_TRAP(SM_OK, Se05x_API_CheckObjectExists(&session->s_ctx, keyId, &exists));
	if (exists != kSE05x_Result_SUCCESS) {
		LOG_W("Key object does not exist");
		return SW_FILE_NOT_FOUND;
	}

	CHECK_TRAP(SM_OK,
			Se05x_API_ReadRSA(&session->s_ctx, keyId, 0, 0,
			kSE05x_RSAPubKeyComp_MOD, modulus, modLen));

	CHECK_TRAP(SM_OK, Se05x_API_ReadRSA(&session->s_ctx, keyId, 0, 0,
			kSE05x_RSAPubKeyComp_PUB_EXP, exponent, expLen));

	return SW_SUCCESS;
}

sw_enum_t se_get_origin(uint32_t objectID, uint8_t *statusByte) {
	sss_se05x_session_t *session = (sss_se05x_session_t*) &PCONTEXT->session;
	pSe05xSession_t session_ctx = &session->s_ctx;
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
	retStatus = Se05x_API_CheckObjectExists(session_ctx, objectID,
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
	retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf,
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

sss_status_t se_rsa_decrypt(uint32_t keyId, uint8_t *cipher, size_t cipherLen,
		uint8_t *plain, size_t *plainLen) {
	sss_status_t status;
	sss_algorithm_t algorithm = kAlgorithm_SSS_RSASSA_NO_PADDING;
	sss_mode_t mode = kMode_SSS_Decrypt;
	size_t keylen = 2048;
	/* asymmetric Sign */

	sss_object_t key = {0};
	sss_asymmetric_t ctx_asymm = { 0 };

	LOG_I("RSA decrypt with %X", keyId);

	status = sss_key_object_init(&key, &PCONTEXT->ks);
	if (status != kStatus_SSS_Success) {
		LOG_W("can't init key object");
		return kStatus_SSS_Fail;
	}

	status = sss_key_object_allocate_handle(&key, keyId, kSSS_KeyPart_Pair,
			kSSS_CipherType_RSA, (keylen / 8), kKeyObject_Mode_Persistent);
	if (status != kStatus_SSS_Success) {
		LOG_W("can't allocate key object");
		return kStatus_SSS_Fail;
	}

	status = sss_asymmetric_context_init(&ctx_asymm, &PCONTEXT->session, &key,
			algorithm, mode);
	if (status != kStatus_SSS_Success) {
		LOG_W("can't init asymmetric context key object");
		return kStatus_SSS_Fail;
	}

	status = sss_asymmetric_decrypt(&ctx_asymm, cipher, cipherLen, plain,
			plainLen);
	if (status != kStatus_SSS_Success) {
		LOG_W("can't init asymmetric context key object");
		return kStatus_SSS_Fail;
	}

	return kStatus_SSS_Success;
}
