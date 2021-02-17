/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "gpg_se_if.h"
#include "gpg_config.h"

/* Define policy for Read Always / Write upon PW3 Verify */
const sss_policy_u do_rw_always_pw3_pw3_file = {
	.type = KPolicy_File,
	.auth_obj_id = OBJ_ID_PW3,
	.policy = {
		.file = {
			.can_Write = 1,
			.can_Read = 1,
		}
	}
};

const sss_policy_u do_rw_always_pw3_pw3_common = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW3, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u do_rw_always_pw3_allothers_file = {
	.type = KPolicy_File,
	.auth_obj_id = 0x00000000,
	.policy = {
		.file = {
			.can_Write = 0,
			.can_Read = 1,
		}
	}
};

const sss_policy_u do_rw_always_pw3_allothers_common = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_t policy_do_rw_always_pw3 = {
	.nPolicies = 4,
	.policies = {
			&do_rw_always_pw3_pw3_file,
			&do_rw_always_pw3_pw3_common,
			&do_rw_always_pw3_allothers_file,
			&do_rw_always_pw3_allothers_common,
	}
};

/* Define policy for counter incremention PW1 Verify */

const sss_policy_u do_cnt_PW3_s = {
	.type = KPolicy_Counter,
	.auth_obj_id = OBJ_ID_PW3,
	.policy = {
		.counter = {
			.can_Write = 0,
			.can_Read = 1,
		}
	}
};

const sss_policy_u do_cnt_PW3_c = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW3, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 1,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u do_cnt_PW1_s = {
	.type = KPolicy_Counter,
	.auth_obj_id = OBJ_ID_PW1,
	.policy = {
		.counter = {
			.can_Write = 1,
			.can_Read = 1,
		}
	}
};

const sss_policy_u do_cnt_PW1_c = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW1, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u do_cnt_allothers_s = {
	.type = KPolicy_Counter,
	.auth_obj_id = 0x00000000,
	.policy = {
		.counter = {
			.can_Write = 0,
			.can_Read = 1,
		}
	}
};

const sss_policy_u do_cnt_allothers_c = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_t policy_do_cnt = {
	.nPolicies = 6,
	.policies = {
			&do_cnt_allothers_c,
			&do_cnt_allothers_s,
			&do_cnt_PW1_c,
			&do_cnt_PW1_s,
			&do_cnt_PW3_c,
			&do_cnt_PW3_s,
	}
};

/* Define policy for Read Never / Write upon PW3 Verify */
const sss_policy_u do_rw_never_pw3_pw3_file = {
	.type = KPolicy_File,
	.auth_obj_id = OBJ_ID_PW3,
	.policy = {
		.file = {
			.can_Write = 1,
			.can_Read = 0,
		}
	}
};

const sss_policy_u do_rw_never_pw3_pw3_common = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW3, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u do_rw_never_pw3_allothers_common = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 1,
		}
	}
};

const sss_policy_t policy_do_rw_never_pw3 = {
	.nPolicies = 3,
	.policies = {
			&do_rw_never_pw3_pw3_file,
			&do_rw_never_pw3_pw3_common,
			&do_rw_never_pw3_allothers_common,
	}
};

/* SIGN, ENC, AUTH keys policy */

const sss_policy_u asym_key_specific_pw3 = {
	.type = KPolicy_Asym_Key,
	.auth_obj_id = OBJ_ID_PW3,
	.policy = {
		.asymmkey = {
				.can_Sign = 0,
				.can_Verify = 0,
				.can_Encrypt = 0,
				.can_Decrypt = 0,
				.can_KD = 0,
			    .can_Write = 1,
			    .can_Gen = 1,
			    .can_Import_Export = 0,
			    .can_KA = 0,
			    .can_Read = 1,
			    .can_Attest = 0,
		}
	}
};

const sss_policy_u asym_key_common_pw3 = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW3, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u asym_key_specific_pw1 = {
	.type = KPolicy_Asym_Key,
	.auth_obj_id = OBJ_ID_PW1,
	.policy = {
		.asymmkey = {
				.can_Sign = 0,
				.can_Verify = 0,
				.can_Encrypt = 0,
				.can_Decrypt = 1,
				.can_KD = 0,
			    .can_Write = 0,
			    .can_Gen = 0,
			    .can_Import_Export = 0,
			    .can_KA = 0,
			    .can_Read = 1,
			    .can_Attest = 0,
		}
	}
};

const sss_policy_u asym_key_common_pw1 = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW1, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u asym_key_specific_allothers = {
	.type = KPolicy_Asym_Key,
	.auth_obj_id = 0x00000000,
	.policy = {
		.asymmkey = {
				.can_Sign = 0,
				.can_Verify = 0,
				.can_Encrypt = 0,
				.can_Decrypt = 0,
				.can_KD = 0,
			    .can_Write = 0,
			    .can_Gen = 0,
			    .can_Import_Export = 0,
			    .can_KA = 0,
			    .can_Read = 1,
			    .can_Attest = 0,
		}
	}
};

const sss_policy_u asym_key_common_allothers = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000, //All others
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_t policy_asymmkey = {
	.nPolicies = 6,
	.policies = {
			&asym_key_common_allothers,
			&asym_key_specific_allothers,
			&asym_key_common_pw1,
			&asym_key_specific_pw1,
			&asym_key_common_pw3,
			&asym_key_specific_pw3,
	}
};

/* PW3 PIN policy */
const sss_policy_u PW3Policy_common_PW3 = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW3,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 1,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u PW3Policy_common_allothers = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_t policy_PW3 = {
	.nPolicies = 2,
	.policies = {
			&PW3Policy_common_PW3,
			&PW3Policy_common_allothers,
	}
};

/* PW1 PIN policy */
const sss_policy_u PW1Policy_common_PW3 = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW3,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 1,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u PW1Policy_common_PW1 = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_PW1,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 1,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u PW1Policy_common_RC = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_RC,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 1,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u PW1Policy_common_allothers = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_t policy_PW1 = {
	.nPolicies = 4,
	.policies = {
			&PW1Policy_common_PW3,
			&PW1Policy_common_PW1,
			&PW1Policy_common_RC,
			&PW1Policy_common_allothers,
	}
};

/* LockState PIN policy */
const sss_policy_u LSPolicy_common_LS = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = OBJ_ID_LOCKSTATE,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 1,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_u LSPolicy_common_allothers = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_t policy_LS = {
	.nPolicies = 2,
	.policies = {
			&LSPolicy_common_LS,
			&LSPolicy_common_allothers,
	}
};

//default policy, only delete is forbidden

const sss_policy_u nopolicy_file_allothers = {
	.type = KPolicy_File,
	.auth_obj_id = 0x00000000,
	.policy = {
		.file = {
			.can_Write = 1,
			.can_Read = 1,
		}
	}
};

const sss_policy_u nopolicy_common_allothers = {
	.type = KPolicy_Common,
	/*Authentication object based on SE05X_AUTH*/
	.auth_obj_id = 0x00000000,
	.policy = {
		.common = {
			/*Secure Messaging*/
			.req_Sm = 0,
			/*Policy to Delete object*/
			.can_Delete = 0,
			/*Forbid all operations on object*/
			.forbid_All = 0,
		}
	}
};

const sss_policy_t policy_nopolicy = {
	.nPolicies = 2,
	.policies = {
			&nopolicy_common_allothers,
			&nopolicy_file_allothers,
	}
};
