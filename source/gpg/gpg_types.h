/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#ifndef GPG_GPG_TYPES_H_
#define GPG_GPG_TYPES_H_

/**
 * \enum gpg_apdu_ins_enum_t
 * \brief GPG INS code defined by PGP card standard
 */
typedef enum _gpg_apdu_ins_enum_t {
	INS_SELECT=0xA4,
	INS_SELECT_DATA=0xA5,
	INS_GET_DATA=0xCA,
	INS_GET_NEXT_DATA=0xCC,
	INS_VERIFY=0x20,
	INS_CHANGE_REFERENCE_DATA=0x24,
	INS_RESET_RETRY_COUNTER=0x2C,
	INS_PUTDATA_A=0xDA,
	INS_PUTDATA_B=0xDB,
	INS_GENERATE_ASYMMETRIC_KEY_PAIR=0x47,
	INS_PSO=0x2A,
	INS_INTERNAL_AUTHENTICATE=0x88,
	INS_GET_CHALLENGE=0x84,
	INS_TERMINATE_DF=0xE6,
	INS_ACTIVATE_FILE=0x44,
	INS_MANAGE_SECURITY_EVIRONMENT=0x22,
	INS_RESUME_PIN_CHANGE=0xFE,
	INS_GET_REMAINING_MEMORY=0xFD,
} __attribute__ ((__packed__)) gpg_apdu_ins_enum_t;


#define CLA_OFFSET 0 	//!< \def Offset of the CLA byte in an ISO7816 command
#define INS_OFFSET 1	//!< \def Offset of the INS byte in an ISO7816 command
#define P1_OFFSET 2		//!< \def Offset of the P1 byte in an ISO7816 command
#define P2_OFFSET 3		//!< \def Offset of the P2 byte in an ISO7816 command
#define LC_OFFSET 4		//!< \def Offset of the LC byte in an ISO7816 command

/**
 * \enum sw_enum_t ISO7816 status words
 */
typedef enum _sw_enum_t {
	SW_ALGORITHM_UNSUPPORTED = 0x9484,
	SW_BYTES_REMAINING_00 = 0x6100,
	SW_WARNING_STATE_UNCHANGED = 0x6200,
	SW_STATE_TERMINATED = 0x6285,
	SW_MORE_DATA_AVAILABLE = 0x6310,
	SW_WRONG_LENGTH = 0x6700,
	SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881,
	SW_SECURE_MESSAGING_NOT_SUPPORTED = 0x6882,
	SW_LAST_COMMAND_EXPECTED = 0x6883,
	SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884,
	SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982,
	SW_FILE_INVALID = 0x6983,
	SW_PIN_BLOCKED = 0x6983,
	SW_DATA_INVALID = 0x6984,
	SW_CONDITIONS_NOT_SATISFIED = 0x6985,
	SW_COMMAND_NOT_ALLOWED = 0x6986,
	SW_APPLET_SELECT_FAILED = 0x6999,
	SW_WRONG_DATA = 0x6a80,
	SW_FUNC_NOT_SUPPORTED = 0x6a81,
	SW_FILE_NOT_FOUND = 0x6a82,
	SW_RECORD_NOT_FOUND = 0x6a83,
	SW_FILE_FULL = 0x6a84,
	SW_INCORRECT_P1P2 = 0x6a86,
	SW_REFERENCED_DATA_NOT_FOUND = 0x6a88,
	SW_WRONG_P1P2 = 0x6b00,
	SW_CORRECT_LENGTH_00 = 0x6c00,
	SW_INS_NOT_SUPPORTED = 0x6d00,
	SW_CLA_NOT_SUPPORTED = 0x6e00,
	SW_ERR_ACCESS_DENIED_BASED_ON_POLICY = 0x6986,
	SW_UNKOWN = 0xFFFF,
	SW_SUCCESS=0x9000
} __attribute__ ((__packed__)) sw_enum_t;

/**
 * \struct gpg_cmd_struct_t
 * \brief Type describing the structure of an ISO7816 command
 *
 * cmdData and rspData actually point to the same buffer.
 */
typedef struct _gpg_cmd_struct_t {
	uint8_t CLA;			//!< CLA byte
	uint8_t INS;			//!< INS byte
	uint8_t P1;				//!< P1 byte
	uint8_t P2;				//!< P2 byte
	uint16_t LC;			//!< LC byte
	uint8_t *cmdData;		//!< Pointer to the first byte of the command data (if any)
	uint16_t cmdDataOffset;	//!< Offset of the cmd data byte which is currently processed
	uint32_t LE;			//!< LE byte
	uint8_t *rspData;		//!< Pointer to the first byte of the response data
	uint16_t rspDataLen; 	//!< Length of the response
	sw_enum_t SW;			//!< Response status word half-word
	uint8_t isExtended; 	//!< Is true if this is an extended command
} gpg_cmd_struct_t;

#define PW1_81_ACTIVE 1		//!< \def Flag indicating that PW1 N°81 is active
#define PW1_82_ACTIVE 2		//!< \def Flag indicating that PW1 N°82 is active
#define PW3_ACTIVE 4		//!< \def Flag indicating that PW3 is active

/**
 * \struct gpg_handle_struct_t
 * \brief Structure storing main information about GPG application
 */
typedef struct _gpg_handle_struct_t {
	uint8_t state;			//!< State of the GPG application ACTIVE/TERMINATED
	uint8_t activePin;		//!< Variable storing which PINs are active
	gpg_cmd_struct_t io;	//!< Variable storing the content of an ISO 7816 command and response
} gpg_handle_struct_t;

/* GPG Data structures */

/**
 * \struct historical_bytes_t
 * \brief Structure representing historical bytes
 *
 * More information given in ISO7816-4 and Open PGP Smart Card standard (section 6.1 of v3.4).
 * Due to serialization order of fields matter
 */
typedef struct
{
	uint8_t category_indicator;				//!< Category indicatore byte. For Open PGP, should be set to 0x00.
	/* card capabilities */
	uint8_t TL_card_capabilities;			//!< Card capabilities Tag
	uint8_t selection;						//!< Section method supported by the application
	uint8_t coding;							//!< Data coding byte
	uint8_t max_logical_channel : 3;		//!< Maximum number of logical channels
	uint8_t logical_channel_number : 2; 	//!< Logical channel number assignment
	uint8_t extended_length_info : 1;		//!< Extended Length Information in EF.ATR/INFO
	uint8_t extended_lc_le : 1;				//!< Extended Lc and Le fields
	uint8_t command_chaining : 1;			//!< Command chaining
	/* Card service data */
	uint8_t TL_service_data;				//!< Card service data Tag
	uint8_t card_without_MF : 1;			//!< Card with MF (=0), card without MF (=1)
	uint8_t DOs_access_services : 3;		/*! EF.DIR and EF.ATR/INFO access servicesby the GET DATA command (BER-TLV)
												Should be set to 010, if Extended Length is supported */
	uint8_t DOs_available_EFATR_INFO : 1;	//!< DOs available in EF.ATR/INFOShould be set to 1, if Extended Length is sup-ported
	uint8_t DOs_available_EFDIR : 1;		//!< DOs available in EF.DIR
	uint8_t select_partial_DF : 1;			//!< Application Selection by partial DF name
	uint8_t select_full_DF : 1;				//!< Application Selection by full DF name (AID)
} __attribute__ ((__packed__)) historical_bytes_t;

/**
 * \enum sm_type_t Type of available secure messaging
 */
typedef enum
{
	SM_NONE = 0x00,		//!< No secure messagin available
	SM_AES128 = 0x01,	//!< Secure messaging with AES128
	SM_AES256 = 0x02,	//!< Secure messaging with AES256
	SM_SCP11 = 0x03		//!< Secure messaging using SCP11
} __attribute__ ((__packed__)) sm_type_t;

/**
 * \struct extended_capabilities_t
 * \brief Structure representing Extended Capabilities bytes
 *
 * More information given in Open PGP Smart Card standard (section 6.1 of v3.4).
 * Due to serialization order of fields matter
 */
typedef struct
{
	uint8_t KDF_DO_available : 1;		//!< KDF-DO (F9) and related functionality avail-able
	uint8_t PSO_AES : 1;				//!< PSO:DEC/ENC with AES
	uint8_t alg_attr_changeable : 1;	//!< Algorithm attributes changeable with PUT DATA
	uint8_t privateDO_available : 1;	//!< Support for Private use DOs (0101-0104)
	uint8_t PWStatus_editable : 1;		//!< PW Status changeable (DO C4 available for PUT DATA)
	uint8_t Kimport_supported : 1;		//!< Support for Key Import
	uint8_t GC_supported : 1;			//!< Support for GET CHALLENGEThe maximum supported length of a chal-lenge can be found in Extended Capabilities
	uint8_t SM_supported : 1;			//!< Secure Messaging supported
	sm_type_t sm_type;					//!< Secure Messaging Algorithm (SM)
	uint16_t GC_max_len;				/*! Maximum length of a challenge supported by the command GETCHALLENGE
											(unsigned integer, Most Significant Bit ... Least Significant Bit).
											If GET CHALLENGE is not supported (see 1stbyte), the coding is 0000 */
	uint16_t CC_max_len;				/*! Maximum length of Cardholder Certificates (DO 7F21, each for AUT, DEC and SIG),
											coded as unsigned integer (Most Signific-ant Bit ... Least Significant Bit). */
	uint16_t DO_max_len;				/*! Maximum length of special DOs with no precise length informa-tion given in the definition
											(Private Use, Login data, URL, Algorithm attributes, KDF etc.),
											coded as unsigned integer (MostSignificant Bit ... Least Significant Bit) */
	uint8_t pinblock2_suported;			//!< PIN block 2 format (0 = not supported, 1 = supported)
	uint8_t MSE_cmd_key2_key3;			//!< MSE command for key numbers 2 (DEC) and 3 (AUT) (0 = not supported, 1 = supported)
} __attribute__ ((__packed__)) extended_capabilities_t;

/**
 *  \struct rsa_attributes_t
 *  \brief Attribute structure of an RSA key
 */
typedef struct {
	uint8_t algorithm;	//!< =0x01 in case of RSA
	uint16_t m_size;	//!< Size of the modulus in bits
	uint16_t e_size;	//!< Size of the public exponent in bits
	uint8_t pk_format;	/*! Import-Format of private key
								- 00 = standard (e, p, q)
								- 01 = standard with modulus (n)
								- 02 = crt (Chinese Remainder Theorem)
								- 03 = crt with modulus (n) */
} __attribute__ ((__packed__)) rsa_attributes_t;

typedef enum {
	RSA_PRIVATE_KEY,
	ECDSA_PRIVATE_KEY,
} keytype_enum_t;

typedef struct {
	uint8_t *data;
	size_t dataLen;
} array_struct_t;

typedef struct {
	array_struct_t e;
	array_struct_t p;
	array_struct_t q;
	array_struct_t pq1;
	array_struct_t dp1;
	array_struct_t dq1;
	array_struct_t n;
} rsakey_struct_t;

typedef struct {
	array_struct_t private;
	array_struct_t public;
} ecdsakey_struct_t;

typedef struct {
	uint32_t id;
	keytype_enum_t type;
	union {
		rsakey_struct_t rsa;
		ecdsakey_struct_t ecdsa;
	};
} key_struct_t;

/**
 * \struct pw_status_bytes_t
 *
 * Due to serialization order of fields matter
 */
typedef struct {
	uint8_t pw1_validity; 	//!< 00 = PW1 (no. 81) only valid for one PSO:CDS command, 01 = PW1 valid for several PSO:CDS commands
	const uint8_t pw1_length : 7;	//!< Length of PW1
	const uint8_t pw1_format : 1;	//!< Format of PW1 (0 = UTF-8, 1 = PIN block format 2)
	const uint8_t rc_length;		//!< Length of Reseting Code
	const uint8_t pw3_length : 7;	//!< Length of PW3
	const uint8_t pw3_format : 1;	//!< Format of PW1 (0 = UTF-8, 1 = PIN block format 2)
	uint8_t pw1_ptc;				//!< PW1 PIN try counter value
	uint8_t rc_ptc;					//!< RC PIN try counter value
	uint8_t pw3_ptc;				//!<PW3 PIN try counter	value
} __attribute__ ((__packed__)) pw_status_bytes_t;

/**
 * \enum origin_t Origin of a key
 */
typedef enum
{
	ORIGIN_INTERNAL=0x01, 		//!< Key internally generated
	ORIGIN_EXTERNAL=0x02,		//!< Key imported from outside world
	ORIGIN_PROVISIONED=0x03,	//!< Key pre-provisioned by NXP
} __attribute__ ((__packed__)) origin_t;

#endif /* GPG_GPG_TYPES_H_ */
