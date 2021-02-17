/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "gpg_se_if.h"
#include "gpg_types.h"

#ifndef GPG_GPG_UTIL_H_
#define GPG_GPG_UTIL_H_

#ifdef DEBUG
#define ERROR_TRAP() printf("FATAL ERROR in %s at %d\r\n", __FILE__, __LINE__); while(true);
#else
#define ERROR_TRAP(s) while(true);
#endif

#define CHECK_TRAP(x, y) if((x) != (y)) {ERROR_TRAP()}
#define CHECK_RETURN_SW(x) status = (x); \
						if(status != SW_SUCCESS){ \
							return sendError(gpgHandle, status); \
						}
#define CHECK_RETURN(x, y) status = (x); \
						if(status != (y)){ \
							return status; \
						}
#define CHECK_TAG(x, y) if((x) != (y)) return sendError(gpgHandle, SW_REFERENCED_DATA_NOT_FOUND);

#define CHECK_CMD_OFFSET(x) if((x)->cmdDataOffset > (x)->LC) { \
								ERROR_TRAP(); \
							}
/**
 * \fn uint8_t sendSW(gpg_handle_struct_t *gpgHandle, uint16_t SW)
 * \brief Add the response status word at the end of an ISO7816 response.
 * \param[in] gpgHandle GPG application handler
 * \param[in] SW Status Word to be returned with the ISO7816 response
 * \return ICCD status byte indicating the ICCD status at the end of the command processing
 */
uint8_t sendRsp(gpg_handle_struct_t *gpgHandle);

/**
 * \fn uint8_t sendError(gpg_handle_struct_t *gpgHandle, sw_enum_t SW)
 * \brief Erase any response byte and return an error status word as ISO7816 response
 * \param[in] gpgHandle GPG application handler
 * \param[in] SW Status Word to be returned with the ISO7816 response
 * \return ICCD status byte indicating the ICCD status at the end of the command processing
 */
uint8_t sendError(gpg_handle_struct_t *gpgHandle, sw_enum_t SW);

void io_begin_constructed_field(gpg_handle_struct_t *gpgHandle, uint16_t tag);
void io_end_constructed_field(gpg_handle_struct_t *gpgHandle);
void io_add_tlv(gpg_handle_struct_t *gpgHandle, uint16_t tag, uint8_t const *data, size_t size);
void io_add_tl(gpg_handle_struct_t *gpgHandle, uint16_t tag, size_t size);
void io_add_array(gpg_handle_struct_t *gpgHandle, uint8_t const *data, size_t size);
void io_add_u8(gpg_handle_struct_t *gpgHandle, uint8_t data);
void io_add_u16(gpg_handle_struct_t *gpgHandle, uint16_t data);
void io_add_array_from_se(gpg_handle_struct_t *gpgHandle, uint32_t tag, size_t size);
void io_add_varray_from_se(gpg_handle_struct_t *gpgHandle, uint32_t tag, size_t maxSize);
sw_enum_t io_fetch_tl(gpg_handle_struct_t *gpgHandle, uint16_t *t, size_t *l);
uint8_t io_fetch_u16(gpg_handle_struct_t *gpgHandle);
uint8_t io_fetch_u8(gpg_handle_struct_t *gpgHandle);
sw_enum_t parse_extended_header_list(gpg_handle_struct_t *gpgHandle, key_struct_t* key);

sw_enum_t gpg_get_ptc(uint32_t pinID, uint8_t *ptc, uint8_t *maxptc);
void gpg_reset_ptc(uint32_t pinID);

#endif /* GPG_GPG_UTIL_H_ */
