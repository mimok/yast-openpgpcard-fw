/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "gpg_types.h"
#include "gpg_config.h"
#include "gpg_util.h"

static uint16_t constructed_field_tag;
static uint16_t constructed_field_offset;

uint8_t sendError(gpg_handle_struct_t *gpgHandle, sw_enum_t SW) {
	memset(gpgHandle->io.rspData, 0, MAX_APDU_LEN);
	gpgHandle->io.rspDataLen = 0;
	gpgHandle->io.rspData[gpgHandle->io.rspDataLen++] = (SW >> 8);
	gpgHandle->io.rspData[gpgHandle->io.rspDataLen++] = (SW & 0xFF);
	return 0x20; //RAPDU does not contain data
}

uint8_t sendRsp(gpg_handle_struct_t *gpgHandle) {
	sw_enum_t SW = SW_SUCCESS;
	if(gpgHandle->io.rspDataLen > gpgHandle->io.LE+2) {
		/*
		 * TODO: REquire buffering response to be compliant with ISO 7816
		 * At the moment return data even if data length in greater than Ne.
		 */

	}
	gpgHandle->io.rspData[gpgHandle->io.rspDataLen++] = (SW >> 8);
	gpgHandle->io.rspData[gpgHandle->io.rspDataLen++] = (SW & 0xFF);
	if(gpgHandle->io.rspDataLen > 2) {
		return 0x10; //RAPDU contains data
	} else {
		return 0x20; //RAPDU does not contain data
	}
}

void io_begin_constructed_field(gpg_handle_struct_t *gpgHandle, uint16_t tag) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	constructed_field_tag = tag;
	constructed_field_offset = pio->rspDataLen;
}

void io_end_constructed_field(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t length = pio->rspDataLen - constructed_field_offset;
	uint16_t tag = constructed_field_tag;
	uint16_t destination_offset = 0;

	if ((tag>>8) != 0x00) {
		destination_offset++;
	}
	destination_offset++;
	if(length <= 127U){
		destination_offset += 1;
	} else if(length <= 255U) {
		destination_offset += 2;
	} else if(length <= 65535) {
		destination_offset += 3;
	} else {
		ERROR_TRAP();
	}
	memmove(&pio->rspData[constructed_field_offset+destination_offset],
			&pio->rspData[constructed_field_offset],
			length);

	pio->rspDataLen = constructed_field_offset;
	io_add_tl(gpgHandle, tag, length);
	pio->rspDataLen += length;
}

void io_add_tlv(gpg_handle_struct_t *gpgHandle, uint16_t tag, uint8_t const *data, size_t size) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	io_add_tl(gpgHandle, tag, size);
	memcpy(&pio->rspData[pio->rspDataLen], data, size);
	pio->rspDataLen += size;
}

void io_add_tl(gpg_handle_struct_t *gpgHandle, uint16_t tag, size_t size) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	if ((tag>>8) != 0x00)
		pio->rspData[pio->rspDataLen++] = tag >> 8;
	pio->rspData[pio->rspDataLen++] = tag & 0xFF;
	if(size <= 127U){
		pio->rspData[pio->rspDataLen++] = size & 0x7F;
	} else if(size <= 255U) {
		pio->rspData[pio->rspDataLen++] = 0x81;
		pio->rspData[pio->rspDataLen++] = size & 0xFF;
	} else if(size <= 65535) {
		pio->rspData[pio->rspDataLen++] = 0x82;
		pio->rspData[pio->rspDataLen++] = (size>>8) & 0xFF;
		pio->rspData[pio->rspDataLen++] = size & 0xFF;
	} else {
		ERROR_TRAP();
	}
}

void io_add_array(gpg_handle_struct_t *gpgHandle, uint8_t const *data, size_t size) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	memcpy(&pio->rspData[pio->rspDataLen], data, size);
	pio->rspDataLen += size;
}

void io_add_array_from_se(gpg_handle_struct_t *gpgHandle, uint32_t tag, size_t size) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	size_t sz = size;
	sw_enum_t status;
	status = se_read_do(tag, &pio->rspData[pio->rspDataLen], &sz);
	if(status != SW_SUCCESS || sz != size) {
		ERROR_TRAP();
	}
	pio->rspDataLen += sz;
}

void io_add_varray_from_se(gpg_handle_struct_t *gpgHandle, uint32_t tag, size_t maxSize) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	size_t sz = maxSize;
	sw_enum_t status;
	status = se_read_do(tag, &pio->rspData[pio->rspDataLen], &sz);
	if(status != SW_SUCCESS || sz > maxSize) {
		ERROR_TRAP();
	}
	pio->rspDataLen += sz;
}

void io_add_u8(gpg_handle_struct_t *gpgHandle, uint8_t data) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	pio->rspData[pio->rspDataLen++] = data;
}

void io_add_u16(gpg_handle_struct_t *gpgHandle, uint16_t data) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	pio->rspData[pio->rspDataLen++] = (data >> 8) & 0xFF;
	pio->rspData[pio->rspDataLen++] = data & 0xFF;
}

sw_enum_t io_fetch_tl(gpg_handle_struct_t *gpgHandle, uint16_t *t, size_t *l) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint8_t b;

	*t = pio->cmdData[pio->cmdDataOffset++];
	if((*t&0x1F) == 0x1F) {
		*t = (*t<<8) | pio->cmdData[pio->cmdDataOffset++];
	}

	b = pio->cmdData[pio->cmdDataOffset++];
	if(b <= 127) {
		*l = b;
		return SW_SUCCESS;
	}
	if(b == 0x81) {
		b = pio->cmdData[pio->cmdDataOffset++];
		*l = b;
		return SW_SUCCESS;
	}
	if(b == 0x82) {
		b = pio->cmdData[pio->cmdDataOffset++];
		*l = b << 8;
		*l |= pio->cmdData[pio->cmdDataOffset++];
		return SW_SUCCESS;
	}
	return SW_WRONG_LENGTH;
}

uint8_t io_fetch_u8(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	return pio->cmdData[pio->cmdDataOffset++];
}

uint8_t io_fetch_u16(gpg_handle_struct_t *gpgHandle) {
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t data;
	data = pio->cmdData[pio->cmdDataOffset++]<<8;
	data |= pio->cmdData[pio->cmdDataOffset++];
	return data;
}

sw_enum_t parse_extended_header_list(gpg_handle_struct_t *gpgHandle, key_struct_t* key) {
	sw_enum_t status;
	size_t templateEndOffset;
	gpg_cmd_struct_t *pio = &gpgHandle->io;
	uint16_t tag;
	size_t len;

	CHECK_RETURN(SW_SUCCESS, io_fetch_tl(gpgHandle, &tag, &len));
	CHECK_TAG(tag, 0x004D);
	CHECK_RETURN(SW_SUCCESS, io_fetch_tl(gpgHandle, &tag, &len));
	switch (tag) {
	case 0xB6:
		key->id = OBJ_ID_SIG_KEY;
		break;
	case 0xB8:
		key->id = OBJ_ID_ENC_KEY;
		break;
	case 0xA4:
		key->id = OBJ_IDAUTH_KEY;
		break;
	default:
		return SW_REFERENCED_DATA_NOT_FOUND;
	}

	CHECK_RETURN(SW_SUCCESS, io_fetch_tl(gpgHandle, &tag, &len));
	CHECK_TAG(tag, 0x7F48);
	templateEndOffset = pio->cmdDataOffset + len;
	while(pio->cmdDataOffset < templateEndOffset) {
		CHECK_RETURN(SW_SUCCESS, io_fetch_tl(gpgHandle, &tag, &len));
		switch(tag){
		case 0x91:
			key->rsa.e.dataLen = len;
			break;
		case 0x92:
			key->rsa.p.dataLen = len;
			break;
		case 0x93:
			key->rsa.q.dataLen = len;
			break;
		case 0x94:
			key->rsa.pq1.dataLen = len;
			break;
		case 0x95:
			key->rsa.dp1.dataLen = len;
			break;
		case 0x96:
			key->rsa.dq1.dataLen = len;
			break;
		case 0x97:
			key->rsa.n.dataLen = len;
			break;
		case 0x99:
			return SW_REFERENCED_DATA_NOT_FOUND;
		}
	}
	CHECK_RETURN(SW_SUCCESS, io_fetch_tl(gpgHandle, &tag, &len));
	CHECK_TAG(tag, 0x5F48);
	key->rsa.e.data = &pio->cmdData[pio->cmdDataOffset];
	pio->cmdDataOffset += key->rsa.e.dataLen;
	key->rsa.p.data = &pio->cmdData[pio->cmdDataOffset];
	pio->cmdDataOffset += key->rsa.p.dataLen;
	key->rsa.q.data = &pio->cmdData[pio->cmdDataOffset];
	pio->cmdDataOffset += key->rsa.q.dataLen;
	key->rsa.pq1.data = &pio->cmdData[pio->cmdDataOffset];
	pio->cmdDataOffset += key->rsa.pq1.dataLen;
	key->rsa.dp1.data = &pio->cmdData[pio->cmdDataOffset];
	pio->cmdDataOffset += key->rsa.dp1.dataLen;
	key->rsa.dq1.data = &pio->cmdData[pio->cmdDataOffset];
	pio->cmdDataOffset += key->rsa.dq1.dataLen;
	key->rsa.n.data = &pio->cmdData[pio->cmdDataOffset];
	pio->cmdDataOffset += key->rsa.n.dataLen;

	if(pio->cmdDataOffset > pio->LC) {
		return SW_WRONG_DATA;
	}

	return SW_SUCCESS;
}





