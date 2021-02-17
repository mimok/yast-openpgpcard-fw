/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef GPG_GPG_API_H_
#define GPG_GPG_API_H_

void gpg_init(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_dispatch(gpg_handle_struct_t *gpgHandle);
sw_enum_t gpg_parse_cmd(gpg_handle_struct_t *gpgHandle, uint8_t *buffIn, size_t buffInLen);

#endif /* GPG_GPG_API_H_ */
