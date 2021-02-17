/*
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef GPG_GPG_DISPATCH_H_
#define GPG_GPG_DISPATCH_H_

uint8_t gpg_get_challenge(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_get_data(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_activate_file(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_pso(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_terminate_df(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_gen_key(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_verify_pin(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_put_data_a(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_put_data_b(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_internal_auth(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_change_reference_data(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_reset_retry_counter(gpg_handle_struct_t *gpgHandle);
uint8_t gpg_resume_pin_change(gpg_handle_struct_t *gpgHandle);

#endif /* GPG_GPG_DISPATCH_H_ */
