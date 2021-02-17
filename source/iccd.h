/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_device_iccd.h"
#include "usb_device_descriptor.h"

#ifndef __USB_DEVICE_ICCD_GENERIC_H__
#define __USB_DEVICE_ICCD_GENERIC_H__

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define CONTROLLER_ID kUSB_ControllerLpcIp3511Fs0
#define USB_DEVICE_INTERRUPT_PRIORITY (3U)

typedef struct _usb_iccd_struct
{
    usb_device_handle deviceHandle;
    class_handle_t iccdHandle;
    uint8_t *buffer[2];
    uint8_t bufferIndex;
    uint8_t idleRate;
    uint8_t speed;
    uint8_t attach;
    uint8_t currentConfiguration;
    uint8_t currentInterfaceAlternateSetting[USB_ICCD_INTERFACE_COUNT];
} usb_iccd_struct_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#endif /* __USB_DEVICE_ICCD_GENERIC_H__ */
