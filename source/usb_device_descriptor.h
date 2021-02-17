/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2017 NXP
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_DEVICE_DESCRIPTOR_H__
#define __USB_DEVICE_DESCRIPTOR_H__

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define USB_DEVICE_SPECIFIC_BCD_VERSION (0x0200U)
#define USB_DEVICE_DEMO_BCD_VERSION (0x0101U)

#define USB_DEVICE_CLASS (0x00U)
#define USB_DEVICE_SUBCLASS (0x00U)
#define USB_DEVICE_PROTOCOL (0x00U)

#define USB_DEVICE_MAX_POWER (0x32U)

#define USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL (sizeof(g_UsbDeviceConfigurationDescriptor))
#define USB_DESCRIPTOR_LENGTH_ICCD_REPORT (sizeof(g_UsbDeviceIccdGenericReportDescriptor))
#define USB_DESCRIPTOR_LENGTH_ICCD (0x36U)
#define USB_DESCRIPTOR_LENGTH_STRING0 (sizeof(g_UsbDeviceString0))
#define USB_DESCRIPTOR_LENGTH_STRING1 (sizeof(g_UsbDeviceString1))
#define USB_DESCRIPTOR_LENGTH_STRING2 (sizeof(g_UsbDeviceString2))

#define USB_DEVICE_CONFIGURATION_COUNT (1U)
#define USB_DEVICE_STRING_COUNT (3U)
#define USB_DEVICE_LANGUAGE_COUNT (1U)

#define USB_ICCD_CONFIGURE_INDEX (1U)
#define USB_ICCD_INTERFACE_COUNT (1U)
#define USB_ICCD_IN_BUFFER_LENGTH (8U)
#define USB_ICCD_OUT_BUFFER_LENGTH (8U)
#define USB_ICCD_ENDPOINT_COUNT (0U) //ICCD Version A/B
#define USB_ICCD_INTERFACE_INDEX (0U)
#define USB_ICCD_ENDPOINT_IN (1U)
#define USB_ICCD_ENDPOINT_OUT (2U)

#define USB_ICCD_CLASS (0x0BU)
#define USB_ICCD_SUBCLASS (0x00U)
#define USB_ICCD_PROTOCOL (0x01U) //0x01 = Version A

#define HS_ICCD_INTERRUPT_OUT_PACKET_SIZE (8U)
#define FS_ICCD_INTERRUPT_OUT_PACKET_SIZE (8U)
#define HS_ICCD_INTERRUPT_OUT_INTERVAL (0x04U) /* 2^(4-1) = 1ms */
#define FS_ICCD_INTERRUPT_OUT_INTERVAL (0x01U)

#define HS_ICCD_INTERRUPT_IN_PACKET_SIZE (8U)
#define FS_ICCD_INTERRUPT_IN_PACKET_SIZE (8U)
#define HS_ICCD_INTERRUPT_IN_INTERVAL (0x04U) /* 2^(4-1) = 1ms */
#define FS_ICCD_INTERRUPT_IN_INTERVAL (0x01U)

/*******************************************************************************
 * API
 ******************************************************************************/

/* Configure the device according to the USB speed. */
extern usb_status_t USB_DeviceSetSpeed(usb_device_handle handle, uint8_t speed);

/* Get device descriptor request */
usb_status_t USB_DeviceGetDeviceDescriptor(usb_device_handle handle,
                                           usb_device_get_device_descriptor_struct_t *deviceDescriptor);
#if (defined(USB_DEVICE_CONFIG_CV_TEST) && (USB_DEVICE_CONFIG_CV_TEST > 0U))
/* Get device qualifier descriptor request */
usb_status_t USB_DeviceGetDeviceQualifierDescriptor(
    usb_device_handle handle, usb_device_get_device_qualifier_descriptor_struct_t *deviceQualifierDescriptor);
#endif
/* Get device configuration descriptor request */
usb_status_t USB_DeviceGetConfigurationDescriptor(
    usb_device_handle handle, usb_device_get_configuration_descriptor_struct_t *configurationDescriptor);

/* Get device string descriptor request */
usb_status_t USB_DeviceGetStringDescriptor(usb_device_handle handle,
                                           usb_device_get_string_descriptor_struct_t *stringDescriptor);

/* Get hid descriptor request */
usb_status_t USB_DeviceGetIccdDescriptor(usb_device_handle handle,
                                        usb_device_get_hid_descriptor_struct_t *hidDescriptor);

/* Get hid report descriptor request */
usb_status_t USB_DeviceGetIccdReportDescriptor(usb_device_handle handle,
                                              usb_device_get_hid_report_descriptor_struct_t *hidReportDescriptor);

/* Get hid physical descriptor request */
usb_status_t USB_DeviceGetIccdPhysicalDescriptor(usb_device_handle handle,
                                                usb_device_get_hid_physical_descriptor_struct_t *hidPhysicalDescriptor);

#endif /* __USB_DEVICE_DESCRIPTOR_H__ */
