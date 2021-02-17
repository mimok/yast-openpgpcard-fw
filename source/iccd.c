/*
 * Copyright (c) 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"
#include "usb_device_iccd.h"

#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"

#include "iccd.h"

#include "fsl_device_registers.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "peripherals.h"

#include <stdio.h>
#include <stdlib.h>
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
#include "fsl_sysmpu.h"
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

#include "pin_mux.h"
#include <stdbool.h>
#include "fsl_power.h"
#include "usb_phy.h"

#include "gpg_types.h"
#include "gpg_config.h"
#include "gpg_api.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
const uint8_t ATR[] = { 0x3B, 0x80, 0x01, 0x81 };

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void BOARD_InitHardware(void);
void USB_DeviceClockInit(void);
void USB_DeviceIsrEnable(void);

static usb_status_t USB_DeviceIccdCallback(class_handle_t handle,
		uint32_t event, void *param);
static usb_status_t USB_DeviceCallback(usb_device_handle handle, uint32_t event,
		void *param);
static void USB_DeviceApplicationInit(void);

/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint32_t s_GenericBuffer0[USB_ICCD_OUT_BUFFER_LENGTH
		>> 2];
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint32_t s_GenericBuffer1[USB_ICCD_OUT_BUFFER_LENGTH
		>> 2];
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_apduBuffer[MAX_APDU_LEN];
usb_iccd_struct_t g_UsbDeviceIccd;

extern usb_device_class_struct_t g_UsbDeviceIccdConfig0;

/* Set class configurations */
usb_device_class_config_struct_t g_UsbDeviceIccdConfig[1] = { {
		USB_DeviceIccdCallback, /* ICCD generic class callback pointer */
		(class_handle_t) NULL, /* The ICCD class handle, This field is set by USB_DeviceClassInit */
		&g_UsbDeviceIccdConfig0, /* The ICCD configuration, including class code, subcode, and protocol, class
 type,
 transfer type, endpoint address, max packet size, etc.*/
} };

/* Set class configuration list */
usb_device_class_config_list_struct_t g_UsbDeviceIccdConfigList = {
		g_UsbDeviceIccdConfig, /* Class configurations */
		USB_DeviceCallback, /* Device callback pointer */
		1U, /* Class count */
};

static volatile usb_device_iccd_control_request_struct_t inoutBuffer;

/*******************************************************************************
 * Code
 ******************************************************************************/
void USB0_IRQHandler(void) {
	USB_DeviceLpcIp3511IsrFunction(g_UsbDeviceIccd.deviceHandle);
}

void USB_DeviceClockInit(void) {
	/* enable USB IP clock */
	CLOCK_EnableUsbfs0DeviceClock(kCLOCK_UsbfsSrcFro, CLOCK_GetFroHfFreq());
#if defined(FSL_FEATURE_USB_USB_RAM) && (FSL_FEATURE_USB_USB_RAM)
	for (int i = 0; i < FSL_FEATURE_USB_USB_RAM; i++) {
		((uint8_t*) FSL_FEATURE_USB_USB_RAM_BASE_ADDRESS)[i] = 0x00U;
	}
#endif
}
void USB_DeviceIsrEnable(void) {
	uint8_t irqNumber;
	uint8_t usbDeviceIP3511Irq[] = USB_IRQS;
	irqNumber = usbDeviceIP3511Irq[CONTROLLER_ID - kUSB_ControllerLpcIp3511Fs0];
	/* Install isr, set priority, and enable IRQ. */
	NVIC_SetPriority((IRQn_Type) irqNumber, USB_DEVICE_INTERRUPT_PRIORITY);
	EnableIRQ((IRQn_Type) irqNumber);
}

/* The hid class callback */
static usb_status_t USB_DeviceIccdCallback(class_handle_t handle,
		uint32_t event, void *param) {
	usb_status_t error = kStatus_USB_Error;
	usb_device_iccd_struct_t *iccdHandle = (usb_device_iccd_struct_t*) handle;
	usb_device_iccd_control_request_struct_t *iccd_request;
	static uint8_t tmp_statusByte;
	switch (event) {
	case kUSB_DeviceIccdEventPowerOn:
		iccd_request = (usb_device_iccd_control_request_struct_t*) param;
		iccd_request->buffer = &ATR[0];
		iccd_request->length = sizeof(ATR);
		iccdHandle->statusByte = 0x00U;
		error = kStatus_USB_Success;
		break;
	case kUSB_DeviceIccdEventGetIccStatus:
		iccd_request = (usb_device_iccd_control_request_struct_t*) param;
		//cant use normal buffer as the cmd processing is ongoing
		tmp_statusByte = iccdHandle->statusByte;
		iccd_request->buffer = &tmp_statusByte; //TODO: Should be updated cyclically
		iccd_request->length = 1;
		error = kStatus_USB_Success;
		break;
	case kUSB_DeviceIccdEventPowerOff:
		iccdHandle->statusByte = 0x10U;
		error = kStatus_USB_Success;
		break;
	case kUSB_DeviceIccdEventXfrBlock:
		iccdHandle->statusByte = 0x40U;
		inoutBuffer = *((usb_device_iccd_control_request_struct_t*) param);
		error = kStatus_USB_Success;
		break;
	case kUSB_DeviceIccdEventDataBlock:
		iccd_request = (usb_device_iccd_control_request_struct_t*) param;
		iccd_request->buffer = inoutBuffer.buffer;
		iccd_request->length = inoutBuffer.length;

		iccdHandle->statusByte = 0x00U;
		error = kStatus_USB_Success;
		break;
	case kUSB_DeviceIccdEventXfrRequestBuffer:
		iccd_request = (usb_device_iccd_control_request_struct_t*) param;
		memset(s_apduBuffer, 0, sizeof(s_apduBuffer));
		iccd_request->buffer = &s_apduBuffer[0];
		error = kStatus_USB_Success;
	default:
		break;
	}

	return error;
}

/* The device callback */
static usb_status_t USB_DeviceCallback(usb_device_handle handle, uint32_t event,
		void *param) {
	usb_status_t error = kStatus_USB_Success;
	uint8_t *temp8 = (uint8_t*) param;
	uint16_t *temp16 = (uint16_t*) param;

	switch (event) {
	case kUSB_DeviceEventBusReset: {
		/* USB bus reset signal detected */
		g_UsbDeviceIccd.attach = 0U;
		g_UsbDeviceIccd.currentConfiguration = 0U;
		usb_echo("USB bus reset\r\n");
	}
		break;
	case kUSB_DeviceEventSetConfiguration:
		if (0U == (*temp8)) {
			g_UsbDeviceIccd.attach = 0U;
			g_UsbDeviceIccd.currentConfiguration = 0U;
		} else if (USB_ICCD_CONFIGURE_INDEX == (*temp8)) {
			/* Set device configuration request */
			g_UsbDeviceIccd.attach = 1U;
			g_UsbDeviceIccd.currentConfiguration = *temp8;
			usb_echo("USB setConfiguration\r\n");
		} else {

			error = kStatus_USB_InvalidRequest;
		}
		break;
	case kUSB_DeviceEventSetInterface:
		if (g_UsbDeviceIccd.attach) {
			/* Set device interface request */
			uint8_t interface = (uint8_t) ((*temp16 & 0xFF00U) >> 0x08U);
			uint8_t alternateSetting = (uint8_t) (*temp16 & 0x00FFU);
			if (interface < USB_ICCD_INTERFACE_COUNT) {
				g_UsbDeviceIccd.currentInterfaceAlternateSetting[interface] =
						alternateSetting;
			}
			usb_echo("USB setInterface\r\n");
		}
		break;
	case kUSB_DeviceEventGetConfiguration:
		if (param) {
			/* Get current configuration request */
			*temp8 = g_UsbDeviceIccd.currentConfiguration;
			usb_echo("USB getConfiguration\r\n");
			error = kStatus_USB_Success;
		}
		break;
	case kUSB_DeviceEventGetInterface:
		if (param) {
			/* Get current alternate setting of the interface request */
			uint8_t interface = (uint8_t) ((*temp16 & 0xFF00U) >> 0x08U);
			if (interface < USB_ICCD_INTERFACE_COUNT) {
				*temp16 =
						(*temp16 & 0xFF00U)
								| g_UsbDeviceIccd.currentInterfaceAlternateSetting[interface];
				error = kStatus_USB_Success;
			} else {
				error = kStatus_USB_InvalidRequest;
			}
		}
		break;
	case kUSB_DeviceEventGetDeviceDescriptor:
		if (param) {
			/* Get device descriptor request */
			error = USB_DeviceGetDeviceDescriptor(handle,
					(usb_device_get_device_descriptor_struct_t*) param);
		}
		break;
	case kUSB_DeviceEventGetConfigurationDescriptor:
		if (param) {
			/* Get device configuration descriptor request */
			error = USB_DeviceGetConfigurationDescriptor(handle,
					(usb_device_get_configuration_descriptor_struct_t*) param);
		}
		break;
#if (defined(USB_DEVICE_CONFIG_CV_TEST) && (USB_DEVICE_CONFIG_CV_TEST > 0U))
        case kUSB_DeviceEventGetDeviceQualifierDescriptor:
            if (param)
            {
                /* Get device descriptor request */
                error = USB_DeviceGetDeviceQualifierDescriptor(
                    handle, (usb_device_get_device_qualifier_descriptor_struct_t *)param);
            }
            break;
#endif
	case kUSB_DeviceEventGetStringDescriptor:
		if (param) {
			/* Get device string descriptor request */
			error = USB_DeviceGetStringDescriptor(handle,
					(usb_device_get_string_descriptor_struct_t*) param);
		}
		break;
//        case kUSB_DeviceEventGetIccdDescriptor:
//            if (param)
//            {
//                /* Get hid descriptor request */
//                error = USB_DeviceGetIccdDescriptor(handle, (usb_device_get_hid_descriptor_struct_t *)param);
//            }
//            break;
	default:
		break;
	}

	return error;
}

static void USB_DeviceApplicationInit(void) {
	USB_DeviceClockInit();
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
    SYSMPU_Enable(SYSMPU, 0);
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

	/* Set ICCD generic to default state */
	g_UsbDeviceIccd.speed = USB_SPEED_FULL;
	g_UsbDeviceIccd.attach = 0U;
	g_UsbDeviceIccd.iccdHandle = (class_handle_t) NULL;
	g_UsbDeviceIccd.deviceHandle = NULL;
	g_UsbDeviceIccd.buffer[0] = (uint8_t*) &s_GenericBuffer0[0];
	g_UsbDeviceIccd.buffer[1] = (uint8_t*) &s_GenericBuffer1[0];

	/* Initialize the usb stack and class drivers */
	if (kStatus_USB_Success
			!= USB_DeviceClassInit(CONTROLLER_ID, &g_UsbDeviceIccdConfigList,
					&g_UsbDeviceIccd.deviceHandle)) {
		usb_echo("USB device ICCD failed\r\n");
		return;
	} else {
		usb_echo("USB device ICCD success\r\n");
		/* Get the ICCD class handle */
		g_UsbDeviceIccd.iccdHandle =
				g_UsbDeviceIccdConfigList.config->classHandle;
	}

	USB_DeviceIsrEnable();

	/* Start USB device ICCD generic */
	USB_DeviceRun(g_UsbDeviceIccd.deviceHandle);
}

int main(void)
{
	POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);

	CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

	RESET_PeripheralReset(kFC1_RST_SHIFT_RSTn);
	BOARD_InitBootPins();
	BOARD_InitBootClocks();
	BOARD_InitBootPeripherals();
	BOARD_InitDebugConsole();

	NVIC_ClearPendingIRQ(USB0_IRQn);
	NVIC_ClearPendingIRQ(USB0_NEEDCLK_IRQn);

	POWER_DisablePD(kPDRUNCFG_PD_USB0_PHY); /*< Turn on USB0 Phy */

	/* reset the IP to make sure it's in reset state. */
	RESET_PeripheralReset(kUSB0D_RST_SHIFT_RSTn);
	RESET_PeripheralReset(kUSB0HSL_RST_SHIFT_RSTn);
	RESET_PeripheralReset(kUSB0HMR_RST_SHIFT_RSTn);

	POWER_DisablePD(kPDRUNCFG_PD_USB0_PHY); /*< Turn on USB Phy */

	/* enable usb0 host clock */
	CLOCK_EnableClock(kCLOCK_Usbhsl0);
	/*According to reference manual, device mode setting has to be set by access usb host register */
	*((uint32_t *)(USBFSH_BASE + 0x5C)) |= USBFSH_PORTMODE_DEV_ENABLE_MASK;
	/* disable usb0 host clock */
	CLOCK_DisableClock(kCLOCK_Usbhsl0);

	usb_device_iccd_struct_t *iccdHandle;
	gpg_handle_struct_t gpgHandle;
	USB_DeviceApplicationInit();
	iccdHandle = (usb_device_iccd_struct_t*) g_UsbDeviceIccd.iccdHandle;
	uint8_t localStatusByte;

	gpg_init(&gpgHandle);
	while (1U) {
		if (iccdHandle->statusByte == 0x40U) { //process command
			localStatusByte = gpg_parse_cmd(&gpgHandle, inoutBuffer.buffer, inoutBuffer.length);
			if(localStatusByte == 0x40U) { //verified if no error during command parsing
				localStatusByte = gpg_dispatch(&gpgHandle);
			}
			inoutBuffer.buffer = gpgHandle.io.rspData; //Almost useless, pointed addresses should be the same
			inoutBuffer.length = gpgHandle.io.rspDataLen;
			iccdHandle->statusByte = localStatusByte;
		}
	}

	return -1;

}

