/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"

#if ((defined(USB_DEVICE_CONFIG_ICCD)) && (USB_DEVICE_CONFIG_ICCD > 0U))
#include "usb_device_iccd.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static usb_status_t USB_DeviceIccdAllocateHandle(
		usb_device_iccd_struct_t **handle);
static usb_status_t USB_DeviceIccdFreeHandle(usb_device_iccd_struct_t *handle);
static usb_status_t USB_DeviceIccdInterruptIn(usb_device_handle handle,
		usb_device_endpoint_callback_message_struct_t *message,
		void *callbackParam);
static usb_status_t USB_DeviceIccdInterruptOut(usb_device_handle handle,
		usb_device_endpoint_callback_message_struct_t *message,
		void *callbackParam);
static usb_status_t USB_DeviceIccdEndpointsInit(
		usb_device_iccd_struct_t *iccdHandle);
static usb_status_t USB_DeviceIccdEndpointsDeinit(
		usb_device_iccd_struct_t *iccdHandle);

/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_GLOBAL USB_RAM_ADDRESS_ALIGNMENT(USB_DATA_ALIGN_SIZE) static usb_device_iccd_struct_t s_UsbDeviceIccdHandle[USB_DEVICE_CONFIG_ICCD];

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Allocate a device iccd class handle.
 *
 * This function allocates a device iccd class handle.
 *
 * @param handle          It is out parameter, is used to return pointer of the device iccd class handle to the caller.
 *
 * @retval kStatus_USB_Success              Get a device iccd class handle successfully.
 * @retval kStatus_USB_Busy                 Cannot allocate a device iccd class handle.
 */
static usb_status_t USB_DeviceIccdAllocateHandle(
		usb_device_iccd_struct_t **handle) {
	uint32_t count;
	for (count = 0U; count < USB_DEVICE_CONFIG_ICCD; count++) {
		if (NULL == s_UsbDeviceIccdHandle[count].handle) {
			*handle = &s_UsbDeviceIccdHandle[count];
			return kStatus_USB_Success;
		}
	}

	return kStatus_USB_Busy;
}

/*!
 * @brief Free a device iccd class handle.
 *
 * This function frees a device iccd class handle.
 *
 * @param handle          The device iccd class handle.
 *
 * @retval kStatus_USB_Success              Free device iccd class handle successfully.
 */
static usb_status_t USB_DeviceIccdFreeHandle(usb_device_iccd_struct_t *handle) {
	handle->handle = NULL;
	handle->configStruct = (usb_device_class_config_struct_t*) NULL;
	handle->configuration = 0U;
	handle->alternate = 0U;
	return kStatus_USB_Success;
}

/*!
 * @brief Interrupt IN endpoint callback function.
 *
 * This callback function is used to notify uplayer the transfser result of a transfer.
 * This callback pointer is passed when the interrupt IN pipe initialized.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param message         The result of the interrupt IN pipe transfer.
 * @param callbackParam  The parameter for this callback. It is same with
 * usb_device_endpoint_callback_struct_t::callbackParam. In the class, the value is the ICCD class handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceIccdInterruptIn(usb_device_handle handle,
		usb_device_endpoint_callback_message_struct_t *message,
		void *callbackParam) {
	usb_device_iccd_struct_t *iccdHandle;
	usb_status_t error = kStatus_USB_Error;

	/* Get the ICCD class handle */
	iccdHandle = (usb_device_iccd_struct_t*) callbackParam;

	if (!iccdHandle) {
		return kStatus_USB_InvalidHandle;
	}
	iccdHandle->interruptInPipeBusy = 0U;
	if ((NULL != iccdHandle->configStruct)
			&& (iccdHandle->configStruct->classCallback)) {
		/* Notify the application data sent by calling the iccd class callback. classCallback is initialized
		 in classInit of s_UsbDeviceClassInterfaceMap,it is from the second parameter of classInit */
		error = iccdHandle->configStruct->classCallback(
				(class_handle_t) iccdHandle,
				kUSB_DeviceIccdEventNotifySlotChange, message);
	}

	return error;
}

/*!
 * @brief Interrupt OUT endpoint callback function.
 *
 * This callback function is used to notify uplayer the transfser result of a transfer.
 * This callback pointer is passed when the interrupt OUT pipe initialized.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param message         The result of the interrupt OUT pipe transfer.
 * @param callbackParam  The parameter for this callback. It is same with
 * usb_device_endpoint_callback_struct_t::callbackParam. In the class, the value is the ICCD class handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceIccdInterruptOut(usb_device_handle handle,
		usb_device_endpoint_callback_message_struct_t *message,
		void *callbackParam) {
	return kStatus_USB_NotSupported;
}

/*!
 * @brief Initialize the endpoints of the iccd class.
 *
 * This callback function is used to initialize the endpoints of the iccd class.
 *
 * @param iccdHandle          The device iccd class handle. It equals the value returned from
 * usb_device_class_config_struct_t::classHandle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceIccdEndpointsInit(
		usb_device_iccd_struct_t *iccdHandle) {
	usb_device_interface_list_t *interfaceList;
	usb_device_interface_struct_t *interface =
			(usb_device_interface_struct_t*) NULL;
	usb_status_t error = kStatus_USB_Error;
	int count;
	int index;

	/* Check the configuration is valid or not. */
	if (!iccdHandle->configuration) {
		return error;
	}

	if (iccdHandle->configuration
			> iccdHandle->configStruct->classInfomation->configurations) {
		return error;
	}

	/* Get the interface list of the new configuration. */
	if (NULL == iccdHandle->configStruct->classInfomation->interfaceList) {
		return error;
	}
	interfaceList =
			&iccdHandle->configStruct->classInfomation->interfaceList[iccdHandle->configuration
					- 1U];

	/* Find interface by using the alternate setting of the interface. */
	for (count = 0U; count < interfaceList->count; count++) {
		if (USB_DEVICE_CONFIG_ICCD_CLASS_CODE
				== interfaceList->interfaces[count].classCode) {
			for (index = 0U; index < interfaceList->interfaces[count].count;
					index++) {
				if (interfaceList->interfaces[count].interface[index].alternateSetting
						== iccdHandle->alternate) {
					interface =
							&interfaceList->interfaces[count].interface[index];
					break;
				}
			}
			iccdHandle->interfaceNumber =
					interfaceList->interfaces[count].interfaceNumber;
			break;
		}
	}
	if (!interface) {
		/* Return error if the interface is not found. */
		return error;
	}

	/* Keep new interface handle. */
	iccdHandle->interfaceHandle = interface;

	/* Initialize the endpoints of the new interface. */
	for (count = 0U; count < interface->endpointList.count; count++) {
		usb_device_endpoint_init_struct_t epInitStruct;
		usb_device_endpoint_callback_struct_t epCallback;
		epInitStruct.zlt = 0U;
		epInitStruct.interval =
				interface->endpointList.endpoint[count].interval;
		epInitStruct.endpointAddress =
				interface->endpointList.endpoint[count].endpointAddress;
		epInitStruct.maxPacketSize =
				interface->endpointList.endpoint[count].maxPacketSize;
		epInitStruct.transferType =
				interface->endpointList.endpoint[count].transferType;

		if (USB_IN
				== ((epInitStruct.endpointAddress
						& USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
				USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT)) {
			epCallback.callbackFn = USB_DeviceIccdInterruptIn;
			iccdHandle->interruptInPipeDataBuffer =
					(uint8_t*) USB_UNINITIALIZED_VAL_32;
			iccdHandle->interruptInPipeStall = 0U;
			iccdHandle->interruptInPipeDataLen = 0U;
		} else {
			epCallback.callbackFn = USB_DeviceIccdInterruptOut;
			iccdHandle->interruptOutPipeDataBuffer =
					(uint8_t*) USB_UNINITIALIZED_VAL_32;
			iccdHandle->interruptOutPipeStall = 0U;
			iccdHandle->interruptOutPipeDataLen = 0U;
		}
		epCallback.callbackParam = iccdHandle;

		error = USB_DeviceInitEndpoint(iccdHandle->handle, &epInitStruct,
				&epCallback);
	}
	return error;
}

/*!
 * @brief De-initialize the endpoints of the iccd class.
 *
 * This callback function is used to de-initialize the endpoints of the iccd class.
 *
 * @param iccdHandle          The device iccd class handle. It equals the value returned from
 * usb_device_class_config_struct_t::classHandle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceIccdEndpointsDeinit(
		usb_device_iccd_struct_t *iccdHandle) {
	usb_status_t error = kStatus_USB_Error;
	int count;

	if (!iccdHandle->interfaceHandle) {
		return error;
	}
	/* De-initialize all endpoints of the interface */
	for (count = 0U; count < iccdHandle->interfaceHandle->endpointList.count;
			count++) {
		error =
				USB_DeviceDeinitEndpoint(iccdHandle->handle,
						iccdHandle->interfaceHandle->endpointList.endpoint[count].endpointAddress);
	}
	iccdHandle->interfaceHandle = NULL;
	return error;
}

/*!
 * @brief Handle the event passed to the iccd class.
 *
 * This function handles the event passed to the iccd class.
 *
 * @param handle          The iccd class handle, got from the usb_device_class_config_struct_t::classHandle.
 * @param event           The event codes. Please refer to the enumeration usb_device_class_event_t.
 * @param param           The param type is determined by the event code.
 *
 * @return A USB error code or kStatus_USB_Success.
 * @retval kStatus_USB_Success              Free device handle successfully.
 * @retval kStatus_USB_InvalidParameter     The device handle not be found.
 * @retval kStatus_USB_InvalidRequest       The request is invalid, and the control pipe will be stalled by the caller.
 */
usb_status_t USB_DeviceIccdEvent(void *handle, uint32_t event, void *param) {
	usb_device_iccd_struct_t *iccdHandle;
	usb_status_t error = kStatus_USB_Error;
	uint16_t interfaceAlternate;
	int count;
	uint8_t *temp8;
	uint8_t alternate;

	if ((!param) || (!handle)) {
		return kStatus_USB_InvalidHandle;
	}

	/* Get the iccd class handle. */
	iccdHandle = (usb_device_iccd_struct_t*) handle;

	switch (event) {
	case kUSB_DeviceClassEventDeviceReset:
		/* Bus reset, clear the configuration. */
		iccdHandle->configuration = 0U;
		iccdHandle->interruptInPipeBusy = 0U;
		iccdHandle->interruptOutPipeBusy = 0U;
		iccdHandle->interfaceHandle = NULL;
		break;
	case kUSB_DeviceClassEventSetConfiguration:
		/* Get the new configuration. */
		temp8 = ((uint8_t*) param);
		if (!iccdHandle->configStruct) {
			break;
		}
		if (*temp8 == iccdHandle->configuration) {
			break;
		}

		/* De-initialize the endpoints when current configuration is none zero. */
		if (iccdHandle->configuration) {
			error = USB_DeviceIccdEndpointsDeinit(iccdHandle);
		}
		/* Save new configuration. */
		iccdHandle->configuration = *temp8;
		/* Clear the alternate setting value. */
		iccdHandle->alternate = 0U;

		/* Initialize the endpoints of the new current configuration by using the alternate setting 0. */
		error = USB_DeviceIccdEndpointsInit(iccdHandle);
		break;
	case kUSB_DeviceClassEventSetInterface:
		if (!iccdHandle->configStruct) {
			break;
		}
		/* Get the new alternate setting of the interface */
		interfaceAlternate = *((uint16_t*) param);
		/* Get the alternate setting value */
		alternate = (uint8_t) (interfaceAlternate & 0xFFU);

		/* Whether the interface belongs to the class. */
		if (iccdHandle->interfaceNumber
				!= ((uint8_t) (interfaceAlternate >> 8U))) {
			break;
		}
		/* Only handle new alternate setting. */
		if (alternate == iccdHandle->alternate) {
			break;
		}
		/* De-initialize old endpoints */
		error = USB_DeviceIccdEndpointsDeinit(iccdHandle);
		iccdHandle->alternate = alternate;
		/* Initialize new endpoints */
		error = USB_DeviceIccdEndpointsInit(iccdHandle);
		break;
	case kUSB_DeviceClassEventSetEndpointHalt:
		if ((!iccdHandle->configStruct) || (!iccdHandle->interfaceHandle)) {
			break;
		}
		/* Get the endpoint address */
		temp8 = ((uint8_t*) param);
		for (count = 0U;
				count < iccdHandle->interfaceHandle->endpointList.count;
				count++) {
			if (*temp8
					== iccdHandle->interfaceHandle->endpointList.endpoint[count].endpointAddress) {
				/* Only stall the endpoint belongs to the class */
				if (USB_IN
						== ((iccdHandle->interfaceHandle->endpointList.endpoint[count].endpointAddress
								&
								USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)
								>>
								USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT)) {
					iccdHandle->interruptInPipeStall = 1U;
				} else {
					iccdHandle->interruptOutPipeStall = 1U;
				}
				error = USB_DeviceStallEndpoint(iccdHandle->handle, *temp8);
			}
		}
		break;
	case kUSB_DeviceClassEventClearEndpointHalt:
		if ((!iccdHandle->configStruct) || (!iccdHandle->interfaceHandle)) {
			break;
		}
		/* Get the endpoint address */
		temp8 = ((uint8_t*) param);
		for (count = 0U;
				count < iccdHandle->interfaceHandle->endpointList.count;
				count++) {
			if (*temp8
					== iccdHandle->interfaceHandle->endpointList.endpoint[count].endpointAddress) {
				/* Only un-stall the endpoint belongs to the class */
				error = USB_DeviceUnstallEndpoint(iccdHandle->handle, *temp8);
				if (USB_IN
						== (((*temp8)
								& USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)
								>>
								USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT)) {
					if (iccdHandle->interruptInPipeStall) {
						iccdHandle->interruptInPipeStall = 0U;
						if ((uint8_t*) USB_UNINITIALIZED_VAL_32
								!= iccdHandle->interruptInPipeDataBuffer) {
							error =
									USB_DeviceSendRequest(iccdHandle->handle,
											(iccdHandle->interfaceHandle->endpointList.endpoint[count].endpointAddress
													&
													USB_DESCRIPTOR_ENDPOINT_ADDRESS_NUMBER_MASK),
											iccdHandle->interruptInPipeDataBuffer,
											iccdHandle->interruptInPipeDataLen);
							if (kStatus_USB_Success != error) {
								usb_device_endpoint_callback_message_struct_t endpointCallbackMessage;
								endpointCallbackMessage.buffer =
										iccdHandle->interruptInPipeDataBuffer;
								endpointCallbackMessage.length =
										iccdHandle->interruptInPipeDataLen;
								endpointCallbackMessage.isSetup = 0U;
								USB_DeviceIccdInterruptIn(iccdHandle->handle,
										(void*) &endpointCallbackMessage,
										handle);
							}
							iccdHandle->interruptInPipeDataBuffer =
									(uint8_t*) USB_UNINITIALIZED_VAL_32;
							iccdHandle->interruptInPipeDataLen = 0U;
						}
					}
				} else {
					if (iccdHandle->interruptOutPipeStall) {
						iccdHandle->interruptOutPipeStall = 0U;
						if ((uint8_t*) USB_UNINITIALIZED_VAL_32
								!= iccdHandle->interruptOutPipeDataBuffer) {
							error =
									USB_DeviceRecvRequest(iccdHandle->handle,
											(iccdHandle->interfaceHandle->endpointList.endpoint[count].endpointAddress
													&
													USB_DESCRIPTOR_ENDPOINT_ADDRESS_NUMBER_MASK),
											iccdHandle->interruptOutPipeDataBuffer,
											iccdHandle->interruptOutPipeDataLen);
							if (kStatus_USB_Success != error) {
								usb_device_endpoint_callback_message_struct_t endpointCallbackMessage;
								endpointCallbackMessage.buffer =
										iccdHandle->interruptOutPipeDataBuffer;
								endpointCallbackMessage.length =
										iccdHandle->interruptOutPipeDataLen;
								endpointCallbackMessage.isSetup = 0U;
								USB_DeviceIccdInterruptOut(iccdHandle->handle,
										(void*) &endpointCallbackMessage,
										handle);
							}
							iccdHandle->interruptOutPipeDataBuffer =
									(uint8_t*) USB_UNINITIALIZED_VAL_32;
							;
							iccdHandle->interruptOutPipeDataLen = 0U;
						}
					}
				}
			}
		}
		break;
	case kUSB_DeviceClassEventClassRequest:
		if (param) {
			/* Handle the iccd class specific request. */
			usb_device_control_request_struct_t *controlRequest =
					(usb_device_control_request_struct_t*) param;

			if ((controlRequest->setup->bmRequestType
					& USB_REQUEST_TYPE_RECIPIENT_MASK) !=
			USB_REQUEST_TYPE_RECIPIENT_INTERFACE) {
				break;
			}

			if ((controlRequest->setup->wIndex & 0xFFU)
					!= iccdHandle->interfaceNumber) {
				break;
			}

			usb_device_iccd_control_request_struct_t iccd_request;
			switch (controlRequest->setup->bRequest) {
			case USB_DEVICE_ICCD_REQUEST_ICC_POWER_ON:
				if (iccdHandle->configStruct->classCallback) {
					/* classCallback is initialized in classInit of s_UsbDeviceClassInterfaceMap,
					 it is from the second parameter of classInit */
					error = iccdHandle->configStruct->classCallback(
							(class_handle_t) iccdHandle,
							kUSB_DeviceIccdEventPowerOn, &iccd_request);
					if (kStatus_USB_Success == error) {
						controlRequest->buffer = iccd_request.buffer;
						controlRequest->length = iccd_request.length;
					}
				}
				break;
			case USB_DEVICE_ICCD_REQUEST_DATA_BLOCK:
				if (iccdHandle->configStruct->classCallback) {
					/* classCallback is initialized in classInit of s_UsbDeviceClassInterfaceMap,
					 it is from the second parameter of classInit */
					error = iccdHandle->configStruct->classCallback(
							(class_handle_t) iccdHandle,
							kUSB_DeviceIccdEventDataBlock, &iccd_request);
					if (kStatus_USB_Success == error) {
						controlRequest->buffer = iccd_request.buffer;
						controlRequest->length = iccd_request.length;
					}
				}
				break;
			case USB_DEVICE_ICCD_REQUEST_GET_ICC_STATUS:
				if (iccdHandle->configStruct->classCallback) {
					/* classCallback is initialized in classInit of s_UsbDeviceClassInterfaceMap,
					 it is from the second parameter of classInit */
					error = iccdHandle->configStruct->classCallback(
							(class_handle_t) iccdHandle,
							kUSB_DeviceIccdEventGetIccStatus, &iccd_request);
					if (kStatus_USB_Success == error) {
						controlRequest->buffer = iccd_request.buffer;
						controlRequest->length = iccd_request.length;
					}
				}
				break;
			case USB_DEVICE_ICCD_REQUEST_ICC_POWER_OFF:
				if (iccdHandle->configStruct->classCallback) {
					/* classCallback is initialized in classInit of s_UsbDeviceClassInterfaceMap,
					 it is from the second parameter of classInit */
					error = iccdHandle->configStruct->classCallback(
							(class_handle_t) iccdHandle,
							kUSB_DeviceIccdEventPowerOff,
							NULL);
				}
				break;

			case USB_DEVICE_ICCD_REQUEST_XFR_BLOCK:
				if (iccdHandle->configStruct->classCallback) {
					/* classCallback is initialized in classInit of s_UsbDeviceClassInterfaceMap,
					 it is from the second parameter of classInit */
					iccd_request.bLevelParameter = (controlRequest->setup->wValue>>8) & 0xFF;
					iccd_request.bInterface = controlRequest->setup->wIndex & 0xFF;
					iccd_request.length = controlRequest->setup->wLength;
					iccd_request.buffer = controlRequest->buffer;
					if (controlRequest->isSetup) {
						error = iccdHandle->configStruct->classCallback(
								(class_handle_t) iccdHandle,
								kUSB_DeviceIccdEventXfrRequestBuffer, &iccd_request);
						if (kStatus_USB_Success == error) {
							controlRequest->buffer = iccd_request.buffer;
							controlRequest->length = iccd_request.length;
						}
					} else {
						error = iccdHandle->configStruct->classCallback(
								(class_handle_t) iccdHandle,
								kUSB_DeviceIccdEventXfrBlock,
								&iccd_request);
					}
				}
				break;

			default:
				error = kStatus_USB_InvalidRequest;
				break;
			}
		}
	}
	return error;
}

/*!
 * @brief Initialize the iccd class.
 *
 * This function is used to initialize the iccd class.
 *
 * @param controllerId   The controller id of the USB IP. Please refer to the enumeration usb_controller_index_t.
 * @param config          The class configuration information.
 * @param handle          It is out parameter, is used to return pointer of the iccd class handle to the caller.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceIccdInit(uint8_t controllerId,
		usb_device_class_config_struct_t *config, class_handle_t *handle) {
	usb_device_iccd_struct_t *iccdHandle;
	usb_status_t error = kStatus_USB_Error;

	/* Allocate a iccd class handle. */
	error = USB_DeviceIccdAllocateHandle(&iccdHandle);

	if (kStatus_USB_Success != error) {
		return error;
	}

	/* Get the device handle according to the controller id. */
	error = USB_DeviceClassGetDeviceHandle(controllerId, &iccdHandle->handle);

	if (kStatus_USB_Success != error) {
		return error;
	}

	if (!iccdHandle->handle) {
		return kStatus_USB_InvalidHandle;
	}
	/* Save the configuration of the class. */
	iccdHandle->configStruct = config;
	/* Clear the configuration value. */
	iccdHandle->configuration = 0U;
	iccdHandle->alternate = 0xffU;
	iccdHandle->statusByte = 0x80U;

	*handle = (class_handle_t) iccdHandle;
	return error;
}

/*!
 * @brief De-initialize the device iccd class.
 *
 * The function de-initializes the device iccd class.
 *
 * @param handle The iccd class handle got from usb_device_class_config_struct_t::classHandle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceIccdDeinit(class_handle_t handle) {
	usb_device_iccd_struct_t *iccdHandle;
	usb_status_t error = kStatus_USB_Error;

	iccdHandle = (usb_device_iccd_struct_t*) handle;

	if (!iccdHandle) {
		return kStatus_USB_InvalidHandle;
	}
	/* De-initialzie the endpoints. */
	error = USB_DeviceIccdEndpointsDeinit(iccdHandle);
	/* Free the iccd class handle. */
	USB_DeviceIccdFreeHandle(iccdHandle);
	return error;
}

/*!
 * @brief Send data through a specified endpoint.
 *
 * The function is used to send data through a specified endpoint.
 * The function calls USB_DeviceSendRequest internally.
 *
 * @param handle The iccd class handle got from usb_device_class_config_struct_t::classHandle.
 * @param ep     Endpoint index.
 * @param buffer The memory address to hold the data need to be sent.
 * @param length The data length need to be sent.
 *
 * @return A USB error code or kStatus_USB_Success.
 *
 * @note The return value just means if the sending request is successful or not; the transfer done is notified by
 * USB_DeviceIccdInterruptIn.
 * Currently, only one transfer request can be supported for one specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for one specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer could begin only when the previous transfer is done (get notification through the endpoint
 * callback).
 */
usb_status_t USB_DeviceIccdSend(class_handle_t handle, uint8_t ep,
		uint8_t *buffer, uint32_t length) {
	usb_device_iccd_struct_t *iccdHandle;
	usb_status_t error = kStatus_USB_Error;

	if (!handle) {
		return kStatus_USB_InvalidHandle;
	}
	iccdHandle = (usb_device_iccd_struct_t*) handle;

	if (iccdHandle->interruptInPipeBusy) {
		return kStatus_USB_Busy;
	}
	iccdHandle->interruptInPipeBusy = 1U;

	if (iccdHandle->interruptInPipeStall) {
		iccdHandle->interruptInPipeDataBuffer = buffer;
		iccdHandle->interruptInPipeDataLen = length;
		return kStatus_USB_Success;
	}
	error = USB_DeviceSendRequest(iccdHandle->handle, ep, buffer, length);
	if (kStatus_USB_Success != error) {
		iccdHandle->interruptInPipeBusy = 0U;
	}
	return error;
}

/*!
 * @brief Receive data through a specified endpoint.
 *
 * The function is used to receive data through a specified endpoint.
 * The function calls USB_DeviceRecvRequest internally.
 *
 * @param handle The iccd class handle got from usb_device_class_config_struct_t::classHandle.
 * @param ep     Endpoint index.
 * @param buffer The memory address to save the received data.
 * @param length The data length want to be received.
 *
 * @return A USB error code or kStatus_USB_Success.
 *
 * @note The return value just means if the receiving request is successful or not; the transfer done is notified by
 * USB_DeviceIccdInterruptOut.
 * Currently, only one transfer request can be supported for one specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for one specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer could begin only when the previous transfer is done (get notification through the endpoint
 * callback).
 */
usb_status_t USB_DeviceIccdRecv(class_handle_t handle, uint8_t ep,
		uint8_t *buffer, uint32_t length) {
	usb_device_iccd_struct_t *iccdHandle;
	usb_status_t error = kStatus_USB_Error;

	if (!handle) {
		return kStatus_USB_InvalidHandle;
	}
	iccdHandle = (usb_device_iccd_struct_t*) handle;

	if (iccdHandle->interruptOutPipeBusy) {
		return kStatus_USB_Busy;
	}
	iccdHandle->interruptOutPipeBusy = 1U;

	if (iccdHandle->interruptOutPipeStall) {
		iccdHandle->interruptOutPipeDataBuffer = buffer;
		iccdHandle->interruptOutPipeDataLen = length;
		return kStatus_USB_Success;
	}
	error = USB_DeviceRecvRequest(iccdHandle->handle, ep, buffer, length);
	if (kStatus_USB_Success != error) {
		iccdHandle->interruptOutPipeBusy = 0U;
	}
	return error;
}

#endif
