/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2017 NXP
 * Copyright 2021, Michael Grand
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef USB_DEVICE_ICCD_H_
#define USB_DEVICE_ICCD_H_

/*! @brief The class code of the HID class */
#define USB_DEVICE_CONFIG_ICCD_CLASS_CODE (0x00U)

#define USB_DEVICE_ICCD_REQUEST_ICC_POWER_ON 0x62U		///IN Exits the initial state of a USB-ICC. Returns the ATR in the data stage.
#define USB_DEVICE_ICCD_REQUEST_ICC_POWER_OFF 0x63U		///OUTSets the USB-ICC to initial conditions.
#define USB_DEVICE_ICCD_REQUEST_XFR_BLOCK 0x65U			///OUT Data transfer from the host to the USB-ICC
#define USB_DEVICE_ICCD_REQUEST_DATA_BLOCK 0x6FU		///IN Data transfer from the USB-ICC to the host
#define USB_DEVICE_ICCD_REQUEST_GET_ICC_STATUS 0xA0U	///IN Returns the status of the command execution.

typedef enum _usb_device_iccd_event {
	kUSB_DeviceIccdEventPowerOn, /*!< power on */
	kUSB_DeviceIccdEventPowerOff, /*!< power off */
	kUSB_DeviceIccdEventXfrRequestBuffer, /*!< Request buffer to store incoming data */
	kUSB_DeviceIccdEventXfrBlock, /*!< Receive command */
	kUSB_DeviceIccdEventDataBlock, /*!< Send response */
	kUSB_DeviceIccdEventGetIccStatus, /*!< Return status word */
	kUSB_DeviceIccdEventNotifySlotChange, /*!< USB-ICC virtually removed */
} usb_device_iccd_event_t;

/*! @brief The ICCD device class status structure */
typedef struct _usb_device_iccd_struct {
	 usb_device_handle handle;                       /*!< The device handle */
	    usb_device_class_config_struct_t *configStruct; /*!< The configuration of the class. */
	    usb_device_interface_struct_t *interfaceHandle; /*!< Current interface handle */
	    uint8_t *interruptInPipeDataBuffer;             /*!< IN pipe data buffer backup when stall */
	    uint32_t interruptInPipeDataLen;                /*!< IN pipe data length backup when stall  */
	    uint8_t *interruptOutPipeDataBuffer;             /*!< OUT pipe data buffer backup when stall */
	    uint32_t interruptOutPipeDataLen;                /*!< OUT pipe data length backup when stall  */
	    uint8_t configuration;                          /*!< Current configuration */
	    uint8_t interfaceNumber;                        /*!< The interface number of the class */
	    uint8_t alternate;                              /*!< Current alternate setting of the interface */
	    uint8_t idleRate;                               /*!< The idle rate of the HID device */
	    uint8_t protocol;                               /*!< Current protocol */
	    uint8_t interruptInPipeBusy;                    /*!< Interrupt IN pipe busy flag */
	    uint8_t interruptOutPipeBusy;                   /*!< Interrupt OUT pipe busy flag */
	    uint8_t interruptInPipeStall;                    /*!< Interrupt IN pipe stall flag */
	    uint8_t interruptOutPipeStall;                   /*!< Interrupt OUT pipe stall flag */
	    volatile uint8_t statusByte;								/*!< ICCD Statut Byte */
} usb_device_iccd_struct_t;

typedef struct _usb_device_iccd_control_request_struct {
	uint8_t *buffer; /*!< The buffer address */
	size_t length; /*!< The data length */
	uint8_t bLevelParameter;
	uint8_t bInterface;
} usb_device_iccd_control_request_struct_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Initialize the ICCD class.
 *
 * This function is used to initialize the ICCD class. This function only can be called by #USB_DeviceClassInit.
 *
 * @param[in] controllerId   The controller ID of the USB IP. See the enumeration #usb_controller_index_t.
 * @param[in] config          The class configuration information.
 * @param[out] handle          An out parameter used to return pointer of the video class handle to the caller.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
extern usb_status_t USB_DeviceIccdInit(uint8_t controllerId,
		usb_device_class_config_struct_t *config, class_handle_t *handle);

/*!
 * @brief Deinitializes the device ICCD class.
 *
 * The function deinitializes the device ICCD class. This function can only be called by #USB_DeviceClassDeinit.
 *
 * @param[in] handle The ICCD class handle received from usb_device_class_config_struct_t::classHandle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
extern usb_status_t USB_DeviceIccdDeinit(class_handle_t handle);

/*!
 * @brief Handles the event passed to the ICCD class.
 *
 * This function handles the event passed to the ICCD class. This function can only be called by #USB_DeviceClassEvent.
 *
 * @param[in] handle          The ICCD class handle, received from the usb_device_class_config_struct_t::classHandle.
 * @param[in] event           The event codes. See the enumeration #usb_device_class_event_t.
 * @param[in,out] param           The parameter type is determined by the event code.
 *
 * @return A USB error code or kStatus_USB_Success.
 * @retval kStatus_USB_Success              Free device handle successfully.
 * @retval kStatus_USB_InvalidParameter     The device handle not be found.
 * @retval kStatus_USB_InvalidRequest       The request is invalid and the control pipe is stalled by the caller.
 */
extern usb_status_t USB_DeviceIccdEvent(void *handle, uint32_t event,
		void *param);

/*! @}*/

#if defined(__cplusplus)
}
#endif

/*! @}*/

#endif /* USB_DEVICE_ICCD_H_ */
