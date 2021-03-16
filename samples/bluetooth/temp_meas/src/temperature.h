/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef TEMPERATURE_H_
#define TEMPERATURE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <zephyr/types.h>

/** @brief Temperature Service UUID. */
#define BT_UUID_CUSTOM_TEMP_VAL \
	BT_UUID_128_ENCODE(0x00001652, 0x741b, 0x4f7d, 0xadca, 0xe83cefb68df0)

/** @brief Temperature values Characteristic UUID. */
#define BT_UUID_CUSTOM_TEMP_VALUE_VAL \
	BT_UUID_128_ENCODE(0x00001653, 0x741b, 0x4f7d, 0xadca, 0xe83cefb68df0)

/** @brief Measurement interval Characteristic UUID. */
#define BT_UUID_CUSTOM_TEMP_INTERVAL_VAL \
	BT_UUID_128_ENCODE(0x00001654, 0x741b, 0x4f7d, 0xadca, 0xe83cefb68df0)

#define BT_UUID_CUSTOM_TEMP          BT_UUID_DECLARE_128(BT_UUID_CUSTOM_TEMP_VAL)
#define BT_UUID_CUSTOM_TEMP_VALUE    BT_UUID_DECLARE_128(BT_UUID_CUSTOM_TEMP_VALUE_VAL)
#define BT_UUID_CUSTOM_TEMP_INTERVAL BT_UUID_DECLARE_128(BT_UUID_CUSTOM_TEMP_INTERVAL_VAL)


/** @brief Callback type for when a temperature interval is received */
typedef void (*temperature_interval_cb_t)(const uint32_t interval);

/** @brief Callback type for when a temperature value is requested. */
typedef uint32_t (*temperature_cb_t)(void);

/** @brief Callback struct used by the Temperature Service. */
struct bt_temperature_cb {
	/** Temperature interval change callback. */
	temperature_interval_cb_t interval_cb;
	/** Temperature read callback. */
	temperature_cb_t temperature_cb;
};

/** @brief Initialize the Temperature Service.
 *
 * This function registers a GATT service with two characteristics: Temperature value
 * and Temperature measurement interval.
 * Send notifications for the Temperature value to let connected peers know
 * what is a current temperature value.
 * Write to the Temperature measurement characteristic to change the temperature measurement
 * interval board.
 *
 * @param[in] callbacks Struct containing pointers to callback functions
 *			used by the service. This pointer can be NULL
 *			if no callback functions are defined.
 *
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int bt_temperature_init(const struct bt_temperature_cb *callbacks);

/** @brief Send the temperature value.
 *
 * This function sends a temperature value, to all connected peers.
 *
 * @param[in] temperature The current temperature value.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int bt_temperature_send_value(uint32_t temperature);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* TEMPERATURE_H_ */
