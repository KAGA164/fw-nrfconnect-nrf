/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/printk.h>
#include <sys/byteorder.h>
#include <zephyr.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include "temperature.h"

#include <logging/log.h>

LOG_MODULE_REGISTER(bt_temperature, CONFIG_BT_TEMPERATURE_LOG_LEVEL);

static bool notify_enabled;
static const struct bt_temperature_cb *cb;

static void temperature_ccc_cfg_changed(const struct bt_gatt_attr *attr,
					uint16_t value)
{
	notify_enabled = (value == BT_GATT_CCC_NOTIFY);
}

static ssize_t write_interval(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf,
			      uint16_t len, uint16_t offset, uint8_t flags)
{
	LOG_DBG("Attribute write, handle: %u, conn: %p", attr->handle, conn);

	if (cb->interval_cb) {
		cb->interval_cb(*(uint32_t *)buf);
	}

	return len;
}

static ssize_t read_temperature(struct bt_conn *conn,
				const struct bt_gatt_attr *attr,
				void *buf,
				uint16_t len,
			  	uint16_t offset)
{
	uint32_t temperature_value;

	LOG_DBG("Attribute read, handle: %u, conn: %p", attr->handle, conn);

	if (cb->temperature_cb) {
		temperature_value = cb->temperature_cb();
		return bt_gatt_attr_read(conn, attr, buf, len, offset, (void *) &temperature_value,
					 sizeof(temperature_value));
	}

	return 0;
}

/* Temperature Service Declaration */
BT_GATT_SERVICE_DEFINE(temperature_svc,
BT_GATT_PRIMARY_SERVICE(BT_UUID_CUSTOM_TEMP),
	BT_GATT_CHARACTERISTIC(BT_UUID_CUSTOM_TEMP_VALUE,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ, read_temperature, NULL, NULL),
	BT_GATT_CCC(temperature_ccc_cfg_changed,
		    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_CUSTOM_TEMP_INTERVAL,
			       BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_WRITE,
			       NULL, write_interval, NULL),
);

int bt_temperature_init(const struct bt_temperature_cb *callbacks)
{
	if (callbacks) {
		cb = callbacks;
	}

	return 0;
}

int bt_temperature_send_value(uint32_t temperature)
{
	if (!notify_enabled) {
		return -EACCES;
	}

	return bt_gatt_notify(NULL, &temperature_svc.attrs[2],
			      &temperature,
			      sizeof(temperature));
}
