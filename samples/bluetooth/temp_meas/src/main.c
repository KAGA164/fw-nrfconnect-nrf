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
#include <drivers/gpio.h>
#include <drivers/adc.h>
#include <soc.h>

#include <hal/nrf_saadc.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include <settings/settings.h>

#include <dk_buttons_and_leds.h>

#include "temperature.h"

#define DEVICE_NAME             CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN         (sizeof(DEVICE_NAME) - 1)

#define RUN_STATUS_LED          DK_LED1
#define CON_STATUS_LED          DK_LED2

#define ADC_DEVICE_NAME		DT_LABEL(DT_NODELABEL(adc))
#define ADC_RESOLUTION		12
#define ADC_OVERSAMPLING	4 /* 2^ADC_OVERSAMPLING samples are averaged */
#define ADC_MAX 		4096
#define ADC_GAIN		ADC_GAIN_1_6
#define ADC_REFERENCE		ADC_REF_INTERNAL
#define ADC_ACQUISITION_TIME	ADC_ACQ_TIME_DEFAULT
#define ADC_CHANNEL_ID		1
#define ADC_CHANNEL_INPUT	NRF_SAADC_INPUT_AIN1

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

static const struct bt_data sd[] = {
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_CUSTOM_TEMP_VAL),
};

static const struct device *adc_dev;
static int16_t adc_buffer;
static uint32_t meas_interval = 1000;

static int adc_init(void)
{
	int err;

	adc_dev = device_get_binding(ADC_DEVICE_NAME);
	if (!adc_dev) {
		printk("Cannot get ADC device\n");
		return -ENXIO;
	}

	static const struct adc_channel_cfg channel_cfg = {
		.gain             = ADC_GAIN,
		.reference        = ADC_REFERENCE,
		.acquisition_time = ADC_ACQUISITION_TIME,
		.channel_id       = ADC_CHANNEL_ID,
#if defined(CONFIG_ADC_CONFIGURABLE_INPUTS)
		.input_positive   = ADC_CHANNEL_INPUT,
#endif
	};

	err = adc_channel_setup(adc_dev, &channel_cfg);
	if (err) {
		printk("Setting up the ADC channel failed\n");
		return err;
	}

	return 0;
}

static int temperature_measure(uint32_t *temperature)
{
	int err;
	int32_t val = 0;

	static const struct adc_sequence sequence = {
		.options	= NULL,
		.channels	= BIT(ADC_CHANNEL_ID),
		.buffer		= &adc_buffer,
		.buffer_size	= sizeof(adc_buffer),
		.resolution	= ADC_RESOLUTION,
		.oversampling	= ADC_OVERSAMPLING,
		.calibrate	= false,
	};

	err = adc_read(adc_dev, &sequence);
	if (err) {
		printk("Temperature read failed\n");
		return err;
	}

	val = adc_buffer;

	err = adc_raw_to_millivolts(adc_ref_internal(adc_dev),
				    ADC_GAIN,
				    ADC_RESOLUTION,
				    &val);
	if (err) {
		printk("Cannot calculate temperature value in mV\n");
		return err;
	}

	*temperature = ((val * 147) - (1375 * 100)) / (225);

	return 0;
}


static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		printk("Connection failed (err %u)\n", err);
		return;
	}

	printk("Connected\n");

	dk_set_led_on(CON_STATUS_LED);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	printk("Disconnected (reason %u)\n", reason);

	dk_set_led_off(CON_STATUS_LED);
}

static void security_changed(struct bt_conn *conn, bt_security_t level,
			     enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!err) {
		printk("Security changed: %s level %u\n", addr, level);
	} else {
		printk("Security failed: %s level %u err %d\n", addr, level,
			err);
	}
}
static struct bt_conn_cb conn_callbacks = {
	.connected        = connected,
	.disconnected     = disconnected,
	.security_changed = security_changed,
};

static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	printk("Passkey for %s: %06u\n", addr, passkey);
}

static void auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	printk("Pairing cancelled: %s\n", addr);
}

static void pairing_confirm(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	bt_conn_auth_pairing_confirm(conn);

	printk("Pairing confirmed: %s\n", addr);
}

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	printk("Pairing completed: %s, bonded: %d\n", addr, bonded);
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	printk("Pairing failed conn: %s, reason %d\n", addr, reason);
}

static struct bt_conn_auth_cb conn_auth_callbacks = {
	.passkey_display = auth_passkey_display,
	.cancel = auth_cancel,
	.pairing_confirm = pairing_confirm,
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed
};

static void temperature_meas_interval_change(const uint32_t interval)
{
	printk("Received measurement interval: %d ms\n", interval);

	meas_interval = interval;
}

static uint32_t temperature_read(void)
{
	int err;
	uint32_t temp;

	err = temperature_measure(&temp);
	if (err) {
		printk("Temperature measure failed (err %d)\n", err);
		return 0;
	}

	printk("Read temperature value: %d.%d C\n", temp / 10, temp % 10);

	return temp;
}

static const struct bt_temperature_cb temperature_callbacks = {
	.interval_cb = temperature_meas_interval_change,
	.temperature_cb = temperature_read
};

void main(void)
{
	int blink_status = 0;
	int err;

	printk("Starting Bluetooth temperature measurements\n");

	err = dk_leds_init();
	if (err) {
		printk("LEDs init failed (err %d)\n", err);
		return;
	}

	err = adc_init();
	if (err) {
		printk("ADC init failed (err %d)\n", err);
		return;
	}

	bt_conn_cb_register(&conn_callbacks);
	if (IS_ENABLED(CONFIG_BT_LBS_SECURITY_ENABLED)) {
		bt_conn_auth_cb_register(&conn_auth_callbacks);
	}

	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return;
	}

	printk("Bluetooth initialized\n");

	if (IS_ENABLED(CONFIG_SETTINGS)) {
		settings_load();
	}

	err = bt_temperature_init(&temperature_callbacks);
	if (err) {
		printk("Failed to init LBS (err:%d)\n", err);
		return;
	}

	err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad),
			      sd, ARRAY_SIZE(sd));
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
		return;
	}

	printk("Advertising successfully started\n");

	for (;;) {
		uint32_t temp = 0;

		dk_set_led(RUN_STATUS_LED, (++blink_status) % 2);

		err = temperature_measure(&temp);
		if (err) {
			printk("Temperature measure failed (err %d)\n", err);
		}

		printk("Temperature: %d.%d C\n", (temp / 10), (temp % 10));

		bt_temperature_send_value(temp);

		k_sleep(K_MSEC(meas_interval));
	}
}
