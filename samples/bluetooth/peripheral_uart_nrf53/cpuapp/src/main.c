/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/** @file
 *  @brief Nordic UART Bridge Service (NUS) sample
 */

#include <drivers/uart.h>
#include <zephyr/types.h>
#include <zephyr.h>

#include <device.h>
#include <soc.h>

#include <dk_buttons_and_leds.h>

#include <stdio.h>
#include <string.h>
#include <init.h>

#include <logging/log.h>

LOG_MODULE_REGISTER(peripheral_uart_nrf53);

#include "serialization.h"

#define STACKSIZE CONFIG_BT_GATT_NUS_THREAD_STACK_SIZE
#define PRIORITY 7

#define RUN_STATUS_LED DK_LED1
#define RUN_LED_BLINK_INTERVAL 1000

#define CON_STATUS_LED DK_LED2

#define UART_BUF_SIZE CONFIG_BT_GATT_NUS_UART_BUFFER_SIZE
#define UART_WAIT_FOR_BUF_DELAY 50
#define UART_WAIT_FOR_RX CONFIG_BT_GATT_NUS_UART_RX_WAIT_TIME

#define BT_ADDR_LE_STR_LEN 30

static K_SEM_DEFINE(ble_init_ok, 0, 2);

static struct device *uart;
static struct k_delayed_work uart_work;

struct uart_data_t {
	void *fifo_reserved;
	u8_t data[UART_BUF_SIZE];
	u16_t len;
};

static K_FIFO_DEFINE(fifo_uart_tx_data);
static K_FIFO_DEFINE(fifo_uart_rx_data);

static int bt_addr_le_to_str(const bt_addr_le_t *addr, char *str,
			     size_t len)
{
	char type[10];

	switch (addr->type) {
	case BT_ADDR_LE_PUBLIC:
		strcpy(type, "public");
		break;
	case BT_ADDR_LE_RANDOM:
		strcpy(type, "random");
		break;
	case BT_ADDR_LE_PUBLIC_ID:
		strcpy(type, "public-id");
		break;
	case BT_ADDR_LE_RANDOM_ID:
		strcpy(type, "random-id");
		break;
	default:
		snprintk(type, sizeof(type), "0x%02x", addr->type);
		break;
	}

	return snprintk(str, len, "%02X:%02X:%02X:%02X:%02X:%02X (%s)",
			addr->a.val[5], addr->a.val[4], addr->a.val[3],
			addr->a.val[2], addr->a.val[1], addr->a.val[0], type);
}

static void uart_cb(struct uart_event *evt, void *user_data)
{
	static u8_t *current_buf;
	static size_t aborted_len;
	static bool buf_release;
	struct uart_data_t *buf;
	static u8_t *aborted_buf;

	switch (evt->type) {
	case UART_TX_DONE:
		if ((evt->data.tx.len == 0) ||
		    (!evt->data.tx.buf)) {
			return;
		}

		if (aborted_buf) {
			buf = CONTAINER_OF(aborted_buf, struct uart_data_t,
					   data);
			aborted_buf = NULL;
			aborted_len = 0;
		} else {
			buf = CONTAINER_OF(evt->data.tx.buf, struct uart_data_t,
					   data);
		}

		k_free(buf);

		buf = k_fifo_get(&fifo_uart_tx_data, K_NO_WAIT);
		if (!buf) {
			return;
		}

		if (uart_tx(uart, buf->data, buf->len, K_FOREVER)) {
			LOG_WRN("Failed to send data over UART");
		}

		break;

	case UART_RX_RDY:
		buf = CONTAINER_OF(evt->data.rx.buf, struct uart_data_t, data);
		buf->len += evt->data.rx.len;
		buf_release = false;

		if (buf->len == UART_BUF_SIZE) {
			k_fifo_put(&fifo_uart_rx_data, buf);
		} else if ((evt->data.rx.buf[buf->len - 1] == '\n') ||
			  (evt->data.rx.buf[buf->len - 1] == '\r')) {
			k_fifo_put(&fifo_uart_rx_data, buf);
			current_buf = evt->data.rx.buf;
			buf_release = true;
			uart_rx_disable(uart);
		}

		break;

	case UART_RX_DISABLED:
		buf = k_malloc(sizeof(*buf));
		if (buf) {
			buf->len = 0;
		} else {
			LOG_WRN("Not able to allocate UART receive buffer");
			k_delayed_work_submit(&uart_work,
					      UART_WAIT_FOR_BUF_DELAY);
			return;
		}

		uart_rx_enable(uart, buf->data, sizeof(buf->data),
			       UART_WAIT_FOR_RX);

		break;

	case UART_RX_BUF_REQUEST:
		buf = k_malloc(sizeof(*buf));
		if (buf) {
			buf->len = 0;
			uart_rx_buf_rsp(uart, buf->data, sizeof(buf->data));
		} else {
			LOG_WRN("Not able to allocate UART receive buffer");
		}

		break;

	case UART_RX_BUF_RELEASED:
		buf = CONTAINER_OF(evt->data.rx_buf.buf, struct uart_data_t,
				   data);
		if (buf_release && (current_buf != evt->data.rx_buf.buf)) {
			k_free(buf);
			buf_release = false;
			current_buf = NULL;
		}

		break;

	case UART_TX_ABORTED:
			if (!aborted_buf) {
				aborted_buf = (u8_t *)evt->data.tx.buf;
			}

			aborted_len += evt->data.tx.len;
			buf = CONTAINER_OF(aborted_buf, struct uart_data_t,
					   data);

			uart_tx(uart, &buf->data[aborted_len],
				buf->len - aborted_len, K_FOREVER);

		break;

	default:
		break;
	}
}

static void uart_work_handler(struct k_work *item)
{
	struct uart_data_t *buf;

	buf = k_malloc(sizeof(*buf));
	if (buf) {
		buf->len = 0;
	} else {
		LOG_WRN("Not able to allocate UART receive buffer");
		k_delayed_work_submit(&uart_work, UART_WAIT_FOR_BUF_DELAY);
		return;
	}

	uart_rx_enable(uart, buf->data, sizeof(buf->data), UART_WAIT_FOR_RX);
}

static int uart_init(void)
{
	int err;
	struct uart_data_t *rx;
	uart = device_get_binding("UART_0");
	if (!uart) {
		return -ENXIO;
	}

	rx = k_malloc(sizeof(*rx));
	if (rx) {
		rx->len = 0;
	} else {
		return -ENOMEM;
	}

	k_delayed_work_init(&uart_work, uart_work_handler);

	err = uart_callback_set(uart, uart_cb, NULL);
	if (err) {
		return err;
	}

	return uart_rx_enable(uart, rx->data, sizeof(rx->data), 50);
}

static void bt_connected(const bt_addr_le_t *addr, u8_t err)
{
	char addr_str[BT_ADDR_LE_STR_LEN];

	if (err) {
		LOG_ERR("Connection failed (err %u)", err);
		return;
	}

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	LOG_INF("Connected %s", log_strdup(addr_str));

	dk_set_led_on(CON_STATUS_LED);
}

static void bt_disconnected(const bt_addr_le_t *addr, u8_t reason)
{
	char addr_str[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	LOG_INF("Disconnected: %s (reason %u)", log_strdup(addr_str),
		reason);

	dk_set_led_off(CON_STATUS_LED);
}

static void bt_received(const bt_addr_le_t *addr, const u8_t *data, size_t len)
{
	int err;
	char addr_str[BT_ADDR_LE_STR_LEN] = { 0 };

	bt_addr_le_to_str(addr, addr_str, ARRAY_SIZE(addr_str));

	LOG_INF("Received data from: %s", log_strdup(addr_str));

	for (u16_t pos = 0; pos != len;) {
		struct uart_data_t *tx = k_malloc(sizeof(*tx));

		if (!tx) {
			LOG_WRN("Not able to allocate UART send data buffer");
			return;
		}

		/* Keep the last byte of TX buffer for potential LF char. */
		size_t tx_data_size = sizeof(tx->data) - 1;

		if ((len - pos) > tx_data_size) {
			tx->len = tx_data_size;
		} else {
			tx->len = (len - pos);
		}

		memcpy(tx->data, &data[pos], tx->len);

		pos += tx->len;

		/* Append the LF character when the CR character triggered
		 * transmission from the peer.
		 */
		if ((pos == len) && (data[len - 1] == '\r')) {
			tx->data[tx->len] = '\n';
			tx->len++;
		}

		err = uart_tx(uart, tx->data, tx->len, K_FOREVER);
		if (err) {
			k_fifo_put(&fifo_uart_tx_data, tx);
		}
	}
}

static const struct bt_nus_cb bt_nus_callbacks = {
	.bt_connected    = bt_connected,
	.bt_disconnected = bt_disconnected,
	.bt_received = bt_received,
};

void error(void)
{
	dk_set_leds_state(DK_ALL_LEDS_MSK, DK_NO_LEDS_MSK);

	while (true) {
		/* Spin for ever */
		k_sleep(1000);
	}
}

static void configure_gpio(void)
{
	int err;

	err = dk_leds_init();
	if (err) {
		LOG_WRN("Cannot init LEDs (err: %d)", err);
	}
}

void main(void)
{
	int blink_status = 0;
	int err = 0;

	err = uart_init();
	if (err) {
		error();
	}

	configure_gpio();

	bt_nus_callback_register(&bt_nus_callbacks);

	err = bt_nus_init();
	if (err < 0) {
		LOG_ERR("NUS service initialization failed: %d", err);
		error();
	}

	k_sem_give(&ble_init_ok);

	printk("Starting Nordic UART service example[APP CORE]\n");

	for (;;) {
		dk_set_led(RUN_STATUS_LED, (++blink_status) % 2);
		k_sleep(RUN_LED_BLINK_INTERVAL);
	}
}

void ble_write_thread(void)
{
	int err = 0;
	/* Don't go any further until BLE is initailized */
	k_sem_take(&ble_init_ok, K_FOREVER);

	for (;;) {
		/* Wait indefinitely for data to be sent over bluetooth */
		struct uart_data_t *buf = k_fifo_get(&fifo_uart_rx_data,
						     K_FOREVER);

		err = bt_nus_transmit(buf->data, buf->len);
		LOG_INF("NUS send %d bytes status %d", buf->len, err);

		k_free(buf);
	}
}

K_THREAD_DEFINE(ble_write_thread_id, STACKSIZE, ble_write_thread, NULL, NULL,
		NULL, PRIORITY, 0, K_NO_WAIT);
