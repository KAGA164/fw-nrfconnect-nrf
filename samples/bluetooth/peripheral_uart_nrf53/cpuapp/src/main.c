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

#include "bt_ser.h"
#include "rpmsg.h"

#include <bluetooth/uuid.h>
#include "gatt.h"
#include <hal/nrf_spu.h>

#define STACKSIZE CONFIG_BT_GATT_NUS_THREAD_STACK_SIZE
#define PRIORITY 7

#define RUN_STATUS_LED DK_LED1
#define RUN_LED_BLINK_INTERVAL 1000

#define CON_STATUS_LED DK_LED2

#define UART_BUF_SIZE CONFIG_BT_GATT_NUS_UART_BUFFER_SIZE

#define BT_ADDR_LE_STR_LEN 30

/** @brief UUID of the NUS Service. **/
#define NUS_UUID_SERVICE \
	BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

/** @brief UUID of the TX Characteristic. **/
#define NUS_UUID_NUS_TX_CHAR \
	BT_UUID_128_ENCODE(0x6e400003, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

/** @brief UUID of the RX Characteristic. **/
#define NUS_UUID_NUS_RX_CHAR \
	BT_UUID_128_ENCODE(0x6e400002, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

#define BT_UUID_NUS_SERVICE   BT_UUID_DECLARE_128(NUS_UUID_SERVICE)
#define BT_UUID_NUS_RX        BT_UUID_DECLARE_128(NUS_UUID_NUS_RX_CHAR)
#define BT_UUID_NUS_TX        BT_UUID_DECLARE_128(NUS_UUID_NUS_TX_CHAR)

static K_SEM_DEFINE(ble_init_ok, 0, 2);

static struct device *uart;

struct uart_data_t {
	void *fifo_reserved;
	u8_t data[UART_BUF_SIZE];
	u16_t len;
};

static K_FIFO_DEFINE(fifo_uart_tx_data);
static K_FIFO_DEFINE(fifo_uart_rx_data);

static void uart_cb(struct device *uart)
{
	static struct uart_data_t *rx;

	uart_irq_update(uart);

	if (uart_irq_rx_ready(uart)) {
		int data_length;

		if (!rx) {
			rx = k_malloc(sizeof(*rx));
			if (rx) {
				rx->len = 0;
			} else {
				char dummy;

				printk("Not able to allocate UART receive buffer\n");

				/* Drop one byte to avoid spinning in a
				 * eternal loop.
				 */
				uart_fifo_read(uart, &dummy, 1);

				return;
			}
		}

		data_length = uart_fifo_read(uart, &rx->data[rx->len],
		UART_BUF_SIZE - rx->len);
		rx->len += data_length;

		if (rx->len > 0) {
			/* Send buffer to bluetooth unit if either buffer size
			 * is reached or the char \n or \r is received, which
			 * ever comes first
			 */
			if ((rx->len == UART_BUF_SIZE) ||
			    (rx->data[rx->len - 1] == '\n') ||
			    (rx->data[rx->len - 1] == '\r')) {
				k_fifo_put(&fifo_uart_rx_data, rx);
				rx = NULL;
			}
		}
	}

	if (uart_irq_tx_ready(uart)) {
		struct uart_data_t *buf = k_fifo_get(&fifo_uart_tx_data,
						     K_NO_WAIT);
		u16_t written = 0;

		/* Nothing in the FIFO, nothing to send */
		if (!buf) {
			uart_irq_tx_disable(uart);
			return;
		}

		while (buf->len > written) {
			written += uart_fifo_fill(uart, &buf->data[written],
					buf->len - written);
		}

		while (!uart_irq_tx_complete(uart)) {
			/* Wait for the last byte to get
			 * shifted out of the module
			 */
		}

		if (k_fifo_is_empty(&fifo_uart_tx_data)) {
			uart_irq_tx_disable(uart);
		}

		k_free(buf);
	}
}

static int uart_init(void)
{
	uart = device_get_binding("UART_0");
	if (!uart) {
		return -ENXIO;
	}

	uart_irq_callback_set(uart, uart_cb);
	uart_irq_rx_enable(uart);

	return 0;
}

static void bt_connected(const bt_addr_le_t *addr, u8_t err)
{
	char addr_str[BT_ADDR_LE_STR_LEN];

	if (err) {
		printk("Connection failed (err %u)\n", err);
		return;
	}

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	printk("Connected %s\n", addr_str);

	dk_set_led_on(CON_STATUS_LED);
}

static void bt_disconnected(const bt_addr_le_t *addr, u8_t reason)
{
	char addr_str[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	printk("Disconnected: %s (reason %u)\n", addr_str, reason);

	dk_set_led_off(CON_STATUS_LED);
}

static void bt_received(const bt_addr_le_t *addr, const u8_t *data, size_t len)
{
	char addr_str[BT_ADDR_LE_STR_LEN] = { 0 };

	bt_addr_le_to_str(addr, addr_str, ARRAY_SIZE(addr_str));

	printk("Received data from: %s\n", addr_str);

	for (u16_t pos = 0; pos != len;) {
		struct uart_data_t *tx = k_malloc(sizeof(*tx));

		if (!tx) {
			printk("Not able to allocate UART send data buffer\n");
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

		k_fifo_put(&fifo_uart_tx_data, tx);
	}

	/* Start the UART transfer by enabling the TX ready interrupt */
	uart_irq_tx_enable(uart);
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
		printk("Cannot init LEDs (err: %d)\n", err);
	}
}

static ssize_t on_receive(struct bt_conn *conn,
			  const struct bt_gatt_attr *attr,
			  const void *buf,
			  u16_t len,
			  u16_t offset,
			  u8_t flags)
{
	//printk("Received data, handle %d, conn %p\n",
	//	attr->handle, conn);

	return len;
}

/* UART Service Declaration */
BT_GATT_SERVICE_DEFINE(nus_svc,
BT_GATT_PRIMARY_SERVICE(BT_UUID_NUS_SERVICE),
	BT_GATT_CHARACTERISTIC(BT_UUID_NUS_TX,
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ,
			       NULL, NULL, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_NUS_RX,
			       BT_GATT_CHRC_WRITE |
			       BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       NULL, on_receive, NULL),
);

static void led_blink_thread(void)
{
	int blink_status = 0;
	int err = 0;

	NRF_DCNF->EXTCODE[0].PROTECT = 0;


	nrf_spu_extdomain_set(NRF_SPU, 0, true, false);

	for (size_t i = 0; i < 64; i++) {
		nrf_spu_flashregion_set(NRF_SPU, i, true, 0x07, false);
		nrf_spu_ramregion_set(NRF_SPU, i, true, 0x07, false);
	}

	ipc_register_rx_callback(bt_nus_rx_parse);
	err = ipc_init();
	if (err) {
		printk("Rpmsg init error %d\n", err);
	}

	err = uart_init();
	if (err) {
		error();
	}

	configure_gpio();

	bt_nus_callback_register(&bt_nus_callbacks);

	err = bt_nus_init();
	if (err < 0) {
		printk("NUS service initialization failed\n");
		error();
	}

	printk("SVC: %p\n", &nus_svc);
	printk("Callback addr: %p\n", on_receive);
	err = bt_service_register(&nus_svc);
	if (err) {
		printk("NUS Service register error\n");
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
		printk("NUS send %d bytes status %d\n", buf->len, err);

		k_free(buf);
	}
}

K_THREAD_DEFINE(led_blink_thread_id, STACKSIZE, led_blink_thread, NULL, NULL,
		NULL, PRIORITY, 0, K_NO_WAIT);

K_THREAD_DEFINE(ble_write_thread_id, STACKSIZE, ble_write_thread, NULL, NULL,
		NULL, PRIORITY, 0, K_NO_WAIT);
