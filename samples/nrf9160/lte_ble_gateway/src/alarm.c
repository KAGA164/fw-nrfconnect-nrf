/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/printk.h>
#include <net/nrf_cloud.h>

#include "alarm.h"

#include "aggregator.h"

static bool alarm_pending;

extern void sensor_data_send(struct nrf_cloud_sensor_data *data);

void alarm(void)
{
	alarm_pending = true;
}

void send_aggregated_data(void)
{
	uint32_t temp;
	static uint8_t temperature_buf[128];
	static uint8_t gps_data_buffer[GPS_NMEA_SENTENCE_MAX_LENGTH];

	static struct nrf_cloud_sensor_data gps_cloud_data = {
		.type = NRF_CLOUD_SENSOR_GPS,
		.data.ptr = gps_data_buffer,
	};

	static struct nrf_cloud_sensor_data temperature_cloud_data = {
		.type = NRF_CLOUD_SENSOR_TEMP,
	};

	struct sensor_data aggregator_data;

	if (!alarm_pending) {
		return;
	}

	alarm_pending = false;

	printk("Alarm triggered !\n");
	while (1) {
		if (aggregator_get(&aggregator_data) == -ENODATA) {
			break;
		}
		switch (aggregator_data.type) {
		case TEMPERATURE:
			printk("%d] Sending temperature data.\n",
			       aggregator_element_count_get());
			if (aggregator_data.length != sizeof(temp)) {
				printk("Unexpected temperature data format, dropping\n");
				continue;
			}

			temp = sys_get_le32(aggregator_data.data);

			sprintf(temperature_buf, "%d.%d", temp / 10, temp % 10);
			temperature_cloud_data.data.ptr =
				temperature_buf;
			temperature_cloud_data.data.len = strlen(
				temperature_buf);
			sensor_data_send(&temperature_cloud_data);
			break;

		case GPS_POSITION:
			printk("%d] Sending GPS data.\n",
			       aggregator_element_count_get());
			gps_cloud_data.data.ptr = &aggregator_data.data[4];
			gps_cloud_data.data.len = aggregator_data.length;
			gps_cloud_data.tag =
			    *((uint32_t *)&aggregator_data.data[0]);
			sensor_data_send(&gps_cloud_data);
			break;

		default:
			printk("Unsupported data type from aggregator: %d.\n",
			       aggregator_data.type);
			continue;
		}
	}
}
