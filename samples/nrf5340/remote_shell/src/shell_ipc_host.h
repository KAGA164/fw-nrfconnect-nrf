/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SHELL_IPC_HOST_H_
#define SHELL_IPC_HOST_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
        extern "C" {
#endif

typedef void (*shell_ipc_host_recv_cb)(const uint8_t *data, size_t len, void *context);

int shell_ipc_host_init(shell_ipc_host_recv_cb cb, void *context);

int shell_ipc_host_write(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_IPC_HOST_H_ */
