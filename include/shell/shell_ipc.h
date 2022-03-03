/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <kernel.h>
#include <ipc/ipc_service.h>
#include <shell/shell.h>
#include <sys/ring_buffer.h>

#ifndef SHELL_IPC_H_
#define SHELL_IPC_H_

#ifdef __cplusplus
extern "C" {
#endif

struct shell_ipc {
        struct ipc_ept_cfg ept_cfg;

        struct ipc_ept ept;

        struct k_sem ept_bond_sem;

        shell_transport_handler_t handler;

        void *context;

        struct ring_buf *rx_ringbuf;
};

extern const struct shell_transport_api shell_ipc_transport_api;

#define SHELL_IPC_DEFINE(_name, _rx_ring_buffer_size) \
        RING_BUF_DECLARE(_name##_rx_ring_buffer, _rx_ring_buffer_size); \
                                                                    \
        static struct shell_ipc _name##shell_ipc = { \
                .rx_ringbuf = &_name##_rx_ring_buffer \
        }; \
                                            \
        struct shell_transport _name = { \
               .api = &shell_ipc_transport_api, \
               .ctx = &_name##shell_ipc \
        }

const struct shell *shell_backend_ipc_get_ptr(void);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_IPC_H_ */
