/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <nrf_rpc_cbor.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/conn.h"

#include "bt_rpc_common.h"
#include "serialize.h"
#include "cbkproxy.h"

static void report_decoding_error(uint8_t cmd_evt_id, void *data)
{
	nrf_rpc_err(-EBADMSG, NRF_RPC_ERR_SRC_RECV, &bt_rpc_grp, cmd_evt_id,
		    NRF_RPC_PACKET_TYPE_CMD);
}

#define LOCK_CONN_INFO() k_mutex_lock(&bt_rpc_conn_mutex, K_FOREVER)
#define UNLOCK_CONN_INFO() k_mutex_unlock(&bt_rpc_conn_mutex)

static K_MUTEX_DEFINE(bt_rpc_conn_mutex);

struct bt_conn {
	atomic_t ref;
	uint8_t features[8];
	bt_addr_le_t src;
	bt_addr_le_t dst;
	bt_addr_le_t local;
	bt_addr_le_t remote;
#if defined(CONFIG_BT_USER_PHY_UPDATE)
	struct bt_conn_le_phy_info phy;
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
	struct bt_conn_le_data_len_info data_len;
#endif /* defined(CONFIG_BT_USER_DATA_LEN_UPDATE) */
#if defined(CONFIG_BT_SMP) && !defined(CONFIG_BT_SMP_OOB_LEGACY_PAIR_ONLY)
	struct bt_le_oob_sc_data oobd_local;
	struct bt_le_oob_sc_data oobd_remote;
#endif /* defined(CONFIG_BT_SMP) && !defined(CONFIG_BT_SMP_OOB_LEGACY_PAIR_ONLY) */
};

static struct bt_conn connections[CONFIG_BT_MAX_CONN];

static inline uint8_t get_conn_index(const struct bt_conn *conn)
{
	return (uint8_t)(conn - connections);
}

void bt_rpc_encode_bt_conn(CborEncoder *encoder, const struct bt_conn *conn)
{
	if (CONFIG_BT_MAX_CONN > 1) {
		ser_encode_uint(encoder, get_conn_index(conn));
	}
}

struct bt_conn *bt_rpc_decode_bt_conn(CborValue *value)
{
	uint8_t index = 0;

	if (CONFIG_BT_MAX_CONN > 1) {
		index = ser_decode_uint(value);
		if (index >= CONFIG_BT_MAX_CONN) {
			ser_decoder_invalid(value, CborErrorIO);
			return NULL;
		}
	}
	return &connections[index];
}

static void bt_conn_remote_update_ref(struct bt_conn *conn, int8_t value)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 5;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_int(&_ctx.encoder, value);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_REMOTE_UPDATE_REF_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

static void bt_conn_ref_local(struct bt_conn *conn)
{
	if (conn) {
		atomic_inc(&conn->ref);
	}
}

struct bt_conn *bt_conn_ref(struct bt_conn *conn)
{
	atomic_val_t old = atomic_inc(&conn->ref);

	if (old == 0) {
		bt_conn_remote_update_ref(conn, + 1);
	}

	return conn;
}

void bt_conn_unref(struct bt_conn *conn)
{
	atomic_val_t old = atomic_dec(&conn->ref);

	if (old == 1) {
		bt_conn_remote_update_ref(conn, -1);
	}
}

static void bt_conn_foreach_cb_callback_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	void *data;
	bt_conn_foreach_cb callback_slot;

	conn = bt_rpc_decode_bt_conn(_value);
	data = (void *)ser_decode_uint(_value);
	callback_slot = (bt_conn_foreach_cb)ser_decode_callback_call(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	callback_slot(conn, data);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_FOREACH_CB_CALLBACK_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_foreach_cb_callback,
			 BT_CONN_FOREACH_CB_CALLBACK_RPC_CMD,
			 bt_conn_foreach_cb_callback_rpc_handler, NULL);

void bt_conn_foreach(int type, void (*func)(struct bt_conn *conn, void *data),
		     void *data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 15;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_int(&_ctx.encoder, type);
	ser_encode_callback(&_ctx.encoder, func);
	ser_encode_uint(&_ctx.encoder, (uintptr_t)data);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_FOREACH_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

struct bt_conn_lookup_addr_le_rpc_res {
	struct bt_conn *_result;
};

static void bt_conn_lookup_addr_le_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_conn_lookup_addr_le_rpc_res *_res =
		(struct bt_conn_lookup_addr_le_rpc_res *)_handler_data;

	_res->_result = bt_rpc_decode_bt_conn(_value);

	bt_conn_ref_local(_res->_result);
}

struct bt_conn *bt_conn_lookup_addr_le(uint8_t id, const bt_addr_le_t *peer)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn_lookup_addr_le_rpc_res _result;
	size_t _buffer_size_max = 5;

	_buffer_size_max += peer ? sizeof(bt_addr_le_t) : 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_uint(&_ctx.encoder, id);
	ser_encode_buffer(&_ctx.encoder, peer, sizeof(bt_addr_le_t));

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_LOOKUP_ADDR_LE_RPC_CMD,
				&_ctx, bt_conn_lookup_addr_le_rpc_rsp, &_result);

	return _result._result;
}

struct bt_conn_get_dst_out_rpc_res {
	bool _result;
	bt_addr_le_t *dst;

};

static void bt_conn_get_dst_out_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_conn_get_dst_out_rpc_res *_res =
		(struct bt_conn_get_dst_out_rpc_res *)_handler_data;

	_res->_result = ser_decode_bool(_value);
	ser_decode_buffer(_value, _res->dst, sizeof(bt_addr_le_t));
}

static bool bt_conn_get_dst_out(const struct bt_conn *conn, bt_addr_le_t *dst)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn_get_dst_out_rpc_res _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	_result.dst = dst;

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_GET_DST_OUT_RPC_CMD,
				&_ctx, bt_conn_get_dst_out_rpc_rsp, &_result);

	return _result._result;
}

const bt_addr_le_t *bt_conn_get_dst(const struct bt_conn *conn)
{
	bool not_null;

	not_null = bt_conn_get_dst_out(conn, (bt_addr_le_t *)&conn->dst);

	if (not_null) {
		return &conn->dst;
	} else {
		return NULL;
	}
}

uint8_t bt_conn_index(struct bt_conn *conn)
{
	return get_conn_index(conn);
}

#if defined(CONFIG_BT_USER_PHY_UPDATE)
void bt_conn_le_phy_info_dec(CborValue *_value, struct bt_conn_le_phy_info *_data)
{
	_data->tx_phy = ser_decode_uint(_value);
	_data->rx_phy = ser_decode_uint(_value);
}
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
void bt_conn_le_data_len_info_dec(CborValue *_value, struct bt_conn_le_data_len_info *_data)
{
	_data->tx_max_len = ser_decode_uint(_value);
	_data->tx_max_time = ser_decode_uint(_value);
	_data->rx_max_len = ser_decode_uint(_value);
	_data->rx_max_time = ser_decode_uint(_value);
}
#endif /* defined(CONFIG_BT_USER_DATA_LEN_UPDATE) */

void bt_conn_info_dec(CborValue *value, struct bt_conn *conn, struct bt_conn_info *info)
{
	info->type = ser_decode_uint(value);
	info->role = ser_decode_uint(value);
	info->id = ser_decode_uint(value);

	if (info->type == BT_CONN_TYPE_LE) {
		info->le.interval = ser_decode_uint(value);
		info->le.latency = ser_decode_uint(value);
		info->le.timeout = ser_decode_uint(value);
		LOCK_CONN_INFO();
		info->le.src = ser_decode_buffer(value, &conn->src, sizeof(bt_addr_le_t));
		info->le.dst = ser_decode_buffer(value, &conn->dst, sizeof(bt_addr_le_t));
		info->le.local = ser_decode_buffer(value, &conn->local, sizeof(bt_addr_le_t));
		info->le.remote = ser_decode_buffer(value, &conn->remote, sizeof(bt_addr_le_t));
#if defined(CONFIG_BT_USER_PHY_UPDATE)
		if (ser_decode_is_null(value)) {
			info->le.phy = NULL;
			ser_decode_skip(value);
		} else {
			info->le.phy = &conn->phy;
			bt_conn_le_phy_info_dec(value, &conn->phy);
		}
#else
		ser_decode_skip(value);
#endif
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
		if (ser_decode_is_null(value)) {
			info->le.data_len = NULL;
			ser_decode_skip(value);
		} else {
			info->le.data_len = &conn->data_len;
			bt_conn_le_data_len_info_dec(value, &conn->data_len);
		}
#else
		ser_decode_skip(value);
#endif
		UNLOCK_CONN_INFO();
	} else {
		/* non-LE connection types are not supported. */
		ser_decoder_invalid(value, CborErrorIO);
	}
}

struct bt_conn_get_info_rpc_res {
	int _result;
	struct bt_conn *conn;
	struct bt_conn_info *info;

};

static void bt_conn_get_info_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_conn_get_info_rpc_res *_res =
		(struct bt_conn_get_info_rpc_res *)_handler_data;

	_res->_result = ser_decode_int(_value);

	bt_conn_info_dec(_value, _res->conn, _res->info);
}

int bt_conn_get_info(const struct bt_conn *conn, struct bt_conn_info *info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn_get_info_rpc_res _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	_result.conn = (struct bt_conn *)conn;
	_result.info = info;

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_GET_INFO_RPC_CMD,
				&_ctx, bt_conn_get_info_rpc_rsp, &_result);

	return _result._result;
}

void bt_conn_remote_info_dec(CborValue *value, struct bt_conn *conn,
			     struct bt_conn_remote_info *remote_info)
{
	remote_info->type = ser_decode_uint(value);
	remote_info->version = ser_decode_uint(value);
	remote_info->manufacturer = ser_decode_uint(value);
	remote_info->subversion = ser_decode_uint(value);

	if (remote_info->type == BT_CONN_TYPE_LE && conn != NULL) {
		LOCK_CONN_INFO();
		remote_info->le.features = ser_decode_buffer(value, &conn->features,
							     sizeof(conn->features));
		UNLOCK_CONN_INFO();
	} else {
		/* non-LE connection types are not supported. */
		ser_decoder_invalid(value, CborErrorIO);
	}
}

struct bt_conn_get_remote_info_rpc_res {
	int _result;
	struct bt_conn *conn;
	struct bt_conn_remote_info *remote_info;
};

static void bt_conn_get_remote_info_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_conn_get_remote_info_rpc_res *_res =
		(struct bt_conn_get_remote_info_rpc_res *)_handler_data;

	_res->_result = ser_decode_int(_value);

	bt_conn_remote_info_dec(_value, _res->conn, _res->remote_info);
}

int bt_conn_get_remote_info(struct bt_conn *conn,
			    struct bt_conn_remote_info *remote_info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn_get_remote_info_rpc_res _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	_result.conn = conn;
	_result.remote_info = remote_info;

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_GET_REMOTE_INFO_RPC_CMD,
				&_ctx, bt_conn_get_remote_info_rpc_rsp, &_result);

	return _result._result;
}

void bt_le_conn_param_enc(CborEncoder *_encoder, const struct bt_le_conn_param *_data)
{
	ser_encode_uint(_encoder, _data->interval_min);
	ser_encode_uint(_encoder, _data->interval_max);
	ser_encode_uint(_encoder, _data->latency);
	ser_encode_uint(_encoder, _data->timeout);
}

void bt_le_conn_param_dec(CborValue *_value, struct bt_le_conn_param *_data)
{
	_data->interval_min = ser_decode_uint(_value);
	_data->interval_max = ser_decode_uint(_value);
	_data->latency = ser_decode_uint(_value);
	_data->timeout = ser_decode_uint(_value);
}

int bt_conn_le_param_update(struct bt_conn *conn,
			    const struct bt_le_conn_param *param)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 15;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_le_conn_param_enc(&_ctx.encoder, param);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_LE_PARAM_UPDATE_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
void bt_conn_le_data_len_param_enc(CborEncoder *_encoder,
				   const struct bt_conn_le_data_len_param *_data)
{
	ser_encode_uint(_encoder, _data->tx_max_len);
	ser_encode_uint(_encoder, _data->tx_max_time);
}

int bt_conn_le_data_len_update(struct bt_conn *conn,
			       const struct bt_conn_le_data_len_param *param)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 9;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_conn_le_data_len_param_enc(&_ctx.encoder, param);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_LE_DATA_LEN_UPDATE_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}
#endif /* defined(CONFIG_BT_USER_DATA_LEN_UPDATE) */

#if defined(CONFIG_BT_USER_PHY_UPDATE)
void bt_conn_le_phy_param_enc(CborEncoder *_encoder, const struct bt_conn_le_phy_param *_data)
{
	ser_encode_uint(_encoder, _data->options);
	ser_encode_uint(_encoder, _data->pref_tx_phy);
	ser_encode_uint(_encoder, _data->pref_rx_phy);
}

int bt_conn_le_phy_update(struct bt_conn *conn,
			  const struct bt_conn_le_phy_param *param)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 10;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_conn_le_phy_param_enc(&_ctx.encoder, param);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_LE_PHY_UPDATE_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */

int bt_conn_disconnect(struct bt_conn *conn, uint8_t reason)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 5;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, reason);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_DISCONNECT_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

#if defined(CONFIG_BT_CENTRAL)
void bt_conn_le_create_param_enc(CborEncoder *_encoder, const struct bt_conn_le_create_param *_data)
{
	ser_encode_uint(_encoder, _data->options);
	ser_encode_uint(_encoder, _data->interval);
	ser_encode_uint(_encoder, _data->window);
	ser_encode_uint(_encoder, _data->interval_coded);
	ser_encode_uint(_encoder, _data->window_coded);
	ser_encode_uint(_encoder, _data->timeout);
}

struct bt_conn_le_create_rpc_res {
	int _result;
	struct bt_conn **conn;

};

static void bt_conn_le_create_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_conn_le_create_rpc_res *_res =
		(struct bt_conn_le_create_rpc_res *)_handler_data;

	_res->_result = ser_decode_int(_value);
	*(_res->conn) = bt_rpc_decode_bt_conn(_value);

	bt_conn_ref_local(*(_res->conn));
}

int bt_conn_le_create(const bt_addr_le_t *peer,
		      const struct bt_conn_le_create_param *create_param,
		      const struct bt_le_conn_param *conn_param,
		      struct bt_conn **conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn_le_create_rpc_res _result;
	size_t _buffer_size_max = 35;

	_buffer_size_max += peer ? sizeof(bt_addr_le_t) : 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_buffer(&_ctx.encoder, peer, sizeof(bt_addr_le_t));
	bt_conn_le_create_param_enc(&_ctx.encoder, create_param);
	bt_le_conn_param_enc(&_ctx.encoder, conn_param);

	_result.conn = conn;

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_LE_CREATE_RPC_CMD,
				&_ctx, bt_conn_le_create_rpc_rsp, &_result);

	return _result._result;
}

#if defined(CONFIG_BT_WHITELIST)
int bt_conn_le_create_auto(const struct bt_conn_le_create_param *create_param,
			   const struct bt_le_conn_param *conn_param)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 32;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_conn_le_create_param_enc(&_ctx.encoder, create_param);
	bt_le_conn_param_enc(&_ctx.encoder, conn_param);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_LE_CREATE_AUTO_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

int bt_conn_create_auto_stop(void)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CREATE_AUTO_STOP_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}
#endif /* defined(CONFIG_BT_WHITELIST) */

#if !defined(CONFIG_BT_WHITELIST)
int bt_le_set_auto_conn(const bt_addr_le_t *addr,
			const struct bt_le_conn_param *param)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 3;

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;
	_buffer_size_max += (param == NULL) ? 1 : 12;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));
	if (param == NULL) {
		ser_encode_null(&_ctx.encoder);
	} else {
		bt_le_conn_param_enc(&_ctx.encoder, param);
	}

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SET_AUTO_CONN_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}
#endif  /* !defined(CONFIG_BT_WHITELIST) */
#endif  /* defined(CONFIG_BT_CENTRAL) */

#if defined(CONFIG_BT_SMP)
int bt_conn_set_security(struct bt_conn *conn, bt_security_t sec)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 8;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, (uint32_t)sec);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_SET_SECURITY_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}


struct bt_conn_get_security_rpc_res {
	bt_security_t _result;
};

static void bt_conn_get_security_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_conn_get_security_rpc_res *_res =
		(struct bt_conn_get_security_rpc_res *)_handler_data;

	_res->_result = (bt_security_t)ser_decode_uint(_value);
}

bt_security_t bt_conn_get_security(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn_get_security_rpc_res _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_GET_SECURITY_RPC_CMD,
				&_ctx, bt_conn_get_security_rpc_rsp, &_result);

	return _result._result;
}

uint8_t bt_conn_enc_key_size(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	uint8_t _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_ENC_KEY_SIZE_RPC_CMD,
				&_ctx, ser_rsp_decode_u8, &_result);

	return _result;
}
#endif /* defined(CONFIG_BT_SMP) */

static struct bt_conn_cb *first_bt_conn_cb;

static void bt_conn_cb_connected_call(struct bt_conn *conn, uint8_t err)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->connected) {
			cb->connected(conn, err);
		}
	}
}

static void bt_conn_cb_connected_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	uint8_t err;

	conn = bt_rpc_decode_bt_conn(_value);
	err = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_connected_call(conn, err);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_CONNECTED_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_connected_call, BT_CONN_CB_CONNECTED_CALL_RPC_CMD,
			 bt_conn_cb_connected_call_rpc_handler, NULL);

static void bt_conn_cb_disconnected_call(struct bt_conn *conn, uint8_t reason)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->disconnected) {
			cb->disconnected(conn, reason);
		}
	}
}

static void bt_conn_cb_disconnected_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	uint8_t reason;

	conn = bt_rpc_decode_bt_conn(_value);
	reason = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_disconnected_call(conn, reason);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_DISCONNECTED_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_disconnected_call,
			 BT_CONN_CB_DISCONNECTED_CALL_RPC_CMD,
			 bt_conn_cb_disconnected_call_rpc_handler, NULL);

static bool bt_conn_cb_le_param_req_call(struct bt_conn *conn, struct bt_le_conn_param *param)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->le_param_req) {
			if (!cb->le_param_req(conn, param)) {
				return false;
			}
		}
	}

	return true;
}

static void bt_conn_cb_le_param_req_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_le_conn_param param;
	bool _result;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_le_conn_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_cb_le_param_req_call(conn, &param);

	ser_rsp_send_bool(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_LE_PARAM_REQ_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_le_param_req_call,
			 BT_CONN_CB_LE_PARAM_REQ_CALL_RPC_CMD,
			 bt_conn_cb_le_param_req_call_rpc_handler, NULL);

static void bt_conn_cb_le_param_updated_call(struct bt_conn *conn, uint16_t interval, uint16_t
					     latency, uint16_t timeout)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->le_param_updated) {
			cb->le_param_updated(conn, interval, latency, timeout);
		}
	}
}

static void bt_conn_cb_le_param_updated_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	uint16_t interval;
	uint16_t latency;
	uint16_t timeout;

	conn = bt_rpc_decode_bt_conn(_value);
	interval = ser_decode_uint(_value);
	latency = ser_decode_uint(_value);
	timeout = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_le_param_updated_call(conn, interval, latency, timeout);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_LE_PARAM_UPDATED_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_le_param_updated_call,
			 BT_CONN_CB_LE_PARAM_UPDATED_CALL_RPC_CMD,
			 bt_conn_cb_le_param_updated_call_rpc_handler, NULL);

#if defined(CONFIG_BT_SMP)
static void bt_conn_cb_identity_resolved_call(struct bt_conn *conn, const bt_addr_le_t *rpa, const
					      bt_addr_le_t *identity)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->identity_resolved) {
			cb->identity_resolved(conn, rpa, identity);
		}
	}
}

static void bt_conn_cb_identity_resolved_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	bt_addr_le_t _rpa_data;
	const bt_addr_le_t *rpa;
	bt_addr_le_t _identity_data;
	const bt_addr_le_t *identity;

	conn = bt_rpc_decode_bt_conn(_value);
	rpa = ser_decode_buffer(_value, &_rpa_data, sizeof(bt_addr_le_t));
	identity = ser_decode_buffer(_value, &_identity_data, sizeof(bt_addr_le_t));

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_identity_resolved_call(conn, rpa, identity);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_IDENTITY_RESOLVED_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_identity_resolved_call,
			 BT_CONN_CB_IDENTITY_RESOLVED_CALL_RPC_CMD,
			 bt_conn_cb_identity_resolved_call_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_SMP) */

#if defined(CONFIG_BT_SMP)
static void bt_conn_cb_security_changed_call(struct bt_conn *conn, bt_security_t level,
					     enum bt_security_err err)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->security_changed) {
			cb->security_changed(conn, level, err);
		}
	}
}

static void bt_conn_cb_security_changed_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	bt_security_t level;
	enum bt_security_err err;

	conn = bt_rpc_decode_bt_conn(_value);
	level = (bt_security_t)ser_decode_uint(_value);
	err = (enum bt_security_err)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_security_changed_call(conn, level, err);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_SECURITY_CHANGED_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_security_changed_call,
			 BT_CONN_CB_SECURITY_CHANGED_CALL_RPC_CMD,
			 bt_conn_cb_security_changed_call_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_SMP) */

#if defined(CONFIG_BT_REMOTE_INFO)
static void bt_conn_cb_remote_info_available_call(struct bt_conn *conn,
						  struct bt_conn_remote_info *remote_info)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->remote_info_available) {
			cb->remote_info_available(conn, remote_info);
		}
	}
}

static void bt_conn_cb_remote_info_available_call_rpc_handler(CborValue *_value,
							      void *_handler_data)
{
	struct bt_conn *conn;

	struct bt_conn_remote_info remote_info;

	conn = bt_rpc_decode_bt_conn(_value);

	bt_conn_remote_info_dec(_value, conn, &remote_info);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_remote_info_available_call(conn, &remote_info);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_REMOTE_INFO_AVAILABLE_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_remote_info_available_call,
			 BT_CONN_CB_REMOTE_INFO_AVAILABLE_CALL_RPC_CMD,
			 bt_conn_cb_remote_info_available_call_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_REMOTE_INFO) */

#if defined(CONFIG_BT_USER_PHY_UPDATE)
static void bt_conn_cb_le_phy_updated_call(struct bt_conn *conn, struct bt_conn_le_phy_info *param)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->le_phy_updated) {
			cb->le_phy_updated(conn, param);
		}
	}
}

static void bt_conn_cb_le_phy_updated_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_conn_le_phy_info param;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_conn_le_phy_info_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_le_phy_updated_call(conn, &param);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_LE_PHY_UPDATED_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_le_phy_updated_call,
			 BT_CONN_CB_LE_PHY_UPDATED_CALL_RPC_CMD,
			 bt_conn_cb_le_phy_updated_call_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
static void bt_conn_cb_le_data_len_updated_call(struct bt_conn *conn,
						struct bt_conn_le_data_len_info *info)
{
	struct bt_conn_cb *cb;

	for (cb = first_bt_conn_cb; cb; cb = cb->_next) {
		if (cb->le_data_len_updated) {
			cb->le_data_len_updated(conn, info);
		}
	}
}

static void bt_conn_cb_le_data_len_updated_call_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_conn_le_data_len_info info;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_conn_le_data_len_info_dec(_value, &info);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_cb_le_data_len_updated_call(conn, &info);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_CB_LE_DATA_LEN_UPDATED_CALL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_le_data_len_updated_call,
			 BT_CONN_CB_LE_DATA_LEN_UPDATED_CALL_RPC_CMD,
			 bt_conn_cb_le_data_len_updated_call_rpc_handler, NULL);

#endif /* defined(CONFIG_BT_USER_DATA_LEN_UPDATE) */

static void bt_conn_cb_register_on_remote(void)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_REGISTER_ON_REMOTE_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_conn_cb_register(struct bt_conn_cb *cb)
{
	bool register_on_remote;

	LOCK_CONN_INFO();
	register_on_remote = (first_bt_conn_cb == NULL);
	cb->_next = first_bt_conn_cb;
	first_bt_conn_cb = cb;
	UNLOCK_CONN_INFO();

	if (register_on_remote) {
		bt_conn_cb_register_on_remote();
	}
}

#if defined(CONFIG_BT_SMP)
void bt_set_bondable(bool enable)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 1;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_bool(&_ctx.encoder, enable);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_SET_BONDABLE_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_set_oob_data_flag(bool enable)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 1;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_bool(&_ctx.encoder, enable);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_SET_OOB_DATA_FLAG_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

#if !defined(CONFIG_BT_SMP_SC_PAIR_ONLY)
int bt_le_oob_set_legacy_tk(struct bt_conn *conn, const uint8_t *tk)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _tk_size;
	int _result;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 13;

	_tk_size = sizeof(uint8_t) * 16;
	_buffer_size_max += _tk_size;

	_scratchpad_size += SCRATCHPAD_ALIGN(_tk_size);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_buffer(&_ctx.encoder, tk, _tk_size);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_OOB_SET_LEGACY_TK_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}
#endif /* !defined(CONFIG_BT_SMP_SC_PAIR_ONLY) */

#if !defined(CONFIG_BT_SMP_OOB_LEGACY_PAIR_ONLY)
size_t bt_le_oob_sc_data_buf_size(const struct bt_le_oob_sc_data *_data)
{
	size_t _buffer_size_max = 10;

	_buffer_size_max += 16 * sizeof(uint8_t);
	_buffer_size_max += 16 * sizeof(uint8_t);

	return _buffer_size_max;
}

void bt_le_oob_sc_data_enc(CborEncoder *_encoder, const struct bt_le_oob_sc_data *_data)
{
	ser_encode_buffer(_encoder, _data->r, 16 * sizeof(uint8_t));
	ser_encode_buffer(_encoder, _data->c, 16 * sizeof(uint8_t));
}

void bt_le_oob_sc_data_dec(CborValue *_value, struct bt_le_oob_sc_data *_data)
{
	ser_decode_buffer(_value, _data->r, 16 * sizeof(uint8_t));
	ser_decode_buffer(_value, _data->c, 16 * sizeof(uint8_t));
}

int bt_le_oob_set_sc_data(struct bt_conn *conn,
			  const struct bt_le_oob_sc_data *oobd_local,
			  const struct bt_le_oob_sc_data *oobd_remote)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 3;

	_buffer_size_max += (oobd_local == NULL) ? 1 : 0 + bt_le_oob_sc_data_buf_size(oobd_local);
	_buffer_size_max += (oobd_remote == NULL) ? 1 : 0 + bt_le_oob_sc_data_buf_size(oobd_remote);
	;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	if (oobd_local == NULL) {
		ser_encode_null(&_ctx.encoder);
	} else {
		bt_le_oob_sc_data_enc(&_ctx.encoder, oobd_local);
	}
	if (oobd_remote == NULL) {
		ser_encode_null(&_ctx.encoder);
	} else {
		bt_le_oob_sc_data_enc(&_ctx.encoder, oobd_remote);
	}

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_OOB_SET_SC_DATA_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

struct bt_le_oob_get_sc_data_rpc_res {
	int _result;
	struct bt_conn *conn;
	const struct bt_le_oob_sc_data **oobd_local;
	const struct bt_le_oob_sc_data **oobd_remote;
};

static void bt_le_oob_get_sc_data_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_le_oob_get_sc_data_rpc_res *_res =
		(struct bt_le_oob_get_sc_data_rpc_res *)_handler_data;

	_res->_result = ser_decode_int(_value);

	if (ser_decode_is_null(_value)) {
		*_res->oobd_local = NULL;
		ser_decode_skip(_value);
	} else {
		*_res->oobd_local = &_res->conn->oobd_local;
		bt_le_oob_sc_data_dec(_value, &_res->conn->oobd_local);
	}

	if (ser_decode_is_null(_value)) {
		*_res->oobd_remote = NULL;
		ser_decode_skip(_value);
	} else {
		*_res->oobd_remote = &_res->conn->oobd_remote;
		bt_le_oob_sc_data_dec(_value, &_res->conn->oobd_remote);
	}
}

int bt_le_oob_get_sc_data(struct bt_conn *conn,
			  const struct bt_le_oob_sc_data **oobd_local,
			  const struct bt_le_oob_sc_data **oobd_remote)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_le_oob_get_sc_data_rpc_res _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	_result.conn = conn;
	_result.oobd_local = oobd_local;
	_result.oobd_remote = oobd_remote;

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_OOB_GET_SC_DATA_RPC_CMD,
				&_ctx, bt_le_oob_get_sc_data_rpc_rsp, &_result);

	return _result._result;
}
#endif /* !defined(CONFIG_BT_SMP_OOB_LEGACY_PAIR_ONLY) */

#if defined(CONFIG_BT_FIXED_PASSKEY)
int bt_passkey_set(unsigned int passkey)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 5;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_uint(&_ctx.encoder, passkey);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_PASSKEY_SET_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}
#endif /* defined(CONFIG_BT_FIXED_PASSKEY) */

static const struct bt_conn_auth_cb *auth_cb;

#if defined(CONFIG_BT_SMP_APP_PAIRING_ACCEPT)
void bt_conn_pairing_feat_dec(CborValue *_value, struct bt_conn_pairing_feat *_data)
{
	_data->io_capability = ser_decode_uint(_value);
	_data->oob_data_flag = ser_decode_uint(_value);
	_data->auth_req = ser_decode_uint(_value);
	_data->max_enc_key_size = ser_decode_uint(_value);
	_data->init_key_dist = ser_decode_uint(_value);
	_data->resp_key_dist = ser_decode_uint(_value);
}

static void bt_rpc_auth_cb_pairing_accept_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	enum bt_security_err _result;
	struct bt_conn *conn;
	struct bt_conn_pairing_feat feat;
	size_t _buffer_size_max = 5;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_conn_pairing_feat_dec(_value, &feat);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->pairing_accept) {
		_result = auth_cb->pairing_accept(conn, &feat);
	} else {
		_result = BT_SECURITY_ERR_INVALID_PARAM;
	}

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_uint(&_ctx.encoder, (uint32_t)_result);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_PAIRING_ACCEPT_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_pairing_accept,
			 BT_RPC_AUTH_CB_PAIRING_ACCEPT_RPC_CMD,
			 bt_rpc_auth_cb_pairing_accept_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_SMP_APP_PAIRING_ACCEPT) */

static void bt_rpc_auth_cb_passkey_display_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	unsigned int passkey;

	conn = bt_rpc_decode_bt_conn(_value);
	passkey = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->passkey_display) {
		auth_cb->passkey_display(conn, passkey);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_PASSKEY_DISPLAY_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_passkey_display,
			 BT_RPC_AUTH_CB_PASSKEY_DISPLAY_RPC_CMD,
			 bt_rpc_auth_cb_passkey_display_rpc_handler, NULL);

static void bt_rpc_auth_cb_passkey_entry_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->passkey_entry) {
		auth_cb->passkey_entry(conn);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_PASSKEY_ENTRY_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_passkey_entry,
			 BT_RPC_AUTH_CB_PASSKEY_ENTRY_RPC_CMD,
			 bt_rpc_auth_cb_passkey_entry_rpc_handler, NULL);

static void bt_rpc_auth_cb_passkey_confirm_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	unsigned int passkey;

	conn = bt_rpc_decode_bt_conn(_value);
	passkey = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->passkey_confirm) {
		auth_cb->passkey_confirm(conn, passkey);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_PASSKEY_CONFIRM_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_passkey_confirm,
			 BT_RPC_AUTH_CB_PASSKEY_CONFIRM_RPC_CMD,
			 bt_rpc_auth_cb_passkey_confirm_rpc_handler, NULL);

static void bt_rpc_auth_cb_oob_data_request_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_conn_oob_info _info_data;
	struct bt_conn_oob_info *info;

	conn = bt_rpc_decode_bt_conn(_value);
	info = ser_decode_buffer(_value, &_info_data, sizeof(struct bt_conn_oob_info));

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->oob_data_request) {
		auth_cb->oob_data_request(conn, info);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_OOB_DATA_REQUEST_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_oob_data_request,
			 BT_RPC_AUTH_CB_OOB_DATA_REQUEST_RPC_CMD,
			 bt_rpc_auth_cb_oob_data_request_rpc_handler, NULL);

static void bt_rpc_auth_cb_cancel_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->cancel) {
		auth_cb->cancel(conn);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_CANCEL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_cancel, BT_RPC_AUTH_CB_CANCEL_RPC_CMD,
			 bt_rpc_auth_cb_cancel_rpc_handler, NULL);

static void bt_rpc_auth_cb_pairing_confirm_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->pairing_confirm) {
		auth_cb->pairing_confirm(conn);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_PAIRING_CONFIRM_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_pairing_confirm,
			 BT_RPC_AUTH_CB_PAIRING_CONFIRM_RPC_CMD,
			 bt_rpc_auth_cb_pairing_confirm_rpc_handler, NULL);

static void bt_rpc_auth_cb_pairing_complete_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	bool bonded;

	conn = bt_rpc_decode_bt_conn(_value);
	bonded = ser_decode_bool(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->pairing_complete) {
		auth_cb->pairing_complete(conn, bonded);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_PAIRING_COMPLETE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_pairing_complete,
			 BT_RPC_AUTH_CB_PAIRING_COMPLETE_RPC_CMD,
			 bt_rpc_auth_cb_pairing_complete_rpc_handler, NULL);

static void bt_rpc_auth_cb_pairing_failed_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	enum bt_security_err reason;

	conn = bt_rpc_decode_bt_conn(_value);
	reason = (enum bt_security_err)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (auth_cb->pairing_failed) {
		auth_cb->pairing_failed(conn, reason);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_AUTH_CB_PAIRING_FAILED_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_auth_cb_pairing_failed,
			 BT_RPC_AUTH_CB_PAIRING_FAILED_RPC_CMD,
			 bt_rpc_auth_cb_pairing_failed_rpc_handler, NULL);

int bt_conn_auth_cb_register_on_remote(uint16_t flags)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_uint(&_ctx.encoder, flags);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_AUTH_CB_REGISTER_ON_REMOTE_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

int bt_conn_auth_cb_register(const struct bt_conn_auth_cb *cb)
{
	int res;
	uint16_t flags = 0;

#if defined(CONFIG_BT_SMP_APP_PAIRING_ACCEPT)
	flags |= cb->pairing_accept ? FLAG_PAIRING_ACCEPT_PRESENT : 0;
#endif /* CONFIG_BT_SMP_APP_PAIRING_ACCEPT */
	flags |= cb->passkey_display ? FLAG_PASSKEY_DISPLAY_PRESENT : 0;
	flags |= cb->passkey_entry ? FLAG_PASSKEY_ENTRY_PRESENT : 0;
	flags |= cb->passkey_confirm ? FLAG_PASSKEY_CONFIRM_PRESENT : 0;
	flags |= cb->oob_data_request ? FLAG_OOB_DATA_REQUEST_PRESENT : 0;
	flags |= cb->cancel ? FLAG_CANCEL_PRESENT : 0;
	flags |= cb->pairing_confirm ? FLAG_PAIRING_CONFIRM_PRESENT : 0;
	flags |= cb->pairing_complete ? FLAG_PAIRING_COMPLETE_PRESENT : 0;
	flags |= cb->pairing_failed ? FLAG_PAIRING_FAILED_PRESENT : 0;

	res = bt_conn_auth_cb_register_on_remote(flags);

	if (res == 0) {
		auth_cb = cb;
	}

	return res;
}

int bt_conn_auth_passkey_entry(struct bt_conn *conn, unsigned int passkey)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 8;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, passkey);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_AUTH_PASSKEY_ENTRY_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

int bt_conn_auth_cancel(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_AUTH_CANCEL_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

int bt_conn_auth_passkey_confirm(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_AUTH_PASSKEY_CONFIRM_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

int bt_conn_auth_pairing_confirm(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_AUTH_PAIRING_CONFIRM_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}
#else /* defined(CONFIG_BT_SMP) */

bt_security_t bt_conn_get_security(struct bt_conn *conn)
{
	return BT_SECURITY_L1;
}
#endif /* defined(CONFIG_BT_SMP) */
