/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>

#include <zephyr.h>

#include <nrf_rpc_cbor.h>

#include "bt_rpc_common.h"
#include "serialize.h"
#include "cbkproxy.h"

#include <logging/log.h>

LOG_MODULE_DECLARE(BT_RPC, CONFIG_BT_RPC_LOG_LEVEL);

#define SIZE_OF_FIELD(structure, field) (sizeof(((structure *)NULL)->field))

static void report_decoding_error(uint8_t cmd_evt_id, void *data)
{
	nrf_rpc_err(-EBADMSG, NRF_RPC_ERR_SRC_RECV, &bt_rpc_grp, cmd_evt_id,
		    NRF_RPC_PACKET_TYPE_CMD);
}

void bt_rpc_encode_bt_conn(CborEncoder *encoder,
			   const struct bt_conn *conn)
{
	if (CONFIG_BT_MAX_CONN > 1) {
		ser_encode_uint(encoder, (uint8_t)bt_conn_index((struct bt_conn *)conn));
	}
}

struct bt_conn *bt_rpc_decode_bt_conn(CborValue *value)
{
	/* Making bt_conn_lookup_index() public will be better approach. */
	extern struct bt_conn *bt_conn_lookup_index(uint8_t index);

	struct bt_conn *conn;
	uint8_t index;

	if (CONFIG_BT_MAX_CONN > 1) {
		index = ser_decode_uint(value);
	} else {
		index = 0;
	}

	conn = bt_conn_lookup_index(index);

	if (conn == NULL) {
		LOG_ERR("Cannot find connection of specified index");
		ser_decoder_invalid(value, CborErrorIO);
	} else {
		/* It is safe to unref, because remote side must be holding
		 * at least one reference.
		 */
		bt_conn_unref(conn);
	}

	return conn;
}

static void bt_conn_remote_update_ref(struct bt_conn *conn, int8_t value)
{
	if (value < 0) {
		bt_conn_unref(conn);
	} else {
		bt_conn_ref(conn);
	}
}

static void bt_conn_remote_update_ref_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	int8_t value;

	conn = bt_rpc_decode_bt_conn(_value);
	value = ser_decode_int(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_remote_update_ref(conn, value);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_REMOTE_UPDATE_REF_RPC_CMD, _handler_data);
}


NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_remote_update_ref, BT_CONN_REMOTE_UPDATE_REF_RPC_CMD,
			 bt_conn_remote_update_ref_rpc_handler, NULL);

static inline void bt_conn_foreach_cb_callback(struct bt_conn *conn, void *data,
					       uint32_t callback_slot)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 11;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, (uintptr_t)data);
	ser_encode_callback_call(&_ctx.encoder, callback_slot);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_FOREACH_CB_CALLBACK_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

CBKPROXY_HANDLER(bt_conn_foreach_cb_encoder, bt_conn_foreach_cb_callback,
		 (struct bt_conn *conn, void *data), (conn, data));

static void bt_conn_foreach_rpc_handler(CborValue *_value, void *_handler_data)
{
	int type;
	bt_conn_foreach_cb func;
	void *data;

	type = ser_decode_int(_value);
	func = (bt_conn_foreach_cb)ser_decode_callback(_value, bt_conn_foreach_cb_encoder);
	data = (void *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_conn_foreach(type, func, data);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_CONN_FOREACH_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_foreach, BT_CONN_FOREACH_RPC_CMD,
			 bt_conn_foreach_rpc_handler, NULL);


static void bt_conn_lookup_addr_le_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn *_result;
	uint8_t id;
	bt_addr_le_t _peer_data;
	const bt_addr_le_t *peer;
	size_t _buffer_size_max = 3;

	id = ser_decode_uint(_value);
	peer = ser_decode_buffer(_value, &_peer_data, sizeof(bt_addr_le_t));

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_lookup_addr_le(id, peer);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		bt_rpc_encode_bt_conn(&_ctx.encoder, _result);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_CONN_LOOKUP_ADDR_LE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_lookup_addr_le, BT_CONN_LOOKUP_ADDR_LE_RPC_CMD,
			 bt_conn_lookup_addr_le_rpc_handler, NULL);

static void bt_conn_get_dst_out_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	bool _result;
	const struct bt_conn *conn;
	bt_addr_le_t _dst_data;
	bt_addr_le_t *dst = &_dst_data;
	size_t _buffer_size_max = 4;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	dst = (bt_addr_le_t *)bt_conn_get_dst(conn);
	_result = (dst != NULL);

	_buffer_size_max += sizeof(bt_addr_le_t);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_bool(&_ctx.encoder, _result);
		ser_encode_buffer(&_ctx.encoder, dst, sizeof(bt_addr_le_t));

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_CONN_GET_DST_OUT_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_get_dst_out, BT_CONN_GET_DST_OUT_RPC_CMD,
			 bt_conn_get_dst_out_rpc_handler, NULL);

#if defined(CONFIG_BT_USER_PHY_UPDATE)
void bt_conn_le_phy_info_enc(CborEncoder *_encoder, const struct bt_conn_le_phy_info *_data)
{
	ser_encode_uint(_encoder, _data->tx_phy);
	ser_encode_uint(_encoder, _data->rx_phy);
}
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
void bt_conn_le_data_len_info_enc(CborEncoder *_encoder,
				  const struct bt_conn_le_data_len_info *_data)
{
	ser_encode_uint(_encoder, _data->tx_max_len);
	ser_encode_uint(_encoder, _data->tx_max_time);
	ser_encode_uint(_encoder, _data->rx_max_len);
	ser_encode_uint(_encoder, _data->rx_max_time);
}
#endif /* defined(CONFIG_BT_USER_DATA_LEN_UPDATE) */

static const size_t bt_conn_info_buf_size =
	1 + SIZE_OF_FIELD(struct bt_conn_info, type) +
	1 + SIZE_OF_FIELD(struct bt_conn_info, role) +
	1 + SIZE_OF_FIELD(struct bt_conn_info, id) +
	1 + SIZE_OF_FIELD(struct bt_conn_info, le.interval) +
	1 + SIZE_OF_FIELD(struct bt_conn_info, le.latency) +
	1 + SIZE_OF_FIELD(struct bt_conn_info, le.timeout) +
	4 * (1 + sizeof(bt_addr_le_t)) +
#if defined(CONFIG_BT_USER_PHY_UPDATE)
	bt_conn_le_phy_info_buf_size +
#else
	1 +
#endif
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
	bt_conn_le_data_len_info_buf_size;
#else
	1;
#endif

void bt_conn_info_enc(CborEncoder *encoder, struct bt_conn_info *info)
{
	ser_encode_uint(encoder, info->type);
	ser_encode_uint(encoder, info->role);
	ser_encode_uint(encoder, info->id);

	if (info->type == BT_CONN_TYPE_LE) {
		ser_encode_uint(encoder, info->le.interval);
		ser_encode_uint(encoder, info->le.latency);
		ser_encode_uint(encoder, info->le.timeout);
		ser_encode_buffer(encoder, info->le.src, sizeof(bt_addr_le_t));
		ser_encode_buffer(encoder, info->le.dst, sizeof(bt_addr_le_t));
		ser_encode_buffer(encoder, info->le.local, sizeof(bt_addr_le_t));
		ser_encode_buffer(encoder, info->le.remote, sizeof(bt_addr_le_t));
#if defined(CONFIG_BT_USER_PHY_UPDATE)
		bt_conn_le_phy_info_enc(encoder, info->le.phy);
#else
		ser_encode_null(encoder);
#endif
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
		bt_conn_le_data_len_info_enc(encoder, info->le.data_len);
#else
		ser_encode_null(encoder);
#endif
	} else {
		/* non-LE connection types are not supported. */
		ser_encoder_invalid(encoder);
	}
}

static void bt_conn_get_info_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	const struct bt_conn *conn;
	size_t _buffer_size_max = 5;

	struct bt_conn_info info;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_get_info(conn, &info);

	_buffer_size_max += bt_conn_info_buf_size;

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);

		bt_conn_info_enc(&_ctx.encoder, &info);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_CONN_GET_INFO_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_get_info, BT_CONN_GET_INFO_RPC_CMD,
			 bt_conn_get_info_rpc_handler, NULL);


static const size_t bt_conn_remote_info_buf_size =
	1 + SIZE_OF_FIELD(struct bt_conn_remote_info, type) +
	1 + SIZE_OF_FIELD(struct bt_conn_remote_info, version) +
	1 + SIZE_OF_FIELD(struct bt_conn_remote_info, manufacturer) +
	1 + SIZE_OF_FIELD(struct bt_conn_remote_info, subversion) +
	1 + 8 * sizeof(uint8_t);

void bt_conn_remote_info_enc(CborEncoder *encoder, struct bt_conn_remote_info *remote_info)
{
	ser_encode_uint(encoder, remote_info->type);
	ser_encode_uint(encoder, remote_info->version);
	ser_encode_uint(encoder, remote_info->manufacturer);
	ser_encode_uint(encoder, remote_info->subversion);

	if (remote_info->type == BT_CONN_TYPE_LE) {
		ser_encode_buffer(encoder, remote_info->le.features, 8 * sizeof(uint8_t));
	} else {
		/* non-LE connection types are not supported. */
		ser_encoder_invalid(encoder);
	}
}

static void bt_conn_get_remote_info_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	struct bt_conn *conn;
	size_t _buffer_size_max = 5;

	struct bt_conn_remote_info remote_info;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_get_remote_info(conn, &remote_info);

	_buffer_size_max += bt_conn_remote_info_buf_size;

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);

		bt_conn_remote_info_enc(&_ctx.encoder, &remote_info);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_CONN_GET_REMOTE_INFO_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_get_remote_info, BT_CONN_GET_REMOTE_INFO_RPC_CMD,
			 bt_conn_get_remote_info_rpc_handler, NULL);

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

static void bt_conn_le_param_update_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_le_conn_param param;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_le_conn_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_le_param_update(conn, &param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_LE_PARAM_UPDATE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_le_param_update, BT_CONN_LE_PARAM_UPDATE_RPC_CMD,
			 bt_conn_le_param_update_rpc_handler, NULL);

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
void bt_conn_le_data_len_param_dec(CborValue *_value, struct bt_conn_le_data_len_param *_data)
{
	_data->tx_max_len = ser_decode_uint(_value);
	_data->tx_max_time = ser_decode_uint(_value);
}

static void bt_conn_le_data_len_update_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_conn_le_data_len_param param;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_conn_le_data_len_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_le_data_len_update(conn, &param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_LE_DATA_LEN_UPDATE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_le_data_len_update, BT_CONN_LE_DATA_LEN_UPDATE_RPC_CMD,
			 bt_conn_le_data_len_update_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_USER_DATA_LEN_UPDATE) */

#if defined(CONFIG_BT_USER_PHY_UPDATE)
void bt_conn_le_phy_param_dec(CborValue *_value, struct bt_conn_le_phy_param *_data)
{
	_data->options = ser_decode_uint(_value);
	_data->pref_tx_phy = ser_decode_uint(_value);
	_data->pref_rx_phy = ser_decode_uint(_value);
}

static void bt_conn_le_phy_update_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_conn_le_phy_param param;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_conn_le_phy_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_le_phy_update(conn, &param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_LE_PHY_UPDATE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_le_phy_update, BT_CONN_LE_PHY_UPDATE_RPC_CMD,
			 bt_conn_le_phy_update_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */

static void bt_conn_disconnect_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	uint8_t reason;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	reason = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_disconnect(conn, reason);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_DISCONNECT_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_disconnect, BT_CONN_DISCONNECT_RPC_CMD,
			 bt_conn_disconnect_rpc_handler, NULL);

#if defined(CONFIG_BT_CENTRAL)
void bt_conn_le_create_param_dec(CborValue *_value, struct bt_conn_le_create_param *_data)
{
	_data->options = ser_decode_uint(_value);
	_data->interval = ser_decode_uint(_value);
	_data->window = ser_decode_uint(_value);
	_data->interval_coded = ser_decode_uint(_value);
	_data->window_coded = ser_decode_uint(_value);
	_data->timeout = ser_decode_uint(_value);
}

static void bt_conn_le_create_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	bt_addr_le_t _peer_data;
	const bt_addr_le_t *peer;
	struct bt_conn_le_create_param create_param;
	struct bt_le_conn_param conn_param;
	struct bt_conn *_conn_data;
	struct bt_conn **conn = &_conn_data;
	size_t _buffer_size_max = 8;

	peer = ser_decode_buffer(_value, &_peer_data, sizeof(bt_addr_le_t));
	bt_conn_le_create_param_dec(_value, &create_param);
	bt_le_conn_param_dec(_value, &conn_param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_le_create(peer, &create_param, &conn_param, conn);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);
		bt_rpc_encode_bt_conn(&_ctx.encoder, *conn);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_CONN_LE_CREATE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_le_create, BT_CONN_LE_CREATE_RPC_CMD,
			 bt_conn_le_create_rpc_handler, NULL);

#if defined(CONFIG_BT_WHITELIST)
static void bt_conn_le_create_auto_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn_le_create_param create_param;
	struct bt_le_conn_param conn_param;
	int _result;

	bt_conn_le_create_param_dec(_value, &create_param);
	bt_le_conn_param_dec(_value, &conn_param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_le_create_auto(&create_param, &conn_param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_LE_CREATE_AUTO_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_le_create_auto, BT_CONN_LE_CREATE_AUTO_RPC_CMD,
			 bt_conn_le_create_auto_rpc_handler, NULL);

static void bt_conn_create_auto_stop_rpc_handler(CborValue *_value, void *_handler_data)
{
	int _result;

	nrf_rpc_cbor_decoding_done(_value);

	_result = bt_conn_create_auto_stop();

	ser_rsp_send_int(_result);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_create_auto_stop, BT_CONN_CREATE_AUTO_STOP_RPC_CMD,
			 bt_conn_create_auto_stop_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_WHITELIST) */

#if !defined(CONFIG_BT_WHITELIST)
static void bt_le_set_auto_conn_rpc_handler(CborValue *_value, void *_handler_data)
{
	bt_addr_le_t _addr_data;
	const bt_addr_le_t *addr;
	struct bt_le_conn_param _param_data;
	struct bt_le_conn_param *param;
	int _result;

	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));
	if (ser_decode_is_null(_value)) {
		param = NULL;
		ser_decode_skip(_value);
	} else {
		param = &_param_data;
		bt_le_conn_param_dec(_value, param);
	}

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_set_auto_conn(addr, param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_SET_AUTO_CONN_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_set_auto_conn, BT_LE_SET_AUTO_CONN_RPC_CMD,
			 bt_le_set_auto_conn_rpc_handler, NULL);
#endif  /* !defined(CONFIG_BT_WHITELIST) */
#endif  /* defined(CONFIG_BT_CENTRAL) */

#if defined(CONFIG_BT_SMP)
static void bt_conn_set_security_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	bt_security_t sec;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	sec = (bt_security_t)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_set_security(conn, sec);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_SET_SECURITY_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_set_security, BT_CONN_SET_SECURITY_RPC_CMD,
			 bt_conn_set_security_rpc_handler, NULL);

static void bt_conn_get_security_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	bt_security_t _result;
	struct bt_conn *conn;
	size_t _buffer_size_max = 5;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_get_security(conn);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_uint(&_ctx.encoder, (uint32_t)_result);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_CONN_GET_SECURITY_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_get_security, BT_CONN_GET_SECURITY_RPC_CMD,
			 bt_conn_get_security_rpc_handler, NULL);

static void bt_conn_enc_key_size_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	uint8_t _result;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_enc_key_size(conn);

	ser_rsp_send_uint(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_ENC_KEY_SIZE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_enc_key_size, BT_CONN_ENC_KEY_SIZE_RPC_CMD,
			 bt_conn_enc_key_size_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_SMP) */

static void bt_conn_cb_connected_call(struct bt_conn *conn, uint8_t err)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 5;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, err);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_CONNECTED_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

static void bt_conn_cb_disconnected_call(struct bt_conn *conn, uint8_t reason)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 5;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, reason);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_DISCONNECTED_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

static bool bt_conn_cb_le_param_req_call(struct bt_conn *conn, struct bt_le_conn_param *param)
{
	struct nrf_rpc_cbor_ctx _ctx;
	bool _result;
	size_t _buffer_size_max = 15;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_le_conn_param_enc(&_ctx.encoder, param);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_LE_PARAM_REQ_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_bool, &_result);

	return _result;
}

static void bt_conn_cb_le_param_updated_call(struct bt_conn *conn, uint16_t interval, uint16_t
					     latency, uint16_t timeout)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 12;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, interval);
	ser_encode_uint(&_ctx.encoder, latency);
	ser_encode_uint(&_ctx.encoder, timeout);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_LE_PARAM_UPDATED_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

#if defined(CONFIG_BT_SMP)
static void bt_conn_cb_identity_resolved_call(struct bt_conn *conn, const bt_addr_le_t *rpa, const
					      bt_addr_le_t *identity)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 9;

	_buffer_size_max += rpa ? sizeof(bt_addr_le_t) : 0;
	_buffer_size_max += identity ? sizeof(bt_addr_le_t) : 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_buffer(&_ctx.encoder, rpa, sizeof(bt_addr_le_t));
	ser_encode_buffer(&_ctx.encoder, identity, sizeof(bt_addr_le_t));

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_IDENTITY_RESOLVED_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

static void bt_conn_cb_security_changed_call(struct bt_conn *conn, bt_security_t level,
					     enum bt_security_err err)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 13;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, (uint32_t)level);
	ser_encode_uint(&_ctx.encoder, (uint32_t)err);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_SECURITY_CHANGED_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}
#endif /* defined(CONFIG_BT_SMP) */

#if defined(CONFIG_BT_REMOTE_INFO)
static void bt_conn_cb_remote_info_available_call(struct bt_conn *conn,
						  struct bt_conn_remote_info *remote_info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 3;

	_buffer_size_max += bt_conn_remote_info_buf_size;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	bt_conn_remote_info_enc(&_ctx.encoder, remote_info);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_REMOTE_INFO_AVAILABLE_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}
#endif /* defined(CONFIG_BT_REMOTE_INFO) */

#if defined(CONFIG_BT_USER_PHY_UPDATE)
static void bt_conn_cb_le_phy_updated_call(struct bt_conn *conn, struct bt_conn_le_phy_info *param)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 7;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_conn_le_phy_info_enc(&_ctx.encoder, param);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_LE_PHY_UPDATED_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
static void bt_conn_cb_le_data_len_updated_call(struct bt_conn *conn,
						struct bt_conn_le_data_len_info *info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 15;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_conn_le_data_len_info_enc(&_ctx.encoder, info);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_CONN_CB_LE_DATA_LEN_UPDATED_CALL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}
#endif /* defined(CONFIG_BT_USER_DATA_LEN_UPDATE) */

static struct bt_conn_cb bt_conn_cb_register_data = {

	.connected = bt_conn_cb_connected_call,
	.disconnected = bt_conn_cb_disconnected_call,
	.le_param_req = bt_conn_cb_le_param_req_call,
	.le_param_updated = bt_conn_cb_le_param_updated_call,
#if defined(CONFIG_BT_SMP)
	.identity_resolved = bt_conn_cb_identity_resolved_call,
	.security_changed = bt_conn_cb_security_changed_call,
#endif /* defined(CONFIG_BT_SMP) */
#if defined(CONFIG_BT_REMOTE_INFO)
	.remote_info_available = bt_conn_cb_remote_info_available_call,
#endif /* defined(CONFIG_BT_REMOTE_INFO) */
#if defined(CONFIG_BT_USER_PHY_UPDATE)
	.le_phy_updated = bt_conn_cb_le_phy_updated_call,
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
	.le_data_len_updated = bt_conn_cb_le_data_len_updated_call,
#endif /* defined(CONFIG_BT_USER_PHY_UPDATE) */
};

static void bt_conn_cb_register_on_remote_rpc_handler(CborValue *_value, void *_handler_data)
{
	nrf_rpc_cbor_decoding_done(_value);

	bt_conn_cb_register(&bt_conn_cb_register_data);

	ser_rsp_send_void();
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_cb_register_on_remote,
			 BT_CONN_CB_REGISTER_ON_REMOTE_RPC_CMD,
			 bt_conn_cb_register_on_remote_rpc_handler, NULL);

#if defined(CONFIG_BT_SMP)
static void bt_set_bondable_rpc_handler(CborValue *_value, void *_handler_data)
{
	bool enable;

	enable = ser_decode_bool(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_set_bondable(enable);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_SET_BONDABLE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_set_bondable, BT_SET_BONDABLE_RPC_CMD,
			 bt_set_bondable_rpc_handler, NULL);


static void bt_set_oob_data_flag_rpc_handler(CborValue *_value, void *_handler_data)
{
	bool enable;

	enable = ser_decode_bool(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_set_oob_data_flag(enable);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_SET_OOB_DATA_FLAG_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_set_oob_data_flag, BT_SET_OOB_DATA_FLAG_RPC_CMD,
			 bt_set_oob_data_flag_rpc_handler, NULL);

#if !defined(CONFIG_BT_SMP_SC_PAIR_ONLY)
static void bt_le_oob_set_legacy_tk_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	const uint8_t *tk;
	int _result;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	conn = bt_rpc_decode_bt_conn(_value);
	tk = ser_decode_buffer_into_scratchpad(&_scratchpad);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_oob_set_legacy_tk(conn, tk);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_OOB_SET_LEGACY_TK_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_oob_set_legacy_tk, BT_LE_OOB_SET_LEGACY_TK_RPC_CMD,
			 bt_le_oob_set_legacy_tk_rpc_handler, NULL);
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

static void bt_le_oob_set_sc_data_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	struct bt_le_oob_sc_data _oobd_local_data;
	struct bt_le_oob_sc_data *oobd_local;
	struct bt_le_oob_sc_data _oobd_remote_data;
	struct bt_le_oob_sc_data *oobd_remote;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	if (ser_decode_is_null(_value)) {
		oobd_local = NULL;
		ser_decode_skip(_value);
	} else {
		oobd_local = &_oobd_local_data;
		bt_le_oob_sc_data_dec(_value, oobd_local);
	}
	if (ser_decode_is_null(_value)) {
		oobd_remote = NULL;
		ser_decode_skip(_value);
	} else {
		oobd_remote = &_oobd_remote_data;
		bt_le_oob_sc_data_dec(_value, oobd_remote);
	}

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_oob_set_sc_data(conn, oobd_local, oobd_remote);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_OOB_SET_SC_DATA_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_oob_set_sc_data, BT_LE_OOB_SET_SC_DATA_RPC_CMD,
			 bt_le_oob_set_sc_data_rpc_handler, NULL);

static void bt_le_oob_get_sc_data_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	struct bt_conn *conn;
	size_t _buffer_size_max = 5;

	const struct bt_le_oob_sc_data *oobd_local;
	const struct bt_le_oob_sc_data *oobd_remote;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_oob_get_sc_data(conn, &oobd_local, &oobd_remote);

	_buffer_size_max += bt_le_oob_sc_data_buf_size(oobd_local);
	_buffer_size_max += bt_le_oob_sc_data_buf_size(oobd_remote);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);

		if (!oobd_local) {
			ser_encode_null(&_ctx.encoder);
		} else {
			bt_le_oob_sc_data_enc(&_ctx.encoder, oobd_local);
		}

		if (!oobd_remote) {
			ser_encode_null(&_ctx.encoder);
		} else {
			bt_le_oob_sc_data_enc(&_ctx.encoder, oobd_remote);
		}

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_LE_OOB_GET_SC_DATA_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_oob_get_sc_data, BT_LE_OOB_GET_SC_DATA_RPC_CMD,
			 bt_le_oob_get_sc_data_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_SMP) && !defined(CONFIG_BT_SMP_OOB_LEGACY_PAIR_ONLY) */

#if defined(CONFIG_BT_FIXED_PASSKEY)
static void bt_passkey_set_rpc_handler(CborValue *_value, void *_handler_data)
{
	unsigned int passkey;
	int _result;

	passkey = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_passkey_set(passkey);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_PASSKEY_SET_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_passkey_set, BT_PASSKEY_SET_RPC_CMD,
			 bt_passkey_set_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_FIXED_PASSKEY) */

static struct bt_conn_auth_cb remote_auth_cb;

#if defined(CONFIG_BT_SMP_APP_PAIRING_ACCEPT)
static const size_t bt_conn_pairing_feat_buf_size = 12;

void bt_conn_pairing_feat_enc(CborEncoder *_encoder, const struct bt_conn_pairing_feat *_data)
{
	ser_encode_uint(_encoder, _data->io_capability);
	ser_encode_uint(_encoder, _data->oob_data_flag);
	ser_encode_uint(_encoder, _data->auth_req);
	ser_encode_uint(_encoder, _data->max_enc_key_size);
	ser_encode_uint(_encoder, _data->init_key_dist);
	ser_encode_uint(_encoder, _data->resp_key_dist);
}

struct bt_rpc_auth_cb_pairing_accept_rpc_res {

	enum bt_security_err _result;

};

static void bt_rpc_auth_cb_pairing_accept_rpc_rsp(CborValue *_value, void *_handler_data)
{
	struct bt_rpc_auth_cb_pairing_accept_rpc_res *_res =
		(struct bt_rpc_auth_cb_pairing_accept_rpc_res *)_handler_data;

	_res->_result = (enum bt_security_err)ser_decode_uint(_value);
}

enum bt_security_err bt_rpc_auth_cb_pairing_accept(struct bt_conn *conn,
						   const struct bt_conn_pairing_feat *const feat)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_rpc_auth_cb_pairing_accept_rpc_res _result;
	size_t _buffer_size_max = 15;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_conn_pairing_feat_enc(&_ctx.encoder, feat);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_PAIRING_ACCEPT_RPC_CMD,
				&_ctx, bt_rpc_auth_cb_pairing_accept_rpc_rsp, &_result);

	return _result._result;
}
#endif /* CONFIG_BT_SMP_APP_PAIRING_ACCEPT */

void bt_rpc_auth_cb_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 8;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, passkey);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_PASSKEY_DISPLAY_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_rpc_auth_cb_passkey_entry(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_PASSKEY_ENTRY_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_rpc_auth_cb_passkey_confirm(struct bt_conn *conn, unsigned int passkey)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 8;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, passkey);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_PASSKEY_CONFIRM_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_rpc_auth_cb_oob_data_request(struct bt_conn *conn, struct bt_conn_oob_info *info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 6;

	_buffer_size_max += info ? sizeof(struct bt_conn_oob_info) : 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_buffer(&_ctx.encoder, info, sizeof(struct bt_conn_oob_info));

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_OOB_DATA_REQUEST_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_rpc_auth_cb_cancel(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_CANCEL_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_rpc_auth_cb_pairing_confirm(struct bt_conn *conn)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 3;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_PAIRING_CONFIRM_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_rpc_auth_cb_pairing_complete(struct bt_conn *conn, bool bonded)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 4;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_bool(&_ctx.encoder, bonded);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_PAIRING_COMPLETE_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_rpc_auth_cb_pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 8;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	ser_encode_uint(&_ctx.encoder, (uint32_t)reason);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_AUTH_CB_PAIRING_FAILED_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

static int bt_conn_auth_cb_register_on_remote(uint16_t flags)
{
#if defined(CONFIG_BT_SMP_APP_PAIRING_ACCEPT)
	remote_auth_cb.pairing_accept = (flags & FLAG_PAIRING_ACCEPT_PRESENT) ?
					bt_rpc_auth_cb_pairing_accept : NULL;
#endif /* CONFIG_BT_SMP_APP_PAIRING_ACCEPT */
	remote_auth_cb.passkey_display = (flags & FLAG_PASSKEY_DISPLAY_PRESENT) ?
					 bt_rpc_auth_cb_passkey_display : NULL;
	remote_auth_cb.passkey_entry = (flags & FLAG_PASSKEY_ENTRY_PRESENT) ?
				       bt_rpc_auth_cb_passkey_entry : NULL;
	remote_auth_cb.passkey_confirm = (flags & FLAG_PASSKEY_CONFIRM_PRESENT) ?
					 bt_rpc_auth_cb_passkey_confirm : NULL;
	remote_auth_cb.oob_data_request = (flags & FLAG_OOB_DATA_REQUEST_PRESENT) ?
					  bt_rpc_auth_cb_oob_data_request : NULL;
	remote_auth_cb.cancel = (flags & FLAG_CANCEL_PRESENT) ? bt_rpc_auth_cb_cancel : NULL;
	remote_auth_cb.pairing_confirm = (flags & FLAG_PAIRING_CONFIRM_PRESENT) ?
					 bt_rpc_auth_cb_pairing_confirm : NULL;
	remote_auth_cb.pairing_complete = (flags & FLAG_PAIRING_COMPLETE_PRESENT) ?
					  bt_rpc_auth_cb_pairing_complete : NULL;
	remote_auth_cb.pairing_failed = (flags & FLAG_PAIRING_FAILED_PRESENT) ?
					bt_rpc_auth_cb_pairing_failed : NULL;

	return bt_conn_auth_cb_register(&remote_auth_cb);
}

static void bt_conn_auth_cb_register_on_remote_rpc_handler(CborValue *_value, void *_handler_data)
{
	uint16_t flags;
	int _result;

	flags = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_auth_cb_register_on_remote(flags);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_AUTH_CB_REGISTER_ON_REMOTE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_auth_cb_register_on_remote,
			 BT_CONN_AUTH_CB_REGISTER_ON_REMOTE_RPC_CMD,
			 bt_conn_auth_cb_register_on_remote_rpc_handler, NULL);

static void bt_conn_auth_passkey_entry_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	unsigned int passkey;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	passkey = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_auth_passkey_entry(conn, passkey);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_AUTH_PASSKEY_ENTRY_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_auth_passkey_entry, BT_CONN_AUTH_PASSKEY_ENTRY_RPC_CMD,
			 bt_conn_auth_passkey_entry_rpc_handler, NULL);

static void bt_conn_auth_cancel_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_auth_cancel(conn);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_AUTH_CANCEL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_auth_cancel, BT_CONN_AUTH_CANCEL_RPC_CMD,
			 bt_conn_auth_cancel_rpc_handler, NULL);

static void bt_conn_auth_passkey_confirm_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_auth_passkey_confirm(conn);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_AUTH_PASSKEY_CONFIRM_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_auth_passkey_confirm,
			 BT_CONN_AUTH_PASSKEY_CONFIRM_RPC_CMD,
			 bt_conn_auth_passkey_confirm_rpc_handler, NULL);

static void bt_conn_auth_pairing_confirm_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_conn_auth_pairing_confirm(conn);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_CONN_AUTH_PAIRING_CONFIRM_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_conn_auth_pairing_confirm,
			 BT_CONN_AUTH_PAIRING_CONFIRM_RPC_CMD,
			 bt_conn_auth_pairing_confirm_rpc_handler, NULL);

#endif /* defined(CONFIG_BT_SMP) */
