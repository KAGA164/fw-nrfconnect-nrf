/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <bluetooth/bluetooth.h>

#include <zephyr.h>

#include <nrf_rpc_cbor.h>

#include "bt_rpc_common.h"
#include "serialize.h"
#include "cbkproxy.h"

static void report_decoding_error(uint8_t cmd_evt_id, void *data)
{
	nrf_rpc_err(-EBADMSG, NRF_RPC_ERR_SRC_RECV, &bt_rpc_grp, cmd_evt_id,
		    NRF_RPC_PACKET_TYPE_CMD);
}

static void bt_rpc_get_check_list_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t size;
	uint8_t *data;
	size_t _buffer_size_max = 5;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	size = ser_decode_uint(_value);
	data = ser_scratchpad_add(&_scratchpad, sizeof(uint8_t) * size);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_rpc_get_check_list(data, size);

	_buffer_size_max += sizeof(uint8_t) * size;

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_buffer(&_ctx.encoder, data, sizeof(uint8_t) * size);

		SER_SCRATCHPAD_FREE(&_scratchpad);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_RPC_GET_CHECK_LIST_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);

}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_get_check_list, BT_RPC_GET_CHECK_LIST_RPC_CMD,
			 bt_rpc_get_check_list_rpc_handler, NULL);


static inline void bt_ready_cb_t_callback(int err,
					  uint32_t callback_slot)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 8;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_int(&_ctx.encoder, err);
	ser_encode_callback_call(&_ctx.encoder, callback_slot);

	nrf_rpc_cbor_evt_no_err(&bt_rpc_grp,
				BT_READY_CB_T_CALLBACK_RPC_EVT, &_ctx);
}

CBKPROXY_HANDLER(bt_ready_cb_t_encoder, bt_ready_cb_t_callback, (int err), (err));

static void bt_enable_rpc_handler(CborValue *_value, void *_handler_data)
{
	bt_ready_cb_t cb;
	int _result;

	cb = (bt_ready_cb_t)ser_decode_callback(_value, bt_ready_cb_t_encoder);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_enable(cb);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_ENABLE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_enable, BT_ENABLE_RPC_CMD,
			 bt_enable_rpc_handler, NULL);



#if defined(CONFIG_BT_DEVICE_NAME_DYNAMIC)

static void bt_set_name_rpc_handler(CborValue *_value, void *_handler_data)
{
	const char *name;
	int _result;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	name = ser_decode_str_into_scratchpad(&_scratchpad);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_set_name(name);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_SET_NAME_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_set_name, BT_SET_NAME_RPC_CMD,
			 bt_set_name_rpc_handler, NULL);

static bool bt_get_name_out(char *name, size_t size)
{
	const char *src;

	src = bt_get_name();

	if (!src) {
		strcpy(name, "");
		return false;
	}

	strncpy(name, src, size);
	return true;
}

static void bt_get_name_out_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	bool _result;
	size_t size;
	size_t _name_strlen;
	char *name;
	size_t _buffer_size_max = 6;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	size = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	name = ser_scratchpad_add(&_scratchpad, size);

	_result = bt_get_name_out(name, size);

	_name_strlen = strlen(name);
	_buffer_size_max += _name_strlen;

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_bool(&_ctx.encoder, _result);
		ser_encode_str(&_ctx.encoder, name, _name_strlen);

		SER_SCRATCHPAD_FREE(&_scratchpad);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_GET_NAME_OUT_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_get_name_out, BT_GET_NAME_OUT_RPC_CMD,
			 bt_get_name_out_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_DEVICE_NAME_DYNAMIC) */

static void bt_id_get_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _count_data;
	size_t *count = &_count_data;
	bt_addr_le_t *addrs;
	size_t _buffer_size_max = 10;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	*count = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	addrs = ser_scratchpad_add(&_scratchpad, *count * sizeof(bt_addr_le_t));

	bt_id_get(addrs, count);

	_buffer_size_max += *count * sizeof(bt_addr_le_t);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_uint(&_ctx.encoder, *count);
		ser_encode_buffer(&_ctx.encoder, addrs, *count * sizeof(bt_addr_le_t));

		SER_SCRATCHPAD_FREE(&_scratchpad);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_ID_GET_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_id_get, BT_ID_GET_RPC_CMD,
			 bt_id_get_rpc_handler, NULL);

static void bt_id_create_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	bt_addr_le_t _addr_data;
	bt_addr_le_t *addr;
	uint8_t *irk;
	size_t _buffer_size_max = 13;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));
	irk = ser_decode_buffer_into_scratchpad(&_scratchpad);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_id_create(addr, irk);

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;
	_buffer_size_max += !irk ? 0 : sizeof(uint8_t) * 16;

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);
		ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));
		ser_encode_buffer(&_ctx.encoder, irk, sizeof(uint8_t) * 16);

		SER_SCRATCHPAD_FREE(&_scratchpad);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_ID_CREATE_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_id_create, BT_ID_CREATE_RPC_CMD,
			 bt_id_create_rpc_handler, NULL);

static void bt_id_reset_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	uint8_t id;
	bt_addr_le_t _addr_data;
	bt_addr_le_t *addr;
	uint8_t *irk;
	size_t _buffer_size_max = 13;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	id = ser_decode_uint(_value);
	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));
	irk = ser_decode_buffer_into_scratchpad(&_scratchpad);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_id_reset(id, addr, irk);

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;
	_buffer_size_max += !irk ? 0 : sizeof(uint8_t) * 16;

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);
		ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));
		ser_encode_buffer(&_ctx.encoder, irk, sizeof(uint8_t) * 16);

		SER_SCRATCHPAD_FREE(&_scratchpad);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_ID_RESET_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_id_reset, BT_ID_RESET_RPC_CMD,
			 bt_id_reset_rpc_handler, NULL);

static void bt_id_delete_rpc_handler(CborValue *_value, void *_handler_data)
{
	uint8_t id;
	int _result;

	id = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_id_delete(id);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_ID_DELETE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_id_delete, BT_ID_DELETE_RPC_CMD,
			 bt_id_delete_rpc_handler, NULL);

void bt_data_dec(struct ser_scratchpad *_scratchpad, struct bt_data *_data)
{
	CborValue *_value = _scratchpad->value;

	_data->type = ser_decode_uint(_value);
	_data->data_len = ser_decode_uint(_value);
	_data->data = ser_decode_buffer_into_scratchpad(_scratchpad);
}

void bt_le_scan_param_dec(CborValue *_value, struct bt_le_scan_param *_data)
{
	_data->type = ser_decode_uint(_value);
	_data->options = ser_decode_uint(_value);
	_data->interval = ser_decode_uint(_value);
	_data->window = ser_decode_uint(_value);
	_data->timeout = ser_decode_uint(_value);
	_data->interval_coded = ser_decode_uint(_value);
	_data->window_coded = ser_decode_uint(_value);
}


size_t net_buf_simple_sp_size(struct net_buf_simple *_data)
{
	return SCRATCHPAD_ALIGN(_data->len);
}

size_t net_buf_simple_buf_size(struct net_buf_simple *_data)
{
	return 3 + _data->len;
}

void net_buf_simple_enc(CborEncoder *_encoder, struct net_buf_simple *_data)
{
	ser_encode_buffer(_encoder, _data->data, _data->len);
}


static inline void bt_le_scan_cb_t_callback(const bt_addr_le_t *addr,
					    int8_t rssi, uint8_t adv_type,
					    struct net_buf_simple *buf,
					    uint32_t callback_slot)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 15;

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;
	_buffer_size_max += net_buf_simple_buf_size(buf);

	_scratchpad_size += net_buf_simple_sp_size(buf);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));
	ser_encode_int(&_ctx.encoder, rssi);
	ser_encode_uint(&_ctx.encoder, adv_type);
	net_buf_simple_enc(&_ctx.encoder, buf);
	ser_encode_callback_call(&_ctx.encoder, callback_slot);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SCAN_CB_T_CALLBACK_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}


CBKPROXY_HANDLER(bt_le_scan_cb_t_encoder, bt_le_scan_cb_t_callback,
		 (const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type,
		  struct net_buf_simple *buf), (addr, rssi, adv_type, buf));

void bt_le_adv_param_dec(struct ser_scratchpad *_scratchpad, struct bt_le_adv_param *_data)
{
	CborValue *_value = _scratchpad->value;

	_data->id = ser_decode_uint(_value);
	_data->sid = ser_decode_uint(_value);
	_data->secondary_max_skip = ser_decode_uint(_value);
	_data->options = ser_decode_uint(_value);
	_data->interval_min = ser_decode_uint(_value);
	_data->interval_max = ser_decode_uint(_value);
	_data->peer = ser_decode_buffer_into_scratchpad(_scratchpad);
}

static void bt_le_adv_start_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_adv_param param;
	size_t ad_len;
	struct bt_data *ad;
	size_t sd_len;
	struct bt_data *sd;
	int _result;
	struct ser_scratchpad _scratchpad;
	size_t _i;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	bt_le_adv_param_dec(&_scratchpad, &param);
	ad_len = ser_decode_uint(_value);
	ad = ser_scratchpad_add(&_scratchpad, ad_len * sizeof(struct bt_data));
	if (ad == NULL) {
		goto decoding_error;
	}
	for (_i = 0; _i < ad_len; _i++) {
		bt_data_dec(&_scratchpad, &ad[_i]);
	}
	sd_len = ser_decode_uint(_value);
	sd = ser_scratchpad_add(&_scratchpad, sd_len * sizeof(struct bt_data));
	if (sd == NULL) {
		goto decoding_error;
	}
	for (_i = 0; _i < sd_len; _i++) {
		bt_data_dec(&_scratchpad, &sd[_i]);
	}

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_adv_start(&param, ad, ad_len, sd, sd_len);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_ADV_START_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_adv_start, BT_LE_ADV_START_RPC_CMD,
			 bt_le_adv_start_rpc_handler, NULL);

static void bt_le_adv_update_data_rpc_handler(CborValue *_value, void *_handler_data)
{
	size_t ad_len;
	struct bt_data *ad;
	size_t sd_len;
	struct bt_data *sd;
	int _result;
	struct ser_scratchpad _scratchpad;
	size_t _i;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	ad_len = ser_decode_uint(_value);
	ad = ser_scratchpad_add(&_scratchpad, ad_len * sizeof(struct bt_data));
	if (ad == NULL) {
		goto decoding_error;
	}
	for (_i = 0; _i < ad_len; _i++) {
		bt_data_dec(&_scratchpad, &ad[_i]);
	}
	sd_len = ser_decode_uint(_value);
	sd = ser_scratchpad_add(&_scratchpad, sd_len * sizeof(struct bt_data));
	if (sd == NULL) {
		goto decoding_error;
	}
	for (_i = 0; _i < sd_len; _i++) {
		bt_data_dec(&_scratchpad, &sd[_i]);
	}

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_adv_update_data(ad, ad_len, sd, sd_len);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_ADV_UPDATE_DATA_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_adv_update_data, BT_LE_ADV_UPDATE_DATA_RPC_CMD,
			 bt_le_adv_update_data_rpc_handler, NULL);

static void bt_le_adv_stop_rpc_handler(CborValue *_value, void *_handler_data)
{
	int _result;

	nrf_rpc_cbor_decoding_done(_value);

	_result = bt_le_adv_stop();

	ser_rsp_send_int(_result);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_adv_stop, BT_LE_ADV_STOP_RPC_CMD,
			 bt_le_adv_stop_rpc_handler, NULL);

size_t bt_le_oob_buf_size(const struct bt_le_oob *_data)
{
	size_t _buffer_size_max = 13;

	_buffer_size_max += sizeof(bt_addr_le_t);
	_buffer_size_max += 16 * sizeof(uint8_t);
	_buffer_size_max += 16 * sizeof(uint8_t);
	return _buffer_size_max;

}

void bt_le_oob_enc(CborEncoder *_encoder, const struct bt_le_oob *_data)
{
	ser_encode_buffer(_encoder, &_data->addr, sizeof(bt_addr_le_t));
	ser_encode_buffer(_encoder, _data->le_sc_data.r, 16 * sizeof(uint8_t));
	ser_encode_buffer(_encoder, _data->le_sc_data.c, 16 * sizeof(uint8_t));
}

#if defined(CONFIG_BT_EXT_ADV)

K_MEM_SLAB_DEFINE(bt_rpc_ext_adv_cb_cache,
		  sizeof(struct bt_le_ext_adv_cb),
		  CONFIG_BT_EXT_ADV_MAX_ADV_SET,
		  sizeof(void *));
static struct bt_le_ext_adv_cb *ext_adv_cb_cache_map[CONFIG_BT_EXT_ADV_MAX_ADV_SET];

void bt_le_ext_adv_sent_info_enc(CborEncoder *_encoder, const struct bt_le_ext_adv_sent_info *_data)
{
	ser_encode_uint(_encoder, _data->num_sent);
}

void bt_le_ext_adv_connected_info_enc(CborEncoder *_encoder,
				      const struct bt_le_ext_adv_connected_info *_data)
{
	bt_rpc_encode_bt_conn(_encoder, _data->conn);
}

size_t bt_le_ext_adv_scanned_info_sp_size(const struct bt_le_ext_adv_scanned_info *_data)
{
	size_t _scratchpad_size = 0;

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(bt_addr_le_t));

	return _scratchpad_size;
}

size_t bt_le_ext_adv_scanned_info_buf_size(const struct bt_le_ext_adv_scanned_info *_data)
{
	size_t _buffer_size_max = 3;

	_buffer_size_max += sizeof(bt_addr_le_t);

	return _buffer_size_max;
}

void bt_le_ext_adv_scanned_info_enc(CborEncoder *_encoder,
				    const struct bt_le_ext_adv_scanned_info *_data)
{
	ser_encode_buffer(_encoder, _data->addr, sizeof(bt_addr_le_t));
}

static inline
void bt_le_ext_adv_cb_sent_callback(struct bt_le_ext_adv *adv,
				    struct bt_le_ext_adv_sent_info *info,
				    uint32_t callback_slot)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 10;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);
	bt_le_ext_adv_sent_info_enc(&_ctx.encoder, info);
	ser_encode_callback_call(&_ctx.encoder, callback_slot);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_CB_SENT_CALLBACK_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

CBKPROXY_HANDLER(bt_le_ext_adv_cb_sent_encoder, bt_le_ext_adv_cb_sent_callback,
		 (struct bt_le_ext_adv *adv, struct bt_le_ext_adv_sent_info *info),
		 (adv, info));

static inline
void bt_le_ext_adv_cb_connected_callback(struct bt_le_ext_adv *adv,
					 struct bt_le_ext_adv_connected_info *info,
					 uint32_t callback_slot)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 11;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);
	bt_le_ext_adv_connected_info_enc(&_ctx.encoder, info);
	ser_encode_callback_call(&_ctx.encoder, callback_slot);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_CB_CONNECTED_CALLBACK_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

CBKPROXY_HANDLER(bt_le_ext_adv_cb_connected_encoder,
		 bt_le_ext_adv_cb_connected_callback,
		 (struct bt_le_ext_adv *adv, struct bt_le_ext_adv_connected_info *info),
		 (adv, info));

static inline
void bt_le_ext_adv_cb_scanned_callback(struct bt_le_ext_adv *adv,
				       struct bt_le_ext_adv_scanned_info *info,
				       uint32_t callback_slot)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 13;

	_buffer_size_max += bt_le_ext_adv_scanned_info_buf_size(info);

	_scratchpad_size += bt_le_ext_adv_scanned_info_sp_size(info);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);
	bt_le_ext_adv_scanned_info_enc(&_ctx.encoder, info);
	ser_encode_callback_call(&_ctx.encoder, callback_slot);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_CB_SCANNED_CALLBACK_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

CBKPROXY_HANDLER(bt_le_ext_adv_cb_scanned_encoder,
		 bt_le_ext_adv_cb_scanned_callback,
		 (struct bt_le_ext_adv *adv, struct bt_le_ext_adv_scanned_info *info),
		 (adv, info));

void bt_le_ext_adv_cb_dec(CborValue *_value, struct bt_le_ext_adv_cb *_data)
{
	_data->sent = (bt_le_ext_adv_cb_sent)ser_decode_callback(_value,
								 bt_le_ext_adv_cb_sent_encoder);
	_data->connected = (bt_le_ext_adv_cb_connected)ser_decode_callback(_value,
								bt_le_ext_adv_cb_connected_encoder);
	_data->scanned = (bt_le_ext_adv_cb_scanned)ser_decode_callback(_value,
								bt_le_ext_adv_cb_scanned_encoder);
}

static void bt_le_ext_adv_create_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	struct bt_le_adv_param param;
	struct bt_le_ext_adv *_adv_data;
	struct bt_le_ext_adv **adv = &_adv_data;
	size_t _buffer_size_max = 10;
	struct ser_scratchpad _scratchpad;

	size_t adv_index;
	struct bt_le_ext_adv_cb *cb = NULL;

	_result = 0;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	bt_le_adv_param_dec(&_scratchpad, &param);

	if (ser_decode_is_undefined(_value)) {
		ser_decode_skip(_value);
	} else {
		_result = k_mem_slab_alloc(&bt_rpc_ext_adv_cb_cache, (void **)&cb, K_NO_WAIT);
	}

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (_result == 0) {
		_result = bt_le_ext_adv_create(&param, cb, adv);
	}

	if (_result == 0) {
		adv_index = bt_le_ext_adv_get_index(_adv_data);
		ext_adv_cb_cache_map[adv_index] = cb;
	} else {
		k_mem_slab_free(&bt_rpc_ext_adv_cb_cache, (void **)&cb);
	}

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);
		ser_encode_uint(&_ctx.encoder, (uintptr_t)(*adv));

		SER_SCRATCHPAD_FREE(&_scratchpad);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_CREATE_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);

	if (_result == 0) {
		k_mem_slab_free(&bt_rpc_ext_adv_cb_cache, (void **)&cb);
	}
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_create, BT_LE_EXT_ADV_CREATE_RPC_CMD,
			 bt_le_ext_adv_create_rpc_handler, NULL);


void bt_le_ext_adv_start_param_dec(CborValue *_value, struct bt_le_ext_adv_start_param *_data)
{
	_data->timeout = ser_decode_uint(_value);
	_data->num_events = ser_decode_uint(_value);
}

static void bt_le_ext_adv_start_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	struct bt_le_ext_adv_start_param param;
	int _result;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);
	bt_le_ext_adv_start_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_ext_adv_start(adv, &param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_START_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_start, BT_LE_EXT_ADV_START_RPC_CMD,
			 bt_le_ext_adv_start_rpc_handler, NULL);

static void bt_le_ext_adv_stop_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	int _result;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_ext_adv_stop(adv);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_STOP_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_stop, BT_LE_EXT_ADV_STOP_RPC_CMD,
			 bt_le_ext_adv_stop_rpc_handler, NULL);

static void bt_le_ext_adv_set_data_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	size_t ad_len;
	struct bt_data *ad;
	size_t sd_len;
	struct bt_data *sd;
	int _result;
	struct ser_scratchpad _scratchpad;
	size_t _i;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);
	ad_len = ser_decode_uint(_value);
	ad = ser_scratchpad_add(&_scratchpad, ad_len * sizeof(struct bt_data));
	if (ad == NULL) {
		goto decoding_error;
	}
	for (_i = 0; _i < ad_len; _i++) {
		bt_data_dec(&_scratchpad, &ad[_i]);
	}
	sd_len = ser_decode_uint(_value);
	sd = ser_scratchpad_add(&_scratchpad, sd_len * sizeof(struct bt_data));
	if (sd == NULL) {
		goto decoding_error;
	}
	for (_i = 0; _i < sd_len; _i++) {
		bt_data_dec(&_scratchpad, &sd[_i]);
	}

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_ext_adv_set_data(adv, ad, ad_len, sd, sd_len);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_SET_DATA_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_set_data, BT_LE_EXT_ADV_SET_DATA_RPC_CMD,
			 bt_le_ext_adv_set_data_rpc_handler, NULL);

static void bt_le_ext_adv_update_param_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	struct bt_le_adv_param param;
	int _result;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);
	bt_le_adv_param_dec(&_scratchpad, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_ext_adv_update_param(adv, &param);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_UPDATE_PARAM_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_update_param, BT_LE_EXT_ADV_UPDATE_PARAM_RPC_CMD,
			 bt_le_ext_adv_update_param_rpc_handler, NULL);

static void bt_le_ext_adv_delete_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	int _result;

	size_t adv_index;
	struct bt_le_ext_adv_cb *cb;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	adv_index = bt_le_ext_adv_get_index(adv);

	_result = bt_le_ext_adv_delete(adv);

	if (adv_index <= CONFIG_BT_EXT_ADV_MAX_ADV_SET) {
		cb = ext_adv_cb_cache_map[adv_index];
		k_mem_slab_free(&bt_rpc_ext_adv_cb_cache, (void **)&cb);
	}

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_DELETE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_delete, BT_LE_EXT_ADV_DELETE_RPC_CMD,
			 bt_le_ext_adv_delete_rpc_handler, NULL);

static void bt_le_ext_adv_get_index_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	uint8_t _result;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_ext_adv_get_index(adv);

	ser_rsp_send_uint(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_GET_INDEX_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_get_index, BT_LE_EXT_ADV_GET_INDEX_RPC_CMD,
			 bt_le_ext_adv_get_index_rpc_handler, NULL);

void bt_le_ext_adv_info_dec(CborValue *_value, struct bt_le_ext_adv_info *_data)
{
	_data->id = ser_decode_uint(_value);
	_data->tx_power = ser_decode_int(_value);
}

static void bt_le_ext_adv_get_info_rpc_handler(CborValue *_value, void *_handler_data)
{
	const struct bt_le_ext_adv *adv;
	struct bt_le_ext_adv_info info;
	int _result;

	adv = (const struct bt_le_ext_adv *)ser_decode_uint(_value);
	bt_le_ext_adv_info_dec(_value, &info);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_ext_adv_get_info(adv, &info);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_GET_INFO_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_get_info, BT_LE_EXT_ADV_GET_INFO_RPC_CMD,
			 bt_le_ext_adv_get_info_rpc_handler, NULL);

static void bt_le_ext_adv_oob_get_local_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	struct bt_le_ext_adv *adv;
	struct bt_le_oob _oob_data;
	struct bt_le_oob *oob = &_oob_data;
	size_t _buffer_size_max = 5;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_ext_adv_oob_get_local(adv, oob);

	_buffer_size_max += bt_le_oob_buf_size(oob);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);
		bt_le_oob_enc(&_ctx.encoder, oob);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_LE_EXT_ADV_OOB_GET_LOCAL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_oob_get_local,
			 BT_LE_EXT_ADV_OOB_GET_LOCAL_RPC_CMD,
			 bt_le_ext_adv_oob_get_local_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_EXT_ADV) */

#if defined(CONFIG_BT_OBSERVER)
static void bt_le_scan_start_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_scan_param param;
	bt_le_scan_cb_t *cb;
	int _result;

	bt_le_scan_param_dec(_value, &param);
	cb = (bt_le_scan_cb_t *)ser_decode_callback(_value, bt_le_scan_cb_t_encoder);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_scan_start(&param, cb);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_SCAN_START_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_scan_start, BT_LE_SCAN_START_RPC_CMD,
			 bt_le_scan_start_rpc_handler, NULL);

static void bt_le_scan_stop_rpc_handler(CborValue *_value, void *_handler_data)
{
	int _result;

	nrf_rpc_cbor_decoding_done(_value);

	_result = bt_le_scan_stop();

	ser_rsp_send_int(_result);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_scan_stop, BT_LE_SCAN_STOP_RPC_CMD,
			 bt_le_scan_stop_rpc_handler, NULL);

size_t bt_le_scan_recv_info_sp_size(const struct bt_le_scan_recv_info *_data)
{
	size_t _scratchpad_size = 0;

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(bt_addr_le_t));

	return _scratchpad_size;
}

size_t bt_le_scan_recv_info_buf_size(const struct bt_le_scan_recv_info *_data)
{
	size_t _buffer_size_max = 21;

	_buffer_size_max += sizeof(bt_addr_le_t);

	return _buffer_size_max;
}

void bt_le_scan_recv_info_enc(CborEncoder *_encoder, const struct bt_le_scan_recv_info *_data)
{
	ser_encode_buffer(_encoder, _data->addr, sizeof(bt_addr_le_t));
	ser_encode_uint(_encoder, _data->sid);
	ser_encode_int(_encoder, _data->rssi);
	ser_encode_int(_encoder, _data->tx_power);
	ser_encode_uint(_encoder, _data->adv_type);
	ser_encode_uint(_encoder, _data->adv_props);
	ser_encode_uint(_encoder, _data->interval);
	ser_encode_uint(_encoder, _data->primary_phy);
	ser_encode_uint(_encoder, _data->secondary_phy);
}

void bt_le_scan_cb_recv(const struct bt_le_scan_recv_info *info,
			struct net_buf_simple *buf)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 5;

	_buffer_size_max += bt_le_scan_recv_info_buf_size(info);
	_buffer_size_max += net_buf_simple_buf_size(buf);

	_scratchpad_size += bt_le_scan_recv_info_sp_size(info);
	_scratchpad_size += net_buf_simple_sp_size(buf);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	bt_le_scan_recv_info_enc(&_ctx.encoder, info);
	net_buf_simple_enc(&_ctx.encoder, buf);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SCAN_CB_RECV_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_le_scan_cb_timeout(void)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SCAN_CB_TIMEOUT_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

static struct bt_le_scan_cb scan_cb = {
	.recv = bt_le_scan_cb_recv,
	.timeout = bt_le_scan_cb_timeout,
};

static void bt_le_scan_cb_register_on_remote_rpc_handler(CborValue *_value, void *_handler_data)
{
	nrf_rpc_cbor_decoding_done(_value);

	bt_le_scan_cb_register(&scan_cb);

	ser_rsp_send_void();
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_scan_cb_register_on_remote,
			 BT_LE_SCAN_CB_REGISTER_ON_REMOTE_RPC_CMD,
			 bt_le_scan_cb_register_on_remote_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_OBSERVER) */

#if defined(CONFIG_BT_WHITELIST)
static void bt_le_whitelist_add_rpc_handler(CborValue *_value, void *_handler_data)
{
	bt_addr_le_t _addr_data;
	const bt_addr_le_t *addr;
	int _result;

	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_whitelist_add(addr);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_WHITELIST_ADD_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_whitelist_add, BT_LE_WHITELIST_ADD_RPC_CMD,
			 bt_le_whitelist_add_rpc_handler, NULL);

static void bt_le_whitelist_rem_rpc_handler(CborValue *_value, void *_handler_data)
{
	bt_addr_le_t _addr_data;
	const bt_addr_le_t *addr;
	int _result;

	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_whitelist_rem(addr);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_WHITELIST_REM_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_whitelist_rem, BT_LE_WHITELIST_REM_RPC_CMD,
			 bt_le_whitelist_rem_rpc_handler, NULL);

static void bt_le_whitelist_clear_rpc_handler(CborValue *_value, void *_handler_data)
{
	int _result;

	nrf_rpc_cbor_decoding_done(_value);

	_result = bt_le_whitelist_clear();

	ser_rsp_send_int(_result);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_whitelist_clear, BT_LE_WHITELIST_CLEAR_RPC_CMD,
			 bt_le_whitelist_clear_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_WHITELIST) */

static void bt_le_set_chan_map_rpc_handler(CborValue *_value, void *_handler_data)
{
	uint8_t *chan_map;
	int _result;
	struct ser_scratchpad _scratchpad;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	chan_map = ser_decode_buffer_into_scratchpad(&_scratchpad);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_set_chan_map(chan_map);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_SET_CHAN_MAP_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_set_chan_map, BT_LE_SET_CHAN_MAP_RPC_CMD,
			 bt_le_set_chan_map_rpc_handler, NULL);

static void bt_le_oob_get_local_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	uint8_t id;
	struct bt_le_oob _oob_data;
	struct bt_le_oob *oob = &_oob_data;
	size_t _buffer_size_max = 5;

	id = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_oob_get_local(id, oob);

	_buffer_size_max += bt_le_oob_buf_size(oob);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);
		bt_le_oob_enc(&_ctx.encoder, oob);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_LE_OOB_GET_LOCAL_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_oob_get_local, BT_LE_OOB_GET_LOCAL_RPC_CMD,
			 bt_le_oob_get_local_rpc_handler, NULL);

#if defined(CONFIG_BT_CONN)
static void bt_unpair_rpc_handler(CborValue *_value, void *_handler_data)
{
	uint8_t id;
	bt_addr_le_t _addr_data;
	const bt_addr_le_t *addr;
	int _result;

	id = ser_decode_uint(_value);
	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_unpair(id, addr);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_UNPAIR_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_unpair, BT_UNPAIR_RPC_CMD,
			 bt_unpair_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_CONN) */

#if (defined(CONFIG_BT_CONN) && defined(CONFIG_BT_SMP))
size_t bt_bond_info_buf_size(const struct bt_bond_info *_data)
{
	size_t _buffer_size_max = 3;

	_buffer_size_max += sizeof(bt_addr_le_t);

	return _buffer_size_max;
}

void bt_bond_info_enc(CborEncoder *_encoder, const struct bt_bond_info *_data)
{
	ser_encode_buffer(_encoder, &_data->addr, sizeof(bt_addr_le_t));
}

static inline void bt_foreach_bond_cb_callback(const struct bt_bond_info *info,
					       void *user_data,
					       uint32_t callback_slot)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 8;

	_buffer_size_max += bt_bond_info_buf_size(info);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	bt_bond_info_enc(&_ctx.encoder, info);
	ser_encode_uint(&_ctx.encoder, (uintptr_t)user_data);
	ser_encode_callback_call(&_ctx.encoder, callback_slot);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_FOREACH_BOND_CB_CALLBACK_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

CBKPROXY_HANDLER(bt_foreach_bond_cb_encoder, bt_foreach_bond_cb_callback,
		 (const struct bt_bond_info *info, void *user_data), (info, user_data));

static void bt_foreach_bond_rpc_handler(CborValue *_value, void *_handler_data)
{
	uint8_t id;
	bt_foreach_bond_cb func;
	void *user_data;

	id = ser_decode_uint(_value);
	func = (bt_foreach_bond_cb)ser_decode_callback(_value, bt_foreach_bond_cb_encoder);
	user_data = (void *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	bt_foreach_bond(id, func, user_data);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_FOREACH_BOND_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_foreach_bond, BT_FOREACH_BOND_RPC_CMD,
			 bt_foreach_bond_rpc_handler, NULL);
#endif /* (defined(CONFIG_BT_CONN) && defined(CONFIG_BT_SMP)) */

#if defined(CONFIG_BT_PER_ADV)
static void bt_le_per_adv_list_clear_rpc_handler(CborValue *_value, void *_handler_data)
{
	int _result;

	nrf_rpc_cbor_decoding_done(_value);

	_result = bt_le_per_adv_list_clear();

	ser_rsp_send_int(_result);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_list_clear, BT_LE_PER_ADV_LIST_CLEAR_RPC_CMD,
			 bt_le_per_adv_list_clear_rpc_handler, NULL);

static void bt_le_per_adv_list_add_rpc_handler(CborValue *_value, void *_handler_data)
{
	bt_addr_le_t _addr_data;
	const bt_addr_le_t *addr;
	uint8_t sid;
	int _result;

	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));
	sid = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_list_add(addr, sid);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_LIST_ADD_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_list_add, BT_LE_PER_ADV_LIST_ADD_RPC_CMD,
			 bt_le_per_adv_list_add_rpc_handler, NULL);

static void bt_le_per_adv_list_remove_rpc_handler(CborValue *_value, void *_handler_data)
{
	bt_addr_le_t _addr_data;
	const bt_addr_le_t *addr;
	uint8_t sid;
	int _result;

	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));
	sid = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_list_remove(addr, sid);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_LIST_REMOVE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_list_remove, BT_LE_PER_ADV_LIST_REMOVE_RPC_CMD,
			 bt_le_per_adv_list_remove_rpc_handler, NULL);

void bt_le_per_adv_param_dec(CborValue *_value, struct bt_le_per_adv_param *_data)
{
	_data->interval_min = ser_decode_uint(_value);
	_data->interval_max = ser_decode_uint(_value);
	_data->options = ser_decode_uint(_value);
}

static void bt_le_per_adv_set_param_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	struct bt_le_per_adv_param param;
	int _result;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);
	bt_le_per_adv_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_set_param(adv, &param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SET_PARAM_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_set_param, BT_LE_PER_ADV_SET_PARAM_RPC_CMD,
			 bt_le_per_adv_set_param_rpc_handler, NULL);

static void bt_le_per_adv_set_data_rpc_handler(CborValue *_value, void *_handler_data)
{
	const struct bt_le_ext_adv *adv;
	size_t ad_len;
	struct bt_data *ad;
	int _result;
	struct ser_scratchpad _scratchpad;
	size_t _i;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	adv = (const struct bt_le_ext_adv *)ser_decode_uint(_value);
	ad_len = ser_decode_uint(_value);
	ad = ser_scratchpad_add(&_scratchpad, ad_len * sizeof(struct bt_data));
	if (ad == NULL) {
		goto decoding_error;
	}
	for (_i = 0; _i < ad_len; _i++) {
		bt_data_dec(&_scratchpad, &ad[_i]);
	}

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_set_data(adv, ad, ad_len);

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SET_DATA_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_set_data, BT_LE_PER_ADV_SET_DATA_RPC_CMD,
			 bt_le_per_adv_set_data_rpc_handler, NULL);

static void bt_le_per_adv_start_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	int _result;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_start(adv);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_START_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_start, BT_LE_PER_ADV_START_RPC_CMD,
			 bt_le_per_adv_start_rpc_handler, NULL);

static void bt_le_per_adv_stop_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_ext_adv *adv;
	int _result;

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_stop(adv);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_STOP_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_stop, BT_LE_PER_ADV_STOP_RPC_CMD,
			 bt_le_per_adv_stop_rpc_handler, NULL);

#if defined(CONFIG_BT_CONN)
static void bt_le_per_adv_set_info_transfer_rpc_handler(CborValue *_value, void *_handler_data)
{
	const struct bt_le_ext_adv *adv;
	const struct bt_conn *conn;
	uint16_t service_data;
	int _result;

	adv = (const struct bt_le_ext_adv *)ser_decode_uint(_value);
	conn = bt_rpc_decode_bt_conn(_value);
	service_data = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_set_info_transfer(adv, conn, service_data);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SET_INFO_TRANSFER_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_set_info_transfer,
			 BT_LE_PER_ADV_SET_INFO_TRANSFER_RPC_CMD,
			 bt_le_per_adv_set_info_transfer_rpc_handler, NULL);
#endif  /* defined(CONFIG_BT_CONN) */
#endif  /* defined(CONFIG_BT_PER_ADV) */

#if defined(CONFIG_BT_PER_ADV_SYNC)
static void bt_le_per_adv_sync_get_index_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_per_adv_sync *per_adv_sync;
	uint8_t _result;

	per_adv_sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_get_index(per_adv_sync);

	ser_rsp_send_uint(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_GET_INDEX_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_get_index,
			 BT_LE_PER_ADV_SYNC_GET_INDEX_RPC_CMD,
			 bt_le_per_adv_sync_get_index_rpc_handler, NULL);

void bt_le_per_adv_sync_param_dec(CborValue *_value, struct bt_le_per_adv_sync_param *_data)
{
	ser_decode_buffer(_value, &_data->addr, sizeof(bt_addr_le_t));
	_data->sid = ser_decode_uint(_value);
	_data->options = ser_decode_uint(_value);
	_data->skip = ser_decode_uint(_value);
	_data->timeout = ser_decode_uint(_value);
}

static void bt_le_per_adv_sync_create_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	struct bt_le_per_adv_sync_param param;
	struct bt_le_per_adv_sync *_out_sync_data;
	struct bt_le_per_adv_sync **out_sync = &_out_sync_data;
	size_t _buffer_size_max = 10;

	bt_le_per_adv_sync_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_create(&param, out_sync);

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, _result);
		ser_encode_uint(&_ctx.encoder, (uintptr_t)(*out_sync));

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_CREATE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_create, BT_LE_PER_ADV_SYNC_CREATE_RPC_CMD,
			 bt_le_per_adv_sync_create_rpc_handler, NULL);

static void bt_le_per_adv_sync_delete_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_per_adv_sync *per_adv_sync;
	int _result;

	per_adv_sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_delete(per_adv_sync);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_DELETE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_delete, BT_LE_PER_ADV_SYNC_DELETE_RPC_CMD,
			 bt_le_per_adv_sync_delete_rpc_handler, NULL);

static void bt_le_per_adv_sync_recv_enable_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_per_adv_sync *per_adv_sync;
	int _result;

	per_adv_sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_recv_enable(per_adv_sync);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_RECV_ENABLE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_recv_enable,
			 BT_LE_PER_ADV_SYNC_RECV_ENABLE_RPC_CMD,
			 bt_le_per_adv_sync_recv_enable_rpc_handler, NULL);

static void bt_le_per_adv_sync_recv_disable_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_le_per_adv_sync *per_adv_sync;
	int _result;

	per_adv_sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_recv_disable(per_adv_sync);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_RECV_DISABLE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_recv_disable,
			 BT_LE_PER_ADV_SYNC_RECV_DISABLE_RPC_CMD,
			 bt_le_per_adv_sync_recv_disable_rpc_handler, NULL);

#if defined(CONFIG_BT_CONN)
static void bt_le_per_adv_sync_transfer_rpc_handler(CborValue *_value, void *_handler_data)
{
	const struct bt_le_per_adv_sync *per_adv_sync;
	const struct bt_conn *conn;
	uint16_t service_data;
	int _result;

	per_adv_sync = (const struct bt_le_per_adv_sync *)ser_decode_uint(_value);
	conn = bt_rpc_decode_bt_conn(_value);
	service_data = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_transfer(per_adv_sync, conn, service_data);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_TRANSFER_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_transfer,
			 BT_LE_PER_ADV_SYNC_TRANSFER_RPC_CMD,
			 bt_le_per_adv_sync_transfer_rpc_handler, NULL);

static void bt_le_per_adv_sync_transfer_unsubscribe_rpc_handler(CborValue *_value,
								void *_handler_data)
{
	const struct bt_conn *conn;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_transfer_unsubscribe(conn);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_TRANSFER_UNSUBSCRIBE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_transfer_unsubscribe,
			 BT_LE_PER_ADV_SYNC_TRANSFER_UNSUBSCRIBE_RPC_CMD,
			 bt_le_per_adv_sync_transfer_unsubscribe_rpc_handler, NULL);

void bt_le_per_adv_sync_transfer_param_dec(CborValue *_value,
					   struct bt_le_per_adv_sync_transfer_param *_data)
{
	_data->skip = ser_decode_uint(_value);
	_data->timeout = ser_decode_uint(_value);
	_data->options = ser_decode_uint(_value);
}

static void bt_le_per_adv_sync_transfer_subscribe_rpc_handler(CborValue *_value,
							      void *_handler_data)
{
	const struct bt_conn *conn;
	struct bt_le_per_adv_sync_transfer_param param;
	int _result;

	conn = bt_rpc_decode_bt_conn(_value);
	bt_le_per_adv_sync_transfer_param_dec(_value, &param);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	_result = bt_le_per_adv_sync_transfer_subscribe(conn, &param);

	ser_rsp_send_int(_result);

	return;
decoding_error:
	report_decoding_error(BT_LE_PER_ADV_SYNC_TRANSFER_SUBSCRIBE_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_transfer_subscribe,
			 BT_LE_PER_ADV_SYNC_TRANSFER_SUBSCRIBE_RPC_CMD,
			 bt_le_per_adv_sync_transfer_subscribe_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_CONN) */

size_t bt_le_per_adv_sync_synced_info_sp_size(const struct bt_le_per_adv_sync_synced_info *_data)
{
	size_t _scratchpad_size = 0;

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(bt_addr_le_t));

	return _scratchpad_size;
}

size_t bt_le_per_adv_sync_synced_info_buf_size(const struct bt_le_per_adv_sync_synced_info *_data)
{
	size_t _buffer_size_max = 17;

	_buffer_size_max += sizeof(bt_addr_le_t);

	return _buffer_size_max;
}

void bt_le_per_adv_sync_synced_info_enc(CborEncoder *_encoder,
					const struct bt_le_per_adv_sync_synced_info *_data)
{
	ser_encode_buffer(_encoder, _data->addr, sizeof(bt_addr_le_t));
	ser_encode_uint(_encoder, _data->sid);
	ser_encode_uint(_encoder, _data->interval);
	ser_encode_uint(_encoder, _data->phy);
	ser_encode_bool(_encoder, _data->recv_enabled);
	ser_encode_uint(_encoder, _data->service_data);
	bt_rpc_encode_bt_conn(_encoder, _data->conn);
}

void per_adv_sync_cb_synced(struct bt_le_per_adv_sync *sync,
			    struct bt_le_per_adv_sync_synced_info *info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 10;

	_buffer_size_max += bt_le_per_adv_sync_synced_info_buf_size(info);

	_scratchpad_size += bt_le_per_adv_sync_synced_info_sp_size(info);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	ser_encode_uint(&_ctx.encoder, (uintptr_t)sync);
	bt_le_per_adv_sync_synced_info_enc(&_ctx.encoder, info);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, PER_ADV_SYNC_CB_SYNCED_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

size_t bt_le_per_adv_sync_term_info_sp_size(const struct bt_le_per_adv_sync_term_info *_data)
{
	size_t _scratchpad_size = 0;

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(bt_addr_le_t));

	return _scratchpad_size;
}

size_t bt_le_per_adv_sync_term_info_buf_size(const struct bt_le_per_adv_sync_term_info *_data)
{
	size_t _buffer_size_max = 5;

	_buffer_size_max += sizeof(bt_addr_le_t);

	return _buffer_size_max;
}

void bt_le_per_adv_sync_term_info_enc(CborEncoder *_encoder,
				      const struct bt_le_per_adv_sync_term_info *_data)
{
	ser_encode_buffer(_encoder, _data->addr, sizeof(bt_addr_le_t));
	ser_encode_uint(_encoder, _data->sid);
}

void per_adv_sync_cb_term(struct bt_le_per_adv_sync *sync,
			  const struct bt_le_per_adv_sync_term_info *info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 10;

	_buffer_size_max += bt_le_per_adv_sync_term_info_buf_size(info);

	_scratchpad_size += bt_le_per_adv_sync_term_info_sp_size(info);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	ser_encode_uint(&_ctx.encoder, (uintptr_t)sync);
	bt_le_per_adv_sync_term_info_enc(&_ctx.encoder, info);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, PER_ADV_SYNC_CB_TERM_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

size_t bt_le_per_adv_sync_recv_info_sp_size(const struct bt_le_per_adv_sync_recv_info *_data)
{
	size_t _scratchpad_size = 0;

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(bt_addr_le_t));

	return _scratchpad_size;
}

size_t bt_le_per_adv_sync_recv_info_buf_size(const struct bt_le_per_adv_sync_recv_info *_data)
{
	size_t _buffer_size_max = 11;

	_buffer_size_max += sizeof(bt_addr_le_t);

	return _buffer_size_max;
}

void bt_le_per_adv_sync_recv_info_enc(CborEncoder *_encoder,
				      const struct bt_le_per_adv_sync_recv_info *_data)
{
	ser_encode_buffer(_encoder, _data->addr, sizeof(bt_addr_le_t));
	ser_encode_uint(_encoder, _data->sid);
	ser_encode_int(_encoder, _data->tx_power);
	ser_encode_int(_encoder, _data->rssi);
	ser_encode_uint(_encoder, _data->cte_type);
}

void per_adv_sync_cb_recv(struct bt_le_per_adv_sync *sync,
			  const struct bt_le_per_adv_sync_recv_info *info,
			  struct net_buf_simple *buf)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 10;

	_buffer_size_max += bt_le_per_adv_sync_recv_info_buf_size(info);
	_buffer_size_max += net_buf_simple_buf_size(buf);

	_scratchpad_size += bt_le_per_adv_sync_recv_info_sp_size(info);
	_scratchpad_size += net_buf_simple_sp_size(buf);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	ser_encode_uint(&_ctx.encoder, (uintptr_t)sync);
	bt_le_per_adv_sync_recv_info_enc(&_ctx.encoder, info);
	net_buf_simple_enc(&_ctx.encoder, buf);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, PER_ADV_SYNC_CB_RECV_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

void bt_le_per_adv_sync_state_info_enc(CborEncoder *_encoder,
				       const struct bt_le_per_adv_sync_state_info *_data)
{
	ser_encode_bool(_encoder, _data->recv_enabled);
}

void per_adv_sync_cb_state_changed(struct bt_le_per_adv_sync *sync,
				   const struct bt_le_per_adv_sync_state_info *info)
{
	struct nrf_rpc_cbor_ctx _ctx;
	size_t _buffer_size_max = 6;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	ser_encode_uint(&_ctx.encoder, (uintptr_t)sync);
	bt_le_per_adv_sync_state_info_enc(&_ctx.encoder, info);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, PER_ADV_SYNC_CB_STATE_CHANGED_RPC_CMD,
				&_ctx, ser_rsp_decode_void, NULL);
}

static struct bt_le_per_adv_sync_cb per_adv_sync_cb = {
	.synced = per_adv_sync_cb_synced,
	.term = per_adv_sync_cb_term,
	.recv = per_adv_sync_cb_recv,
	.state_changed = per_adv_sync_cb_state_changed
};

static void bt_le_per_adv_sync_cb_register_on_remote_rpc_handler(CborValue *_value,
								 void *_handler_data)
{
	nrf_rpc_cbor_decoding_done(_value);

	bt_le_per_adv_sync_cb_register(&per_adv_sync_cb);
	ser_rsp_send_void();

}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_per_adv_sync_cb_register_on_remote,
			 BT_LE_PER_ADV_SYNC_CB_REGISTER_ON_REMOTE_RPC_CMD,
			 bt_le_per_adv_sync_cb_register_on_remote_rpc_handler, NULL);
#endif /* defined(CONFIG_BT_PER_ADV_SYNC) */
