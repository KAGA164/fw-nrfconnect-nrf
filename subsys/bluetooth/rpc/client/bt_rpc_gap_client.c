/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/* Client side of bluetooth API over nRF RPC.
 */

#include <bluetooth/bluetooth.h>

#include <nrf_rpc_cbor.h>

#include "bt_rpc_common.h"
#include "serialize.h"
#include "cbkproxy.h"

#include <logging/log.h>

LOG_MODULE_DECLARE(BT_RPC, CONFIG_BT_RPC_LOG_LEVEL);

SERIALIZE(GROUP(bt_rpc_grp));

SERIALIZE(RAW_STRUCT(bt_addr_le_t));
SERIALIZE(OPAQUE_STRUCT(void));
SERIALIZE(OPAQUE_STRUCT(struct bt_le_ext_adv));
SERIALIZE(OPAQUE_STRUCT(struct bt_le_per_adv_sync));
SERIALIZE(FILTERED_STRUCT(struct bt_conn, 3, bt_rpc_encode_bt_conn, bt_rpc_decode_bt_conn));

SERIALIZE(FIELD_TYPE(struct bt_le_ext_adv_cb, bt_le_ext_adv_cb_sent, sent));
SERIALIZE(FIELD_TYPE(struct bt_le_ext_adv_cb, bt_le_ext_adv_cb_connected, connected));
SERIALIZE(FIELD_TYPE(struct bt_le_ext_adv_cb, bt_le_ext_adv_cb_scanned, scanned));


#ifndef __GENERATOR
#define UNUSED __attribute__((unused)) /* TODO: Improve generator to avoid this workaround */
#else
#define UNUSED ;
#endif


static void report_decoding_error(uint8_t cmd_evt_id, void* data) {
	nrf_rpc_err(-EBADMSG, NRF_RPC_ERR_SRC_RECV, &bt_rpc_grp, cmd_evt_id,
		    NRF_RPC_PACKET_TYPE_CMD);
}


struct bt_rpc_get_check_list_rpc_res                                             /*####%BuFY*/
{                                                                                /*#####@6PQ*/

	size_t size;                                                             /*####%CQ4t*/
	uint8_t * data;                                                          /*#####@r1M*/

};                                                                               /*##B985gv0*/

static void bt_rpc_get_check_list_rpc_rsp(CborValue *_value, void *_handler_data)/*####%Bjw7*/
{                                                                                /*#####@G2c*/

	struct bt_rpc_get_check_list_rpc_res *_res =                             /*####%ARYO*/
		(struct bt_rpc_get_check_list_rpc_res *)_handler_data;           /*#####@SFU*/

	ser_decode_buffer(_value, _res->data, sizeof(uint8_t) * (_res->size));   /*##DcVdAPg*/

}                                                                                /*##B9ELNqo*/

static void bt_rpc_get_check_list(uint8_t *data, size_t size)
{
	SERIALIZE(SIZE_PARAM(data, size));
	SERIALIZE(OUT(data));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ab*/
	struct bt_rpc_get_check_list_rpc_res _result;                            /*#######st*/
	size_t _scratchpad_size = 0;                                             /*#######Oa*/
	size_t _buffer_size_max = 10;                                            /*#######@w*/

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(uint8_t) * size);            /*##EIzRmJk*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, size);                                    /*##A2nPHkE*/

	_result.size = size;                                                     /*####%CxN2*/
	_result.data = data;                                                     /*#####@rIE*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_GET_CHECK_LIST_RPC_CMD,      /*####%BO6n*/
		&_ctx, bt_rpc_get_check_list_rpc_rsp, &_result);                 /*#####@3YY*/
}

static void validate_config()
{
	size_t size = bt_rpc_calc_check_list_size();
	uint8_t data[size];
	static bool validated = false;

	if (!validated) {
		validated = true;
		bt_rpc_get_check_list(data, size);
		if (!bt_rpc_validate_check_list(data, size)) {
			nrf_rpc_err(-EINVAL, NRF_RPC_ERR_SRC_RECV, &bt_rpc_grp,
				    BT_ENABLE_RPC_CMD, NRF_RPC_PACKET_TYPE_CMD);
		}
	}
}


static void bt_ready_cb_t_callback_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bv/b*/
{                                                                                     /*#####@hiY*/

	int err;                                                                      /*####%AcxU*/
	bt_ready_cb_t callback_slot;                                                  /*#####@1I0*/

	err = ser_decode_int(_value);                                                 /*####%CveX*/
	callback_slot = (bt_ready_cb_t)ser_decode_callback_call(_value);              /*#####@fek*/

	if (!ser_decoding_done_and_check(_value)) {                                   /*######%FE*/
		goto decoding_error;                                                  /*######QTM*/
	}                                                                             /*######@1Y*/

	callback_slot(err);                                                           /*##DnrVhJE*/

	return;                                                                       /*######%FU*/
decoding_error:                                                                       /*######Uok*/
	report_decoding_error(BT_READY_CB_T_CALLBACK_RPC_EVT, _handler_data);         /*######@1Y*/

}                                                                                     /*##B9ELNqo*/

NRF_RPC_CBOR_EVT_DECODER(bt_rpc_grp, bt_ready_cb_t_callback, BT_READY_CB_T_CALLBACK_RPC_EVT,/*####%BqdK*/
	bt_ready_cb_t_callback_rpc_handler, NULL);                                          /*#####@nrU*/


int bt_enable(bt_ready_cb_t cb)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	validate_config();

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_callback(&_ctx.encoder, cb);                                  /*##AxNS7A4*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_ENABLE_RPC_CMD,                  /*####%BPXA*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@zR8*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_set_name(const char *name)
{
#if defined(CONFIG_BT_DEVICE_NAME_DYNAMIC) || defined(__GENERATOR)

	SERIALIZE(STR(name));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	size_t _name_strlen;                                                     /*#######bk*/
	int _result;                                                             /*#######HH*/
	size_t _scratchpad_size = 0;                                             /*#######eY*/
	size_t _buffer_size_max = 10;                                            /*########@*/

	_name_strlen = strlen(name);                                             /*####%CFOk*/
	_buffer_size_max += _name_strlen;                                        /*#####@f8c*/

	_scratchpad_size += SCRATCHPAD_ALIGN(_name_strlen + 1);                  /*##EObZcVc*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_str(&_ctx.encoder, name, _name_strlen);                       /*##A/RUZRo*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_SET_NAME_RPC_CMD,                /*####%BBDk*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@QPw*/

	return _result;                                                          /*##BX7TDLc*/

#else

	return -ENOMEM;

#endif /* defined(CONFIG_BT_DEVICE_NAME_DYNAMIC) || defined(__GENERATOR) */
}

#if defined(CONFIG_BT_DEVICE_NAME_DYNAMIC) || defined(__GENERATOR)
struct bt_get_name_out_rpc_res                                                   /*####%Bp8J*/
{                                                                                /*#####@zYc*/

	bool _result;                                                            /*######%CW*/
	size_t size;                                                             /*######pln*/
	char * name;                                                             /*######@DY*/

};                                                                               /*##B985gv0*/

static void bt_get_name_out_rpc_rsp(CborValue *_value, void *_handler_data)      /*####%BoL7*/
{                                                                                /*#####@fvE*/

	struct bt_get_name_out_rpc_res *_res =                                   /*####%AbU8*/
		(struct bt_get_name_out_rpc_res *)_handler_data;                 /*#####@c5k*/

	_res->_result = ser_decode_bool(_value);                                 /*####%DYid*/
	ser_decode_str(_value, _res->name, (_res->size));                        /*#####@AWM*/

}                                                                                /*##B9ELNqo*/

static bool bt_get_name_out(char *name, size_t size)
{
	SERIALIZE(OUT(name));
	SERIALIZE(STR(name));
	SERIALIZE(SIZE_PARAM(name, size));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AY*/
	struct bt_get_name_out_rpc_res _result;                                  /*#######X2*/
	size_t _scratchpad_size = 0;                                             /*#######Jd*/
	size_t _buffer_size_max = 10;                                            /*#######@I*/

	_scratchpad_size += SCRATCHPAD_ALIGN(size);                              /*##EB+3ycA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, size);                                    /*##A2nPHkE*/

	_result.size = size;                                                     /*####%C5M6*/
	_result.name = name;                                                     /*#####@4K4*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_GET_NAME_OUT_RPC_CMD,            /*####%BG0o*/
		&_ctx, bt_get_name_out_rpc_rsp, &_result);                       /*#####@sSg*/

	return _result._result;                                                  /*##BW0ge3U*/
}

#endif /* defined(CONFIG_BT_DEVICE_NAME_DYNAMIC) || defined(__GENERATOR) */

const char *bt_get_name(void)
{
#if defined(CONFIG_BT_DEVICE_NAME_DYNAMIC) || defined(__GENERATOR)

	static char bt_name_cache[CONFIG_BT_DEVICE_NAME_MAX + 1];
	bool not_null;

	not_null = bt_get_name_out(bt_name_cache, sizeof(bt_name_cache));
	return not_null ? bt_name_cache : NULL;

#else

	return CONFIG_BT_DEVICE_NAME;

#endif /* defined(CONFIG_BT_DEVICE_NAME_DYNAMIC) || defined(__GENERATOR) */
}

int bt_set_id_addr(const bt_addr_le_t *addr)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AR*/
	int _result;                                                             /*######RDP*/
	size_t _buffer_size_max = 3;                                             /*######@sI*/

	validate_config();

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*##CHCgvU0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*##A9rQrRg*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_SET_ID_ADDR_RPC_CMD,             /*####%BHOR*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@SB0*/

	return _result;                                                          /*##BX7TDLc*/
}

struct bt_id_get_rpc_res                                                         /*####%Bmxc*/
{                                                                                /*#####@ZAo*/

	size_t * count;                                                          /*####%CcVF*/
	bt_addr_le_t * addrs;                                                    /*#####@Nco*/

};                                                                               /*##B985gv0*/

static void bt_id_get_rpc_rsp(CborValue *_value, void *_handler_data)                 /*####%BluI*/
{                                                                                     /*#####@1Q4*/

	struct bt_id_get_rpc_res *_res =                                              /*####%AYtj*/
		(struct bt_id_get_rpc_res *)_handler_data;                            /*#####@fr0*/

	*(_res->count) = ser_decode_uint(_value);                                     /*####%DZiC*/
	ser_decode_buffer(_value, _res->addrs, *(_res->count) * sizeof(bt_addr_le_t));/*#####@Ip8*/

}                                                                                     /*##B9ELNqo*/

void bt_id_get(bt_addr_le_t *addrs, size_t *count)
{
	SERIALIZE(OUT(addrs));
	SERIALIZE(SIZE_PARAM_EX(addrs, *$, count));
	SERIALIZE(INOUT(count));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AU*/
	struct bt_id_get_rpc_res _result;                                        /*#######FC*/
	size_t _scratchpad_size = 0;                                             /*#######Cq*/
	size_t _buffer_size_max = 10;                                            /*#######@o*/

	_scratchpad_size += SCRATCHPAD_ALIGN(*count * sizeof(bt_addr_le_t));     /*##EM0RMfw*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, *count);                                  /*##A0IY0+8*/

	_result.count = count;                                                   /*####%C9M/*/
	_result.addrs = addrs;                                                   /*#####@zo8*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_ID_GET_RPC_CMD,                  /*####%BLnI*/
		&_ctx, bt_id_get_rpc_rsp, &_result);                             /*#####@SsE*/
}

struct bt_id_create_rpc_res                                                      /*####%BoIG*/
{                                                                                /*#####@PlM*/

	int _result;                                                             /*######%CT*/
	bt_addr_le_t * addr;                                                     /*######Jyh*/
	uint8_t * irk;                                                           /*######@+s*/

};                                                                               /*##B985gv0*/

static void bt_id_create_rpc_rsp(CborValue *_value, void *_handler_data)         /*####%BqRo*/
{                                                                                /*#####@GSg*/

	struct bt_id_create_rpc_res *_res =                                      /*####%AWr1*/
		(struct bt_id_create_rpc_res *)_handler_data;                    /*#####@UyU*/

	_res->_result = ser_decode_int(_value);                                  /*######%DQ*/
	ser_decode_buffer(_value, _res->addr, sizeof(bt_addr_le_t));             /*######lk5*/
	ser_decode_buffer(_value, _res->irk, sizeof(uint8_t) * 16);              /*######@5o*/

}                                                                                /*##B9ELNqo*/

int bt_id_create(bt_addr_le_t *addr, uint8_t *irk)
{
	SERIALIZE(NULLABLE(addr));
	SERIALIZE(INOUT(addr));
	SERIALIZE(NULLABLE(irk));
	SERIALIZE(INOUT(irk));
	SERIALIZE(SIZE(irk, 16));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	size_t _irk_size;                                                        /*#######Xr*/
	struct bt_id_create_rpc_res _result;                                     /*#######Lm*/
	size_t _scratchpad_size = 0;                                             /*#######Ak*/
	size_t _buffer_size_max = 13;                                            /*########@*/

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*######%CB*/
	_irk_size = !irk ? 0 : sizeof(uint8_t) * 16;                             /*######cKg*/
	_buffer_size_max += _irk_size;                                           /*######@u4*/

	_scratchpad_size += SCRATCHPAD_ALIGN(_irk_size);                         /*##ELqQtKI*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*####%Ax4U*/
	ser_encode_buffer(&_ctx.encoder, irk, _irk_size);                        /*#####@/YU*/

	_result.addr = addr;                                                     /*####%CxTc*/
	_result.irk = irk;                                                       /*#####@QsM*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_ID_CREATE_RPC_CMD,               /*####%BMH+*/
		&_ctx, bt_id_create_rpc_rsp, &_result);                          /*#####@log*/

	return _result._result;                                                  /*##BW0ge3U*/
}

struct bt_id_reset_rpc_res                                                       /*####%Bs1i*/
{                                                                                /*#####@i/M*/

	int _result;                                                             /*######%CT*/
	bt_addr_le_t * addr;                                                     /*######Jyh*/
	uint8_t * irk;                                                           /*######@+s*/

};                                                                               /*##B985gv0*/

static void bt_id_reset_rpc_rsp(CborValue *_value, void *_handler_data)          /*####%BoSY*/
{                                                                                /*#####@/xk*/

	struct bt_id_reset_rpc_res *_res =                                       /*####%AZXs*/
		(struct bt_id_reset_rpc_res *)_handler_data;                     /*#####@oUo*/

	_res->_result = ser_decode_int(_value);                                  /*######%DQ*/
	ser_decode_buffer(_value, _res->addr, sizeof(bt_addr_le_t));             /*######lk5*/
	ser_decode_buffer(_value, _res->irk, sizeof(uint8_t) * 16);              /*######@5o*/

}                                                                                /*##B9ELNqo*/

int bt_id_reset(uint8_t id, bt_addr_le_t *addr, uint8_t *irk)
{
	SERIALIZE(INOUT(addr));
	SERIALIZE(NULLABLE(addr));
	SERIALIZE(INOUT(irk));
	SERIALIZE(NULLABLE(irk));
	SERIALIZE(SIZE(irk, 16));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	size_t _irk_size;                                                        /*#######XB*/
	struct bt_id_reset_rpc_res _result;                                      /*#######PU*/
	size_t _scratchpad_size = 0;                                             /*#######NI*/
	size_t _buffer_size_max = 15;                                            /*########@*/

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*######%CB*/
	_irk_size = !irk ? 0 : sizeof(uint8_t) * 16;                             /*######cKg*/
	_buffer_size_max += _irk_size;                                           /*######@u4*/

	_scratchpad_size += SCRATCHPAD_ALIGN(_irk_size);                         /*##ELqQtKI*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, id);                                      /*######%A9*/
	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*######0qd*/
	ser_encode_buffer(&_ctx.encoder, irk, _irk_size);                        /*######@RU*/

	_result.addr = addr;                                                     /*####%CxTc*/
	_result.irk = irk;                                                       /*#####@QsM*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_ID_RESET_RPC_CMD,                /*####%BDbH*/
		&_ctx, bt_id_reset_rpc_rsp, &_result);                           /*#####@DeY*/

	return _result._result;                                                  /*##BW0ge3U*/
}

int bt_id_delete(uint8_t id)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AW*/
	int _result;                                                             /*######sOU*/
	size_t _buffer_size_max = 2;                                             /*######@TQ*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, id);                                      /*##A9BnOB4*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_ID_DELETE_RPC_CMD,               /*####%BNVY*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@0fI*/

	return _result;                                                          /*##BX7TDLc*/
}


size_t bt_data_buf_size(const struct bt_data *_data)                             /*####%Bmy4*/
{                                                                                /*#####@ED0*/

	size_t _buffer_size_max = 9;                                             /*##Ad+vLz8*/

	_buffer_size_max += sizeof(uint8_t) * _data->data_len;                   /*##CBQ2Maw*/

	return _buffer_size_max;                                                 /*##BWmN6G8*/

}                                                                                /*##B9ELNqo*/

size_t bt_data_sp_size(const struct bt_data *_data)                              /*####%Btzm*/
{                                                                                /*#####@Oy8*/

	size_t _scratchpad_size = 0;                                             /*##ATz5YrA*/

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(uint8_t) * _data->data_len); /*##EGeYfNs*/

	return _scratchpad_size;                                                 /*##BRWAmyU*/

}                                                                                /*##B9ELNqo*/

void bt_data_enc(CborEncoder *_encoder, const struct bt_data *_data)                /*####%BumI*/
{                                                                                   /*#####@wlE*/

	SERIALIZE(STRUCT(struct bt_data));
	SERIALIZE(SIZE_PARAM(data, data_len));

	ser_encode_uint(_encoder, _data->type);                                     /*######%A8*/
	ser_encode_uint(_encoder, _data->data_len);                                 /*######fsW*/
	ser_encode_buffer(_encoder, _data->data, sizeof(uint8_t) * _data->data_len);/*######@EY*/

}                                                                                   /*##B9ELNqo*/


UNUSED
static const size_t bt_le_scan_param_buf_size = 22;                              /*##BvqYHlg*/

void bt_le_scan_param_enc(CborEncoder *_encoder, const struct bt_le_scan_param *_data)/*####%BgZ3*/
{                                                                                     /*#####@RoA*/

	SERIALIZE(STRUCT(struct bt_le_scan_param));
	SERIALIZE(UNION_SELECT(options));
	SERIALIZE(DEL(filter_dup));

	ser_encode_uint(_encoder, _data->type);                                       /*#######%A*/
	ser_encode_uint(_encoder, _data->options);                                    /*#######4W*/
	ser_encode_uint(_encoder, _data->interval);                                   /*########D*/
	ser_encode_uint(_encoder, _data->window);                                     /*########I*/
	ser_encode_uint(_encoder, _data->timeout);                                    /*########n*/
	ser_encode_uint(_encoder, _data->interval_coded);                             /*########Q*/
	ser_encode_uint(_encoder, _data->window_coded);                               /*########@*/

}                                                                                     /*##B9ELNqo*/

void net_buf_simple_dec(struct ser_scratchpad *_scratchpad, struct net_buf_simple *_data)
{
	CborValue *_value = _scratchpad->value;

	_data->len = ser_decode_buffer_size(_value);
	_data->data = ser_decode_buffer_into_scratchpad(_scratchpad);
	_data->size = _data->len;
	_data->__buf = _data->data;
}


static void bt_le_scan_cb_t_callback_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bv5m*/
{                                                                                       /*#####@99E*/

	bt_addr_le_t _addr_data;                                                        /*#######%A*/
	const bt_addr_le_t * addr;                                                      /*#######fR*/
	int8_t rssi;                                                                    /*########0*/
	uint8_t adv_type;                                                               /*########/*/
	struct net_buf_simple buf;                                                      /*########V*/
	bt_le_scan_cb_t * callback_slot;                                                /*########E*/
	struct ser_scratchpad _scratchpad;                                              /*########@*/

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);                                     /*##EZKHjKY*/

	addr = ser_decode_buffer(_value, &_addr_data, sizeof(bt_addr_le_t));            /*#######%C*/
	rssi = ser_decode_int(_value);                                                  /*#######nN*/
	adv_type = ser_decode_uint(_value);                                             /*#######rP*/
	net_buf_simple_dec(&_scratchpad, &buf);                                         /*#######B8*/
	callback_slot = (bt_le_scan_cb_t *)ser_decode_callback_call(_value);            /*########@*/

	if (!ser_decoding_done_and_check(_value)) {                                     /*######%FE*/
		goto decoding_error;                                                    /*######QTM*/
	}                                                                               /*######@1Y*/

	callback_slot(addr, rssi, adv_type, &buf);                                      /*##DgC7dGo*/

		SER_SCRATCHPAD_FREE(&_scratchpad);                                      /*##Eq1r7Tg*/

	ser_rsp_send_void();                                                            /*##BEYGLxw*/

	return;                                                                         /*######%FU*/
decoding_error:                                                                         /*#######Su*/
	report_decoding_error(BT_LE_SCAN_CB_T_CALLBACK_RPC_CMD, _handler_data);         /*#######gr*/
	SER_SCRATCHPAD_FREE(&_scratchpad);                                              /*#######@o*/

}                                                                                       /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_scan_cb_t_callback, BT_LE_SCAN_CB_T_CALLBACK_RPC_CMD,/*####%Bvg5*/
	bt_le_scan_cb_t_callback_rpc_handler, NULL);                                            /*#####@vlo*/

size_t bt_le_adv_param_sp_size(const struct bt_le_adv_param *_data)                   /*####%Bjyc*/
{                                                                                     /*#####@ibE*/

	size_t _scratchpad_size = 0;                                                  /*##ATz5YrA*/

	_scratchpad_size += !_data->peer ? 0 : SCRATCHPAD_ALIGN(sizeof(bt_addr_le_t));/*##EL1Agek*/

	return _scratchpad_size;                                                      /*##BRWAmyU*/

}                                                                                     /*##B9ELNqo*/

size_t bt_le_adv_param_buf_size(const struct bt_le_adv_param *_data)             /*####%BiYp*/
{                                                                                /*#####@Q8I*/

	size_t _buffer_size_max = 22;                                            /*##AavCUAw*/

	_buffer_size_max += !_data->peer ? 0 : 2 + sizeof(bt_addr_le_t);         /*##CASBfgs*/

	return _buffer_size_max;                                                 /*##BWmN6G8*/

}                                                                                /*##B9ELNqo*/

void bt_le_adv_param_enc(CborEncoder *_encoder, const struct bt_le_adv_param *_data)/*####%BmWY*/
{                                                                                   /*#####@Uhs*/

	SERIALIZE(STRUCT(struct bt_le_adv_param));
	SERIALIZE(NULLABLE(peer));

	ser_encode_uint(_encoder, _data->id);                                       /*#######%A*/
	ser_encode_uint(_encoder, _data->sid);                                      /*#######9y*/
	ser_encode_uint(_encoder, _data->secondary_max_skip);                       /*########+*/
	ser_encode_uint(_encoder, _data->options);                                  /*########D*/
	ser_encode_uint(_encoder, _data->interval_min);                             /*########E*/
	ser_encode_uint(_encoder, _data->interval_max);                             /*########E*/
	ser_encode_buffer(_encoder, _data->peer, sizeof(bt_addr_le_t));             /*########@*/

}                                                                                   /*##B9ELNqo*/

int bt_le_adv_start(const struct bt_le_adv_param *param,
		    const struct bt_data *ad, size_t ad_len,
		    const struct bt_data *sd, size_t sd_len)
{
	SERIALIZE(SIZE_PARAM(ad, ad_len));
	SERIALIZE(SIZE_PARAM(sd, sd_len));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	int _result;                                                             /*#######dr*/
	size_t _scratchpad_size = 0;                                             /*#######k2*/
	size_t _buffer_size_max = 15;                                            /*#######pA*/
	size_t _i;                                                               /*########@*/

	_buffer_size_max += bt_le_adv_param_buf_size(param);                     /*########%*/
	for (_i = 0; _i < ad_len; _i++) {                                        /*########C*/
		_buffer_size_max += bt_data_buf_size(&ad[_i]);                   /*########N*/
		_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(struct bt_data));    /*########1*/
		_scratchpad_size += bt_data_sp_size(&ad[_i]);                    /*########8*/
	}                                                                        /*########F*/
	for (_i = 0; _i < sd_len; _i++) {                                        /*########7*/
		_buffer_size_max += bt_data_buf_size(&sd[_i]);                   /*########o*/
		_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(struct bt_data));    /*#########*/
		_scratchpad_size += bt_data_sp_size(&sd[_i]);                    /*#########*/
	}                                                                        /*########@*/

	_scratchpad_size += bt_le_adv_param_sp_size(param);                      /*##EEZ/Gv4*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	bt_le_adv_param_enc(&_ctx.encoder, param);                               /*########%*/
	ser_encode_uint(&_ctx.encoder, ad_len);                                  /*########A*/
	for (_i = 0; _i < ad_len; _i++) {                                        /*########+*/
		bt_data_enc(&_ctx.encoder, &ad[_i]);                             /*########o*/
	}                                                                        /*########a*/
	ser_encode_uint(&_ctx.encoder, sd_len);                                  /*########E*/
	for (_i = 0; _i < sd_len; _i++) {                                        /*########B*/
		bt_data_enc(&_ctx.encoder, &sd[_i]);                             /*########g*/
	}                                                                        /*########@*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_ADV_START_RPC_CMD,            /*####%BDAc*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@B9c*/

	return _result;                                                          /*##BX7TDLc*/
}


int bt_le_adv_update_data(const struct bt_data *ad, size_t ad_len,
			  const struct bt_data *sd, size_t sd_len)
{
	SERIALIZE(SIZE_PARAM(ad, ad_len));
	SERIALIZE(SIZE_PARAM(sd, sd_len));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	int _result;                                                             /*#######dr*/
	size_t _scratchpad_size = 0;                                             /*#######k2*/
	size_t _buffer_size_max = 15;                                            /*#######pA*/
	size_t _i;                                                               /*########@*/

	for (_i = 0; _i < ad_len; _i++) {                                        /*########%*/
		_buffer_size_max += bt_data_buf_size(&ad[_i]);                   /*########C*/
		_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(struct bt_data));    /*########J*/
		_scratchpad_size += bt_data_sp_size(&ad[_i]);                    /*########/*/
	}                                                                        /*########m*/
	for (_i = 0; _i < sd_len; _i++) {                                        /*########7*/
		_buffer_size_max += bt_data_buf_size(&sd[_i]);                   /*########f*/
		_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(struct bt_data));    /*########M*/
		_scratchpad_size += bt_data_sp_size(&sd[_i]);                    /*#########*/
	}                                                                        /*########@*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, ad_len);                                  /*#######%A*/
	for (_i = 0; _i < ad_len; _i++) {                                        /*########/*/
		bt_data_enc(&_ctx.encoder, &ad[_i]);                             /*########P*/
	}                                                                        /*########G*/
	ser_encode_uint(&_ctx.encoder, sd_len);                                  /*########S*/
	for (_i = 0; _i < sd_len; _i++) {                                        /*########r*/
		bt_data_enc(&_ctx.encoder, &sd[_i]);                             /*########c*/
	}                                                                        /*########@*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_ADV_UPDATE_DATA_RPC_CMD,      /*####%BGgz*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@7Ps*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_adv_stop(void)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AX*/
	int _result;                                                             /*######56+*/
	size_t _buffer_size_max = 0;                                             /*######@io*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_ADV_STOP_RPC_CMD,             /*####%BGp9*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@RDI*/

	return _result;                                                          /*##BX7TDLc*/
}

void bt_le_oob_dec(CborValue *_value, struct bt_le_oob *_data)                   /*####%BguA*/
{                                                                                /*#####@olA*/

	ser_decode_buffer(_value, &_data->addr, sizeof(bt_addr_le_t));           /*######%Co*/
	ser_decode_buffer(_value, _data->le_sc_data.r, 16 * sizeof(uint8_t));    /*######YqP*/
	ser_decode_buffer(_value, _data->le_sc_data.c, 16 * sizeof(uint8_t));    /*######@ao*/

}                                                                                /*##B9ELNqo*/

#if defined(CONFIG_BT_EXT_ADV) || defined(__GENERATOR)
void bt_le_ext_adv_sent_info_dec(CborValue *_value, struct bt_le_ext_adv_sent_info *_data)/*####%BgXN*/
{                                                                                         /*#####@4IU*/

	_data->num_sent = ser_decode_uint(_value);                                        /*##CjNgik4*/

}                                                                                         /*##B9ELNqo*/

void bt_le_ext_adv_connected_info_dec(CborValue *_value, struct bt_le_ext_adv_connected_info *_data)/*####%BqU2*/
{                                                                                                   /*#####@mSw*/

	_data->conn = bt_rpc_decode_bt_conn(_value);                                                /*##Cv4jcYE*/

}                                                                                                   /*##B9ELNqo*/

void bt_le_ext_adv_scanned_info_dec(struct ser_scratchpad *_scratchpad, struct bt_le_ext_adv_scanned_info *_data)/*####%Bh42*/
{                                                                                                                /*#####@xmQ*/

	CborValue *_value = _scratchpad->value;                                                                  /*##AU3cSLw*/

	ARG_UNUSED(_value);

	_data->addr = ser_decode_buffer_into_scratchpad(_scratchpad);                                            /*##CkrjlGc*/

}                                                                                                                /*##B9ELNqo*/

static void bt_le_ext_adv_cb_sent_callback_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bvi/*/
{                                                                                             /*#####@nlk*/

	struct bt_le_ext_adv * adv;                                                           /*######%AT*/
	struct bt_le_ext_adv_sent_info info;                                                  /*######jpC*/
	bt_le_ext_adv_cb_sent callback_slot;                                                  /*######@Ww*/

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);                                /*######%Ck*/
	bt_le_ext_adv_sent_info_dec(_value, &info);                                           /*######78k*/
	callback_slot = (bt_le_ext_adv_cb_sent)ser_decode_callback_call(_value);              /*######@4k*/

	if (!ser_decoding_done_and_check(_value)) {                                           /*######%FE*/
		goto decoding_error;                                                          /*######QTM*/
	}                                                                                     /*######@1Y*/

	callback_slot(adv, &info);                                                            /*##DmH3+Xw*/

	ser_rsp_send_void();                                                                  /*##BEYGLxw*/

	return;                                                                               /*######%FT*/
decoding_error:                                                                               /*######6su*/
	report_decoding_error(BT_LE_EXT_ADV_CB_SENT_CALLBACK_RPC_CMD, _handler_data);         /*######@qE*/

}                                                                                             /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_cb_sent_callback, BT_LE_EXT_ADV_CB_SENT_CALLBACK_RPC_CMD,/*####%BiaI*/
	bt_le_ext_adv_cb_sent_callback_rpc_handler, NULL);                                                  /*#####@66M*/

static void bt_le_ext_adv_cb_connected_callback_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bvcv*/
{                                                                                                  /*#####@x+U*/

	struct bt_le_ext_adv * adv;                                                                /*######%AS*/
	struct bt_le_ext_adv_connected_info info;                                                  /*######+r4*/
	bt_le_ext_adv_cb_connected callback_slot;                                                  /*######@Y8*/

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);                                     /*######%Cu*/
	bt_le_ext_adv_connected_info_dec(_value, &info);                                           /*######Etu*/
	callback_slot = (bt_le_ext_adv_cb_connected)ser_decode_callback_call(_value);              /*######@gI*/

	if (!ser_decoding_done_and_check(_value)) {                                                /*######%FE*/
		goto decoding_error;                                                               /*######QTM*/
	}                                                                                          /*######@1Y*/

	callback_slot(adv, &info);                                                                 /*##DmH3+Xw*/

	ser_rsp_send_void();                                                                       /*##BEYGLxw*/

	return;                                                                                    /*######%FY*/
decoding_error:                                                                                    /*######w8G*/
	report_decoding_error(BT_LE_EXT_ADV_CB_CONNECTED_CALLBACK_RPC_CMD, _handler_data);         /*######@a0*/

}                                                                                                  /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_cb_connected_callback, BT_LE_EXT_ADV_CB_CONNECTED_CALLBACK_RPC_CMD,/*####%BjS+*/
	bt_le_ext_adv_cb_connected_callback_rpc_handler, NULL);                                                       /*#####@+H4*/

static void bt_le_ext_adv_cb_scanned_callback_rpc_handler(CborValue *_value, void *_handler_data)/*####%BpY5*/
{                                                                                                /*#####@D7Y*/

	struct bt_le_ext_adv * adv;                                                              /*######%AU*/
	struct bt_le_ext_adv_scanned_info info;                                                  /*#######3f*/
	bt_le_ext_adv_cb_scanned callback_slot;                                                  /*#######8I*/
	struct ser_scratchpad _scratchpad;                                                       /*#######@A*/

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);                                              /*##EZKHjKY*/

	adv = (struct bt_le_ext_adv *)ser_decode_uint(_value);                                   /*######%Cp*/
	bt_le_ext_adv_scanned_info_dec(&_scratchpad, &info);                                     /*######6+V*/
	callback_slot = (bt_le_ext_adv_cb_scanned)ser_decode_callback_call(_value);              /*######@F8*/

	if (!ser_decoding_done_and_check(_value)) {                                              /*######%FE*/
		goto decoding_error;                                                             /*######QTM*/
	}                                                                                        /*######@1Y*/

	callback_slot(adv, &info);                                                               /*##DmH3+Xw*/

		SER_SCRATCHPAD_FREE(&_scratchpad);                                               /*##Eq1r7Tg*/

	ser_rsp_send_void();                                                                     /*##BEYGLxw*/

	return;                                                                                  /*######%FX*/
decoding_error:                                                                                  /*#######Va*/
	report_decoding_error(BT_LE_EXT_ADV_CB_SCANNED_CALLBACK_RPC_CMD, _handler_data);         /*#######v1*/
	SER_SCRATCHPAD_FREE(&_scratchpad);                                                       /*#######@I*/

}                                                                                                /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_ext_adv_cb_scanned_callback, BT_LE_EXT_ADV_CB_SCANNED_CALLBACK_RPC_CMD,/*####%Bnd7*/
	bt_le_ext_adv_cb_scanned_callback_rpc_handler, NULL);                                                     /*#####@hvs*/

static const size_t bt_le_ext_adv_cb_buf_size = 15;                              /*##BpmBBn8*/

void bt_le_ext_adv_cb_enc(CborEncoder *_encoder, const struct bt_le_ext_adv_cb *_data)/*####%BmsD*/
{                                                                                     /*#####@xU4*/

	SERIALIZE(STRUCT(struct bt_le_ext_adv_cb));

	ser_encode_callback(_encoder, _data->sent);                                   /*######%Aw*/
	ser_encode_callback(_encoder, _data->connected);                              /*######vXb*/
	ser_encode_callback(_encoder, _data->scanned);                                /*######@Bg*/

}                                                                                     /*##B9ELNqo*/

struct bt_le_ext_adv_create_rpc_res                                              /*####%Bm6e*/
{                                                                                /*#####@dOE*/

	int _result;                                                             /*####%CRV7*/
	struct bt_le_ext_adv ** adv;                                             /*#####@36w*/

};                                                                               /*##B985gv0*/

static void bt_le_ext_adv_create_rpc_rsp(CborValue *_value, void *_handler_data)  /*####%Bno+*/
{                                                                                 /*#####@e2c*/

	struct bt_le_ext_adv_create_rpc_res *_res =                               /*####%AQ0J*/
		(struct bt_le_ext_adv_create_rpc_res *)_handler_data;             /*#####@yio*/

	_res->_result = ser_decode_int(_value);                                   /*####%DfFr*/
	*(_res->adv) = (struct bt_le_ext_adv *)(uintptr_t)ser_decode_uint(_value);/*#####@lr4*/

}                                                                                 /*##B9ELNqo*/

int bt_le_ext_adv_create(const struct bt_le_adv_param *param,
			 const struct bt_le_ext_adv_cb *cb,
			 struct bt_le_ext_adv **adv)
{
	SERIALIZE(OUT(adv));
	SERIALIZE(DEL(cb));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AX*/
	struct bt_le_ext_adv_create_rpc_res _result;                             /*#######M1*/
	size_t _scratchpad_size = 0;                                             /*#######Ho*/
	size_t _buffer_size_max = 5;                                             /*#######@s*/

	_buffer_size_max += bt_le_adv_param_buf_size(param);                     /*##CKvr4W4*/

	_buffer_size_max += bt_le_ext_adv_cb_buf_size;

	_scratchpad_size += bt_le_adv_param_sp_size(param);                      /*##EEZ/Gv4*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	bt_le_adv_param_enc(&_ctx.encoder, param);                               /*##A/VwjEY*/

	if (cb == NULL) {
		ser_encode_undefined(&_ctx.encoder);
	} else {
		bt_le_ext_adv_cb_enc(&_ctx.encoder, cb);
	}

	_result.adv = adv;                                                       /*##Cx5Tf1c*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_CREATE_RPC_CMD,       /*####%BOJo*/
		&_ctx, bt_le_ext_adv_create_rpc_rsp, &_result);                  /*#####@vEw*/

	return _result._result;                                                  /*##BW0ge3U*/
}

UNUSED
static const size_t bt_le_ext_adv_start_param_buf_size = 5;                      /*##BnevQ70*/

void bt_le_ext_adv_start_param_enc(CborEncoder *_encoder, const struct bt_le_ext_adv_start_param *_data)/*####%BlZN*/
{                                                                                                       /*#####@uEw*/

	SERIALIZE(STRUCT(struct bt_le_ext_adv_start_param));

	ser_encode_uint(_encoder, _data->timeout);                                                      /*####%A4oh*/
	ser_encode_uint(_encoder, _data->num_events);                                                   /*#####@m6E*/

}                                                                                                       /*##B9ELNqo*/

int bt_le_ext_adv_start(struct bt_le_ext_adv *adv,
			struct bt_le_ext_adv_start_param *param)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ac*/
	int _result;                                                             /*######PRx*/
	size_t _buffer_size_max = 10;                                            /*######@Yo*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*####%A3ca*/
	bt_le_ext_adv_start_param_enc(&_ctx.encoder, param);                     /*#####@wyE*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_START_RPC_CMD,        /*####%BJMP*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@bZo*/

	return _result;                                                          /*##BX7TDLc*/
}


int bt_le_ext_adv_stop(struct bt_le_ext_adv *adv)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*##A7bUUXs*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_STOP_RPC_CMD,         /*####%BKyh*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@XG4*/

	return _result;                                                          /*##BX7TDLc*/
}


int bt_le_ext_adv_set_data(struct bt_le_ext_adv *adv,
			   const struct bt_data *ad, size_t ad_len,
			   const struct bt_data *sd, size_t sd_len)
{
	SERIALIZE(SIZE_PARAM(ad, ad_len));
	SERIALIZE(SIZE_PARAM(sd, sd_len));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	int _result;                                                             /*#######ci*/
	size_t _scratchpad_size = 0;                                             /*#######Rw*/
	size_t _buffer_size_max = 20;                                            /*#######Eo*/
	size_t _i;                                                               /*########@*/

	for (_i = 0; _i < ad_len; _i++) {                                        /*########%*/
		_buffer_size_max += bt_data_buf_size(&ad[_i]);                   /*########C*/
		_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(struct bt_data));    /*########J*/
		_scratchpad_size += bt_data_sp_size(&ad[_i]);                    /*########/*/
	}                                                                        /*########m*/
	for (_i = 0; _i < sd_len; _i++) {                                        /*########7*/
		_buffer_size_max += bt_data_buf_size(&sd[_i]);                   /*########f*/
		_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(struct bt_data));    /*########M*/
		_scratchpad_size += bt_data_sp_size(&sd[_i]);                    /*#########*/
	}                                                                        /*########@*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*########%*/
	ser_encode_uint(&_ctx.encoder, ad_len);                                  /*########A*/
	for (_i = 0; _i < ad_len; _i++) {                                        /*########3*/
		bt_data_enc(&_ctx.encoder, &ad[_i]);                             /*########m*/
	}                                                                        /*########T*/
	ser_encode_uint(&_ctx.encoder, sd_len);                                  /*########w*/
	for (_i = 0; _i < sd_len; _i++) {                                        /*########G*/
		bt_data_enc(&_ctx.encoder, &sd[_i]);                             /*########Q*/
	}                                                                        /*########@*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_SET_DATA_RPC_CMD,     /*####%BOx7*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@tIA*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_ext_adv_update_param(struct bt_le_ext_adv *adv,
			       const struct bt_le_adv_param *param)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AY*/
	int _result;                                                             /*#######mU*/
	size_t _scratchpad_size = 0;                                             /*#######Us*/
	size_t _buffer_size_max = 10;                                            /*#######@E*/

	_buffer_size_max += bt_le_adv_param_buf_size(param);                     /*##CKvr4W4*/

	_scratchpad_size += bt_le_adv_param_sp_size(param);                      /*##EEZ/Gv4*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*####%A82t*/
	bt_le_adv_param_enc(&_ctx.encoder, param);                               /*#####@9JA*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_UPDATE_PARAM_RPC_CMD, /*####%BCQJ*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@H40*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_ext_adv_delete(struct bt_le_ext_adv *adv)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*##A7bUUXs*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_DELETE_RPC_CMD,       /*####%BEwr*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@L7Q*/

	return _result;                                                          /*##BX7TDLc*/
}

uint8_t bt_le_ext_adv_get_index(struct bt_le_ext_adv *adv)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ac*/
	uint8_t _result;                                                         /*######lxx*/
	size_t _buffer_size_max = 5;                                             /*######@q0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*##A7bUUXs*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_GET_INDEX_RPC_CMD,    /*####%BBLu*/
		&_ctx, ser_rsp_decode_u8, &_result);                             /*#####@SRI*/

	return _result;                                                          /*##BX7TDLc*/
}

UNUSED
static const size_t bt_le_ext_adv_info_buf_size = 4;                             /*##BvEf8RQ*/

void bt_le_ext_adv_info_enc(CborEncoder *_encoder, const struct bt_le_ext_adv_info *_data)/*####%BqGg*/
{                                                                                         /*#####@AXg*/

	SERIALIZE(STRUCT(struct bt_le_ext_adv_info));

	ser_encode_uint(_encoder, _data->id);                                             /*####%AzCC*/
	ser_encode_int(_encoder, _data->tx_power);                                        /*#####@as4*/

}                                                                                         /*##B9ELNqo*/


int bt_le_ext_adv_get_info(const struct bt_le_ext_adv *adv,
			   struct bt_le_ext_adv_info *info)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ad*/
	int _result;                                                             /*######voK*/
	size_t _buffer_size_max = 9;                                             /*######@/8*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*####%A1o5*/
	bt_le_ext_adv_info_enc(&_ctx.encoder, info);                             /*#####@7t0*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_GET_INFO_RPC_CMD,     /*####%BCVS*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@Azk*/

	return _result;                                                          /*##BX7TDLc*/
}

struct bt_le_ext_adv_oob_get_local_rpc_res                                       /*####%BiEN*/
{                                                                                /*#####@OIM*/

	int _result;                                                             /*####%CXk/*/
	struct bt_le_oob * oob;                                                  /*#####@aJI*/

};                                                                               /*##B985gv0*/

static void bt_le_ext_adv_oob_get_local_rpc_rsp(CborValue *_value, void *_handler_data)/*####%Bip2*/
{                                                                                      /*#####@zQs*/

	struct bt_le_ext_adv_oob_get_local_rpc_res *_res =                             /*####%AYRh*/
		(struct bt_le_ext_adv_oob_get_local_rpc_res *)_handler_data;           /*#####@lo4*/

	_res->_result = ser_decode_int(_value);                                        /*####%DR/C*/
	bt_le_oob_dec(_value, _res->oob);                                              /*#####@FlU*/

}                                                                                      /*##B9ELNqo*/

int bt_le_ext_adv_oob_get_local(struct bt_le_ext_adv *adv,
				struct bt_le_oob *oob)
{
	SERIALIZE(OUT(oob));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AQ*/
	struct bt_le_ext_adv_oob_get_local_rpc_res _result;                      /*######Ppb*/
	size_t _buffer_size_max = 5;                                             /*######@OI*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*##A7bUUXs*/

	_result.oob = oob;                                                       /*##C1H7kLY*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_EXT_ADV_OOB_GET_LOCAL_RPC_CMD,/*####%BDti*/
		&_ctx, bt_le_ext_adv_oob_get_local_rpc_rsp, &_result);           /*#####@wh8*/

	return _result._result;                                                  /*##BW0ge3U*/
}
#endif /* defined(CONFIG_BT_EXT_ADV) || defined(__GENERATOR) */

#if defined(CONFIG_BT_PER_ADV) || defined(__GENERATOR)
UNUSED
static const size_t bt_le_per_adv_param_buf_size = 11;                           /*##Bjl8k1o*/

void bt_le_per_adv_param_enc(CborEncoder *_encoder, const struct bt_le_per_adv_param *_data)/*####%Bia6*/
{                                                                                           /*#####@PRk*/

	SERIALIZE(STRUCT(struct bt_le_per_adv_param));

	ser_encode_uint(_encoder, _data->interval_min);                                     /*######%A4*/
	ser_encode_uint(_encoder, _data->interval_max);                                     /*######3gx*/
	ser_encode_uint(_encoder, _data->options);                                          /*######@Wg*/

}                                                                                           /*##B9ELNqo*/


int bt_le_per_adv_set_param(struct bt_le_ext_adv *adv,
			    const struct bt_le_per_adv_param *param)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######LET*/
	size_t _buffer_size_max = 16;                                            /*######@Ec*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*####%A+9+*/
	bt_le_per_adv_param_enc(&_ctx.encoder, param);                           /*#####@z2A*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SET_PARAM_RPC_CMD,    /*####%BNB7*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@lS8*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_per_adv_set_data(const struct bt_le_ext_adv *adv,
			   const struct bt_data *ad, size_t ad_len)
{
	SERIALIZE(SIZE_PARAM(ad, ad_len));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	int _result;                                                             /*#######dr*/
	size_t _scratchpad_size = 0;                                             /*#######k2*/
	size_t _buffer_size_max = 15;                                            /*#######pA*/
	size_t _i;                                                               /*########@*/

	for (_i = 0; _i < ad_len; _i++) {                                        /*#######%C*/
		_buffer_size_max += bt_data_buf_size(&ad[_i]);                   /*#######CC*/
		_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(struct bt_data));    /*#######cw*/
		_scratchpad_size += bt_data_sp_size(&ad[_i]);                    /*#######XI*/
	}                                                                        /*########@*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*#######%A*/
	ser_encode_uint(&_ctx.encoder, ad_len);                                  /*#######1N*/
	for (_i = 0; _i < ad_len; _i++) {                                        /*#######iB*/
		bt_data_enc(&_ctx.encoder, &ad[_i]);                             /*#######6E*/
	}                                                                        /*########@*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SET_DATA_RPC_CMD,     /*####%BNN3*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@MLI*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_per_adv_start(struct bt_le_ext_adv *adv)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*##A7bUUXs*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_START_RPC_CMD,        /*####%BLDr*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@bVA*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_per_adv_stop(struct bt_le_ext_adv *adv)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                          /*##A7bUUXs*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_STOP_RPC_CMD,         /*####%BGja*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@MSg*/

	return _result;                                                          /*##BX7TDLc*/
}

#if defined(CONFIG_BT_CONN) || defined(__GENERATOR)
int bt_le_per_adv_set_info_transfer(const struct bt_le_ext_adv *adv,
				    const struct bt_conn *conn,
				    uint16_t service_data)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                                /*######%Ac*/
	int _result;                                                                 /*######BI5*/
	size_t _buffer_size_max = 11;                                                /*######@0Y*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                                  /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)adv);                              /*######%Aw*/
	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);                                  /*######D2e*/
	ser_encode_uint(&_ctx.encoder, service_data);                                /*######@Hk*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SET_INFO_TRANSFER_RPC_CMD,/*####%BD+g*/
		&_ctx, ser_rsp_decode_i32, &_result);                                /*#####@Q8g*/

	return _result;                                                              /*##BX7TDLc*/
}
#endif /* defined(CONFIG_BT_CONN) || || defined(__GENERATOR) */
#endif /* defined(CONFIG_BT_PER_ADV) || defined(__GENERATOR) */

#if defined(CONFIG_BT_PER_ADV_SYNC) || defined(__GENERATOR)
uint8_t bt_le_per_adv_sync_get_index(struct bt_le_per_adv_sync *per_adv_sync)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                             /*######%Ac*/
	uint8_t _result;                                                          /*######lxx*/
	size_t _buffer_size_max = 5;                                              /*######@q0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                               /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)per_adv_sync);                  /*##AyCxMTE*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_GET_INDEX_RPC_CMD,/*####%BNqI*/
		&_ctx, ser_rsp_decode_u8, &_result);                              /*#####@ST8*/

	return _result;                                                           /*##BX7TDLc*/
}

size_t bt_le_per_adv_sync_param_buf_size(const struct bt_le_per_adv_sync_param *_data)/*####%BvB+*/
{                                                                                     /*#####@DZ8*/

	size_t _buffer_size_max = 16;                                                 /*##AdC7CZ0*/

	_buffer_size_max += sizeof(bt_addr_le_t);                                     /*##CN3eLBo*/

	return _buffer_size_max;                                                      /*##BWmN6G8*/

}                                                                                     /*##B9ELNqo*/

void bt_le_per_adv_sync_param_enc(CborEncoder *_encoder, const struct bt_le_per_adv_sync_param *_data)/*####%Bvxu*/
{                                                                                                     /*#####@f9s*/

	SERIALIZE(STRUCT(struct bt_le_per_adv_sync_param));

	ser_encode_buffer(_encoder, &_data->addr, sizeof(bt_addr_le_t));                              /*#######%A*/
	ser_encode_uint(_encoder, _data->sid);                                                        /*#######4m*/
	ser_encode_uint(_encoder, _data->options);                                                    /*#######8+*/
	ser_encode_uint(_encoder, _data->skip);                                                       /*#######70*/
	ser_encode_uint(_encoder, _data->timeout);                                                    /*########@*/

}                                                                                                     /*##B9ELNqo*/

struct bt_le_per_adv_sync_create_rpc_res                                         /*####%Bvwh*/
{                                                                                /*#####@Y1o*/

	int _result;                                                             /*####%Cdty*/
	struct bt_le_per_adv_sync ** out_sync;                                   /*#####@5Kg*/

};                                                                               /*##B985gv0*/

static void bt_le_per_adv_sync_create_rpc_rsp(CborValue *_value, void *_handler_data)       /*####%BlCp*/
{                                                                                           /*#####@VnE*/

	struct bt_le_per_adv_sync_create_rpc_res *_res =                                    /*####%AUBT*/
		(struct bt_le_per_adv_sync_create_rpc_res *)_handler_data;                  /*#####@RXU*/

	_res->_result = ser_decode_int(_value);                                             /*####%Daep*/
	*(_res->out_sync) = (struct bt_le_per_adv_sync *)(uintptr_t)ser_decode_uint(_value);/*#####@3Q4*/

}                                                                                           /*##B9ELNqo*/

int bt_le_per_adv_sync_create(const struct bt_le_per_adv_sync_param *param,
			      struct bt_le_per_adv_sync **out_sync)
{
	SERIALIZE(OUT(out_sync));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AR*/
	struct bt_le_per_adv_sync_create_rpc_res _result;                        /*######mbl*/
	size_t _buffer_size_max = 0;                                             /*######@yI*/

	_buffer_size_max += bt_le_per_adv_sync_param_buf_size(param);            /*##CKWn94E*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	bt_le_per_adv_sync_param_enc(&_ctx.encoder, param);                      /*##A7I7wxk*/

	_result.out_sync = out_sync;                                             /*##C6QtjrY*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_CREATE_RPC_CMD,  /*####%BPIv*/
		&_ctx, bt_le_per_adv_sync_create_rpc_rsp, &_result);             /*#####@XBs*/

	return _result._result;                                                  /*##BW0ge3U*/
}

int bt_le_per_adv_sync_delete(struct bt_le_per_adv_sync *per_adv_sync)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)per_adv_sync);                 /*##AyCxMTE*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_DELETE_RPC_CMD,  /*####%BMZ2*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@i5E*/

	return _result;                                                          /*##BX7TDLc*/
}

static sys_slist_t pa_sync_cbs = SYS_SLIST_STATIC_INIT(&pa_sync_cbs);

void bt_le_per_adv_sync_cb_register_on_remote(void)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                                         /*####%ATMv*/
	size_t _buffer_size_max = 0;                                                          /*#####@1d4*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                                           /*##AvrU03s*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_CB_REGISTER_ON_REMOTE_RPC_CMD,/*####%BCT/*/
		&_ctx, ser_rsp_decode_void, NULL);                                            /*#####@Eqo*/
}

void bt_le_per_adv_sync_cb_register(struct bt_le_per_adv_sync_cb *cb)
{
	bool register_on_remote;

	register_on_remote = sys_slist_is_empty(&pa_sync_cbs);

	sys_slist_append(&pa_sync_cbs, &cb->node);

	if (register_on_remote) {
		bt_le_per_adv_sync_cb_register_on_remote();
	}
}

int bt_le_per_adv_sync_recv_enable(struct bt_le_per_adv_sync *per_adv_sync)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                               /*######%Aa*/
	int _result;                                                                /*######Qso*/
	size_t _buffer_size_max = 5;                                                /*######@uA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                                 /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)per_adv_sync);                    /*##AyCxMTE*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_RECV_ENABLE_RPC_CMD,/*####%BFmV*/
		&_ctx, ser_rsp_decode_i32, &_result);                               /*#####@9jM*/

	return _result;                                                             /*##BX7TDLc*/
}

int bt_le_per_adv_sync_recv_disable(struct bt_le_per_adv_sync *per_adv_sync)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                                /*######%Aa*/
	int _result;                                                                 /*######Qso*/
	size_t _buffer_size_max = 5;                                                 /*######@uA*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                                  /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)per_adv_sync);                     /*##AyCxMTE*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_RECV_DISABLE_RPC_CMD,/*####%BK7z*/
		&_ctx, ser_rsp_decode_i32, &_result);                                /*#####@2+s*/

	return _result;                                                              /*##BX7TDLc*/
}

#if defined(CONFIG_BT_CONN) || defined(__GENERATOR)
int bt_le_per_adv_sync_transfer(const struct bt_le_per_adv_sync *per_adv_sync,
				const struct bt_conn *conn,
				uint16_t service_data)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ac*/
	int _result;                                                             /*######BI5*/
	size_t _buffer_size_max = 11;                                            /*######@0Y*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, (uintptr_t)per_adv_sync);                 /*######%A3*/
	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);                              /*######BK/*/
	ser_encode_uint(&_ctx.encoder, service_data);                            /*######@Gc*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_TRANSFER_RPC_CMD,/*####%BMMx*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@+A8*/

	return _result;                                                          /*##BX7TDLc*/
}
UNUSED
static const size_t bt_le_per_adv_sync_transfer_param_buf_size = 11;             /*##BvEY4ys*/

void bt_le_per_adv_sync_transfer_param_enc(CborEncoder *_encoder, const struct bt_le_per_adv_sync_transfer_param *_data)/*####%Bn/L*/
{                                                                                                                       /*#####@aTA*/

	SERIALIZE(STRUCT(struct bt_le_per_adv_sync_transfer_param));

	ser_encode_uint(_encoder, _data->skip);                                                                         /*######%A1*/
	ser_encode_uint(_encoder, _data->timeout);                                                                      /*######EtJ*/
	ser_encode_uint(_encoder, _data->options);                                                                      /*######@Lc*/

}                                                                                                                       /*##B9ELNqo*/

int bt_le_per_adv_sync_transfer_subscribe(
	const struct bt_conn *conn,
	const struct bt_le_per_adv_sync_transfer_param *param)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                                      /*######%Aa*/
	int _result;                                                                       /*######MUY*/
	size_t _buffer_size_max = 14;                                                      /*######@VU*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                                        /*##AvrU03s*/

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);                                        /*####%A+wT*/
	bt_le_per_adv_sync_transfer_param_enc(&_ctx.encoder, param);                       /*#####@VH8*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_TRANSFER_SUBSCRIBE_RPC_CMD,/*####%BA8T*/
		&_ctx, ser_rsp_decode_i32, &_result);                                      /*#####@eV0*/

	return _result;                                                                    /*##BX7TDLc*/
}

int bt_le_per_adv_sync_transfer_unsubscribe(const struct bt_conn *conn)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                                        /*######%AR*/
	int _result;                                                                         /*######RDP*/
	size_t _buffer_size_max = 3;                                                         /*######@sI*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                                          /*##AvrU03s*/

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);                                          /*##A0WTTl0*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_SYNC_TRANSFER_UNSUBSCRIBE_RPC_CMD,/*####%BFS1*/
		&_ctx, ser_rsp_decode_i32, &_result);                                        /*#####@+sY*/

	return _result;                                                                      /*##BX7TDLc*/
}
#endif /* defined(CONFIG_BT_CONN) */

int bt_le_per_adv_list_add(const bt_addr_le_t *addr, uint8_t sid)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*##CHCgvU0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*####%AwDj*/
	ser_encode_uint(&_ctx.encoder, sid);                                     /*#####@+Oo*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_LIST_ADD_RPC_CMD,     /*####%BLYP*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@4rw*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_per_adv_list_remove(const bt_addr_le_t *addr, uint8_t sid)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*##CHCgvU0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*####%AwDj*/
	ser_encode_uint(&_ctx.encoder, sid);                                     /*#####@+Oo*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_LIST_REMOVE_RPC_CMD,  /*####%BIoq*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@5j0*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_per_adv_list_clear(void)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AX*/
	int _result;                                                             /*######56+*/
	size_t _buffer_size_max = 0;                                             /*######@io*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_PER_ADV_LIST_CLEAR_RPC_CMD,   /*####%BP5b*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@jhU*/

	return _result;                                                          /*##BX7TDLc*/
}

void bt_le_per_adv_sync_synced_info_dec(struct ser_scratchpad *_scratchpad, struct bt_le_per_adv_sync_synced_info *_data)/*####%Buhz*/
{                                                                                                                        /*#####@+eU*/

	CborValue *_value = _scratchpad->value;                                                                          /*##AU3cSLw*/

	_data->addr = ser_decode_buffer_into_scratchpad(_scratchpad);                                                    /*#######%C*/
	_data->sid = ser_decode_uint(_value);                                                                            /*#######pt*/
	_data->interval = ser_decode_uint(_value);                                                                       /*########w*/
	_data->phy = ser_decode_uint(_value);                                                                            /*########w*/
	_data->recv_enabled = ser_decode_bool(_value);                                                                   /*########0*/
	_data->service_data = ser_decode_uint(_value);                                                                   /*########c*/
	_data->conn = bt_rpc_decode_bt_conn(_value);                                                                     /*########@*/

}                                                                                                                        /*##B9ELNqo*/

static void per_adv_sync_cb_synced(struct bt_le_per_adv_sync *sync,
				   struct bt_le_per_adv_sync_synced_info *info)
{
	SERIALIZE(IGNORE);

	struct bt_le_per_adv_sync_cb *listener;

	SYS_SLIST_FOR_EACH_CONTAINER(&pa_sync_cbs, listener, node) {
		if (listener->synced) {
			listener->synced(sync, info);
		}
	}
}

static void per_adv_sync_cb_synced_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bi1i*/
{                                                                                     /*#####@a4g*/

	struct bt_le_per_adv_sync * sync;                                             /*######%Ac*/
	struct bt_le_per_adv_sync_synced_info info;                                   /*######d5V*/
	struct ser_scratchpad _scratchpad;                                            /*######@2Y*/

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);                                   /*##EZKHjKY*/

	sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);                  /*####%CmCa*/
	bt_le_per_adv_sync_synced_info_dec(&_scratchpad, &info);                      /*#####@RgE*/

	if (!ser_decoding_done_and_check(_value)) {                                   /*######%FE*/
		goto decoding_error;                                                  /*######QTM*/
	}                                                                             /*######@1Y*/

	per_adv_sync_cb_synced(sync, &info);                                          /*##DtmZTFs*/

		SER_SCRATCHPAD_FREE(&_scratchpad);                                    /*##Eq1r7Tg*/

	ser_rsp_send_void();                                                          /*##BEYGLxw*/

	return;                                                                       /*######%FU*/
decoding_error:                                                                       /*#######ho*/
	report_decoding_error(PER_ADV_SYNC_CB_SYNCED_RPC_CMD, _handler_data);         /*#######yM*/
	SER_SCRATCHPAD_FREE(&_scratchpad);                                            /*#######@I*/

}                                                                                     /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, per_adv_sync_cb_synced, PER_ADV_SYNC_CB_SYNCED_RPC_CMD,/*####%BiaR*/
	per_adv_sync_cb_synced_rpc_handler, NULL);                                          /*#####@Hp4*/

void bt_le_per_adv_sync_term_info_dec(struct ser_scratchpad *_scratchpad, struct bt_le_per_adv_sync_term_info *_data)/*####%BmXW*/
{                                                                                                                    /*#####@xho*/

	CborValue *_value = _scratchpad->value;                                                                      /*##AU3cSLw*/

	_data->addr = ser_decode_buffer_into_scratchpad(_scratchpad);                                                /*####%Cmgh*/
	_data->sid = ser_decode_uint(_value);                                                                        /*#####@KUY*/

}                                                                                                                    /*##B9ELNqo*/

void bt_le_per_adv_sync_recv_info_dec(struct ser_scratchpad *_scratchpad, struct bt_le_per_adv_sync_recv_info *_data)/*####%BvIW*/
{                                                                                                                    /*#####@8OA*/

	CborValue *_value = _scratchpad->value;                                                                      /*##AU3cSLw*/

	_data->addr = ser_decode_buffer_into_scratchpad(_scratchpad);                                                /*#######%C*/
	_data->sid = ser_decode_uint(_value);                                                                        /*#######po*/
	_data->tx_power = ser_decode_int(_value);                                                                    /*#######2/*/
	_data->rssi = ser_decode_int(_value);                                                                        /*#######q4*/
	_data->cte_type = ser_decode_uint(_value);                                                                   /*########@*/

}                                                                                                                    /*##B9ELNqo*/

void bt_le_per_adv_sync_state_info_dec(CborValue *_value, struct bt_le_per_adv_sync_state_info *_data)/*####%BkuY*/
{                                                                                                     /*#####@yMY*/

	_data->recv_enabled = ser_decode_bool(_value);                                                /*##Cktm3mQ*/

}                                                                                                     /*##B9ELNqo*/

void per_adv_sync_cb_term(struct bt_le_per_adv_sync *sync,
			  const struct bt_le_per_adv_sync_term_info *info)
{
	SERIALIZE(IGNORE);

	struct bt_le_per_adv_sync_cb *listener;

	SYS_SLIST_FOR_EACH_CONTAINER(&pa_sync_cbs, listener, node) {
		if (listener->term) {
			listener->term(sync, info);
		}
	}
}

static void per_adv_sync_cb_term_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bocf*/
{                                                                                   /*#####@fSw*/

	struct bt_le_per_adv_sync * sync;                                           /*######%AQ*/
	struct bt_le_per_adv_sync_term_info info;                                   /*######lSu*/
	struct ser_scratchpad _scratchpad;                                          /*######@5g*/

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);                                 /*##EZKHjKY*/

	sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);                /*####%Chkm*/
	bt_le_per_adv_sync_term_info_dec(&_scratchpad, &info);                      /*#####@hek*/

	if (!ser_decoding_done_and_check(_value)) {                                 /*######%FE*/
		goto decoding_error;                                                /*######QTM*/
	}                                                                           /*######@1Y*/

	per_adv_sync_cb_term(sync, &info);                                          /*##DvfOJtM*/

		SER_SCRATCHPAD_FREE(&_scratchpad);                                  /*##Eq1r7Tg*/

	ser_rsp_send_void();                                                        /*##BEYGLxw*/

	return;                                                                     /*######%FT*/
decoding_error:                                                                     /*#######EO*/
	report_decoding_error(PER_ADV_SYNC_CB_TERM_RPC_CMD, _handler_data);         /*#######Dv*/
	SER_SCRATCHPAD_FREE(&_scratchpad);                                          /*#######@4*/

}                                                                                   /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, per_adv_sync_cb_term, PER_ADV_SYNC_CB_TERM_RPC_CMD,/*####%Bgpi*/
	per_adv_sync_cb_term_rpc_handler, NULL);                                        /*#####@+ck*/

void per_adv_sync_cb_recv(struct bt_le_per_adv_sync *sync,
			  const struct bt_le_per_adv_sync_recv_info *info,
			  struct net_buf_simple *buf)
{
	SERIALIZE(IGNORE);

	struct net_buf_simple_state state;
	struct bt_le_per_adv_sync_cb *listener;

	SYS_SLIST_FOR_EACH_CONTAINER(&pa_sync_cbs, listener, node) {
		if (listener->recv) {
			net_buf_simple_save(buf, &state);
			listener->recv(sync, info, buf);
			net_buf_simple_restore(buf, &state);
		}
	}
}

static void per_adv_sync_cb_recv_rpc_handler(CborValue *_value, void *_handler_data)/*####%BmPh*/
{                                                                                   /*#####@jzA*/

	struct bt_le_per_adv_sync * sync;                                           /*######%Ab*/
	struct bt_le_per_adv_sync_recv_info info;                                   /*#######Xd*/
	struct net_buf_simple buf;                                                  /*#######xK*/
	struct ser_scratchpad _scratchpad;                                          /*#######@Y*/

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);                                 /*##EZKHjKY*/

	sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);                /*######%Cr*/
	bt_le_per_adv_sync_recv_info_dec(&_scratchpad, &info);                      /*######DHt*/
	net_buf_simple_dec(&_scratchpad, &buf);                                     /*######@d8*/

	if (!ser_decoding_done_and_check(_value)) {                                 /*######%FE*/
		goto decoding_error;                                                /*######QTM*/
	}                                                                           /*######@1Y*/

	per_adv_sync_cb_recv(sync, &info, &buf);                                    /*##Dl8H27w*/

		SER_SCRATCHPAD_FREE(&_scratchpad);                                  /*##Eq1r7Tg*/

	ser_rsp_send_void();                                                        /*##BEYGLxw*/

	return;                                                                     /*######%Fb*/
decoding_error:                                                                     /*#######hQ*/
	report_decoding_error(PER_ADV_SYNC_CB_RECV_RPC_CMD, _handler_data);         /*#######wy*/
	SER_SCRATCHPAD_FREE(&_scratchpad);                                          /*#######@0*/

}                                                                                   /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, per_adv_sync_cb_recv, PER_ADV_SYNC_CB_RECV_RPC_CMD,/*####%Bh2G*/
	per_adv_sync_cb_recv_rpc_handler, NULL);                                        /*#####@roY*/

void per_adv_sync_cb_state_changed(struct bt_le_per_adv_sync *sync,
				   const struct bt_le_per_adv_sync_state_info *info)
{
	SERIALIZE(IGNORE);

	struct bt_le_per_adv_sync_cb *listener;

	SYS_SLIST_FOR_EACH_CONTAINER(&pa_sync_cbs, listener, node) {
		if (listener->state_changed) {
			listener->state_changed(sync, info);
		}
	}
}

static void per_adv_sync_cb_state_changed_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bvnd*/
{                                                                                            /*#####@y6w*/

	struct bt_le_per_adv_sync * sync;                                                    /*####%AT4P*/
	struct bt_le_per_adv_sync_state_info info;                                           /*#####@lo4*/

	sync = (struct bt_le_per_adv_sync *)ser_decode_uint(_value);                         /*####%Cp7i*/
	bt_le_per_adv_sync_state_info_dec(_value, &info);                                    /*#####@sAY*/

	if (!ser_decoding_done_and_check(_value)) {                                          /*######%FE*/
		goto decoding_error;                                                         /*######QTM*/
	}                                                                                    /*######@1Y*/

	per_adv_sync_cb_state_changed(sync, &info);                                          /*##DqIt238*/

	ser_rsp_send_void();                                                                 /*##BEYGLxw*/

	return;                                                                              /*######%FX*/
decoding_error:                                                                              /*######TeR*/
	report_decoding_error(PER_ADV_SYNC_CB_STATE_CHANGED_RPC_CMD, _handler_data);         /*######@U0*/

}                                                                                            /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, per_adv_sync_cb_state_changed, PER_ADV_SYNC_CB_STATE_CHANGED_RPC_CMD,/*####%Bsmn*/
	per_adv_sync_cb_state_changed_rpc_handler, NULL);                                                 /*#####@Ovw*/
#endif /* defined(CONFIG_BT_PER_ADV_SYNC) || defined(__GENERATOR) */

#if defined(CONFIG_BT_OBSERVER) || defined(__GENERATOR)
int bt_le_scan_start(const struct bt_le_scan_param *param, bt_le_scan_cb_t cb)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AR*/
	int _result;                                                             /*######PI0*/
	size_t _buffer_size_max = 27;                                            /*######@Mk*/

	_result = 0;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	bt_le_scan_param_enc(&_ctx.encoder, param);                              /*####%A+tp*/
	ser_encode_callback(&_ctx.encoder, cb);                                  /*#####@nI8*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SCAN_START_RPC_CMD,           /*####%BH2T*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@V0I*/

	return _result;                                                          /*##BX7TDLc*/
}

int bt_le_scan_stop(void)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AX*/
	int _result;                                                             /*######56+*/
	size_t _buffer_size_max = 0;                                             /*######@io*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SCAN_STOP_RPC_CMD,            /*####%BCbu*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@46U*/

	return _result;                                                          /*##BX7TDLc*/
}

void bt_le_scan_recv_info_dec(struct ser_scratchpad *_scratchpad, struct bt_le_scan_recv_info *_data)/*####%BpcV*/
{                                                                                                    /*#####@rYc*/

	CborValue *_value = _scratchpad->value;                                                      /*##AU3cSLw*/

	_data->addr = ser_decode_buffer_into_scratchpad(_scratchpad);                                /*########%*/
	_data->sid = ser_decode_uint(_value);                                                        /*########C*/
	_data->rssi = ser_decode_int(_value);                                                        /*########t*/
	_data->tx_power = ser_decode_int(_value);                                                    /*########B*/
	_data->adv_type = ser_decode_uint(_value);                                                   /*########F*/
	_data->adv_props = ser_decode_uint(_value);                                                  /*########R*/
	_data->interval = ser_decode_uint(_value);                                                   /*########f*/
	_data->primary_phy = ser_decode_uint(_value);                                                /*########w*/
	_data->secondary_phy = ser_decode_uint(_value);                                              /*########@*/

}                                                                                                    /*##B9ELNqo*/


static sys_slist_t scan_cbs = SYS_SLIST_STATIC_INIT(&scan_cbs);


static void bt_le_scan_cb_recv(const struct bt_le_scan_recv_info *info,
			       struct net_buf_simple *buf)
{
	SERIALIZE(IGNORE);

	struct bt_le_scan_cb *listener;
	struct net_buf_simple_state state;

	SYS_SLIST_FOR_EACH_CONTAINER(&scan_cbs, listener, node) {
		net_buf_simple_save(buf, &state);
		listener->recv(info, buf);
		net_buf_simple_restore(buf, &state);
	}
}

static void bt_le_scan_cb_recv_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bn4W*/
{                                                                                 /*#####@TR4*/

	struct bt_le_scan_recv_info info;                                         /*######%AU*/
	struct net_buf_simple buf;                                                /*######QJk*/
	struct ser_scratchpad _scratchpad;                                        /*######@yc*/

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);                               /*##EZKHjKY*/

	bt_le_scan_recv_info_dec(&_scratchpad, &info);                            /*####%Cjth*/
	net_buf_simple_dec(&_scratchpad, &buf);                                   /*#####@XMc*/

	if (!ser_decoding_done_and_check(_value)) {                               /*######%FE*/
		goto decoding_error;                                              /*######QTM*/
	}                                                                         /*######@1Y*/

	bt_le_scan_cb_recv(&info, &buf);                                          /*##Dv8VuU0*/

		SER_SCRATCHPAD_FREE(&_scratchpad);                                /*##Eq1r7Tg*/

	ser_rsp_send_void();                                                      /*##BEYGLxw*/

	return;                                                                   /*######%FU*/
decoding_error:                                                                   /*#######nS*/
	report_decoding_error(BT_LE_SCAN_CB_RECV_RPC_CMD, _handler_data);         /*#######LB*/
	SER_SCRATCHPAD_FREE(&_scratchpad);                                        /*#######@0*/

}                                                                                 /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_scan_cb_recv, BT_LE_SCAN_CB_RECV_RPC_CMD,/*####%Bp/O*/
	bt_le_scan_cb_recv_rpc_handler, NULL);                                      /*#####@bR8*/


static void bt_le_scan_cb_timeout(void)
{
	SERIALIZE(IGNORE);

	struct bt_le_scan_cb *listener;

	SYS_SLIST_FOR_EACH_CONTAINER(&scan_cbs, listener, node) {
		listener->timeout();
	}
}

static void bt_le_scan_cb_timeout_rpc_handler(CborValue *_value, void *_handler_data)/*####%BjmK*/
{                                                                                    /*#####@5cI*/

	nrf_rpc_cbor_decoding_done(_value);                                          /*##FGkSPWY*/

	bt_le_scan_cb_timeout();                                                     /*##DnhVKj8*/

	ser_rsp_send_void();                                                         /*##BEYGLxw*/

}                                                                                    /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_le_scan_cb_timeout, BT_LE_SCAN_CB_TIMEOUT_RPC_CMD,/*####%BkGk*/
	bt_le_scan_cb_timeout_rpc_handler, NULL);                                         /*#####@4uY*/


static void bt_le_scan_cb_register_on_remote(void) {
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                                 /*####%ATMv*/
	size_t _buffer_size_max = 0;                                                  /*#####@1d4*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                                   /*##AvrU03s*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SCAN_CB_REGISTER_ON_REMOTE_RPC_CMD,/*####%BNwX*/
		&_ctx, ser_rsp_decode_void, NULL);                                    /*#####@WhA*/
}

void bt_le_scan_cb_register(struct bt_le_scan_cb *cb)
{
	bool register_on_remote;

	register_on_remote = sys_slist_is_empty(&scan_cbs);

	sys_slist_append(&scan_cbs, &cb->node);

	if (register_on_remote) {
		bt_le_scan_cb_register_on_remote();
	}
}
#endif /* defined(CONFIG_BT_OBSERVER) || defined(__GENERATOR) */

#if defined(CONFIG_BT_WHITELIST) || defined(__GENERATOR)
int bt_le_whitelist_add(const bt_addr_le_t *addr)
{
	SERIALIZE(NULLABLE(addr));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AR*/
	int _result;                                                             /*######RDP*/
	size_t _buffer_size_max = 3;                                             /*######@sI*/

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*##CHCgvU0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*##A9rQrRg*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_WHITELIST_ADD_RPC_CMD,        /*####%BJiW*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@R1Y*/

	return _result;                                                          /*##BX7TDLc*/
}


int bt_le_whitelist_rem(const bt_addr_le_t *addr)
{
	SERIALIZE(NULLABLE(addr));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AR*/
	int _result;                                                             /*######RDP*/
	size_t _buffer_size_max = 3;                                             /*######@sI*/

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*##CHCgvU0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*##A9rQrRg*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_WHITELIST_REM_RPC_CMD,        /*####%BPHp*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@2yc*/

	return _result;                                                          /*##BX7TDLc*/
}


int bt_le_whitelist_clear(void)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AX*/
	int _result;                                                             /*######56+*/
	size_t _buffer_size_max = 0;                                             /*######@io*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_WHITELIST_CLEAR_RPC_CMD,      /*####%BOPs*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@CpE*/

	return _result;                                                          /*##BX7TDLc*/
}

#endif /* defined(CONFIG_BT_WHITELIST) || defined(__GENERATOR) */

int bt_le_set_chan_map(uint8_t chan_map[5])
{
	SERIALIZE(SIZE(chan_map, 5));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	size_t _chan_map_size;                                                   /*#######Sz*/
	int _result;                                                             /*#######xQ*/
	size_t _scratchpad_size = 0;                                             /*#######pA*/
	size_t _buffer_size_max = 10;                                            /*########@*/

	_chan_map_size = sizeof(uint8_t) * 5;                                    /*####%CGlM*/
	_buffer_size_max += _chan_map_size;                                      /*#####@6lU*/

	_scratchpad_size += SCRATCHPAD_ALIGN(_chan_map_size);                    /*##EJHhpZ4*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_buffer(&_ctx.encoder, chan_map, _chan_map_size);              /*##A4qUuxk*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_SET_CHAN_MAP_RPC_CMD,         /*####%BDPn*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@dfg*/

	return _result;                                                          /*##BX7TDLc*/
}


void bt_data_parse(struct net_buf_simple *ad,
		   bool (*func)(struct bt_data *data, void *user_data),
		   void *user_data)
{
	while (ad->len > 1) {
		struct bt_data data;
		uint8_t len;

		len = net_buf_simple_pull_u8(ad);
		if (len == 0U) {
			/* Early termination */
			return;
		}

		if (len > ad->len) {
			LOG_WRN("Malformed data");
			return;
		}

		data.type = net_buf_simple_pull_u8(ad);
		data.data_len = len - 1;
		data.data = ad->data;

		if (!func(&data, user_data)) {
			return;
		}

		net_buf_simple_pull(ad, len - 1);
	}
}


struct bt_le_oob_get_local_rpc_res                                               /*####%BtvS*/
{                                                                                /*#####@LW8*/

	int _result;                                                             /*####%CXk/*/
	struct bt_le_oob * oob;                                                  /*#####@aJI*/

};                                                                               /*##B985gv0*/

static void bt_le_oob_get_local_rpc_rsp(CborValue *_value, void *_handler_data)  /*####%BkkP*/
{                                                                                /*#####@R00*/

	struct bt_le_oob_get_local_rpc_res *_res =                               /*####%ARp5*/
		(struct bt_le_oob_get_local_rpc_res *)_handler_data;             /*#####@QGY*/

	_res->_result = ser_decode_int(_value);                                  /*####%DR/C*/
	bt_le_oob_dec(_value, _res->oob);                                        /*#####@FlU*/

}                                                                                /*##B9ELNqo*/

int bt_le_oob_get_local(uint8_t id, struct bt_le_oob *oob)
{
	SERIALIZE(OUT(oob));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ac*/
	struct bt_le_oob_get_local_rpc_res _result;                              /*######0n1*/
	size_t _buffer_size_max = 2;                                             /*######@dw*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, id);                                      /*##A9BnOB4*/

	_result.oob = oob;                                                       /*##C1H7kLY*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_LE_OOB_GET_LOCAL_RPC_CMD,        /*####%BP2i*/
		&_ctx, bt_le_oob_get_local_rpc_rsp, &_result);                   /*#####@okg*/

	return _result._result;                                                  /*##BW0ge3U*/
}

int bt_addr_from_str(const char *str, bt_addr_t *addr)
{
	int i, j;
	uint8_t tmp;

	if (strlen(str) != 17U) {
		return -EINVAL;
	}

	for (i = 5, j = 1; *str != '\0'; str++, j++) {
		if (!(j % 3) && (*str != ':')) {
			return -EINVAL;
		} else if (*str == ':') {
			i--;
			continue;
		}

		addr->val[i] = addr->val[i] << 4;

		if (char2hex(*str, &tmp) < 0) {
			return -EINVAL;
		}

		addr->val[i] |= tmp;
	}

	return 0;
}

int bt_addr_le_from_str(const char *str, const char *type, bt_addr_le_t *addr)
{
	int err;

	err = bt_addr_from_str(str, &addr->a);
	if (err < 0) {
		return err;
	}

	if (!strcmp(type, "public") || !strcmp(type, "(public)")) {
		addr->type = BT_ADDR_LE_PUBLIC;
	} else if (!strcmp(type, "random") || !strcmp(type, "(random)")) {
		addr->type = BT_ADDR_LE_RANDOM;
	} else if (!strcmp(type, "public-id") || !strcmp(type, "(public-id)")) {
		addr->type = BT_ADDR_LE_PUBLIC_ID;
	} else if (!strcmp(type, "random-id") || !strcmp(type, "(random-id)")) {
		addr->type = BT_ADDR_LE_RANDOM_ID;
	} else {
		return -EINVAL;
	}

	return 0;
}

#if defined(CONFIG_BT_CONN) || defined(__GENERATOR)
int bt_unpair(uint8_t id, const bt_addr_le_t *addr)
{
	SERIALIZE(NULLABLE(addr));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Aa*/
	int _result;                                                             /*######Qso*/
	size_t _buffer_size_max = 5;                                             /*######@uA*/

	_buffer_size_max += addr ? sizeof(bt_addr_le_t) : 0;                     /*##CHCgvU0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, id);                                      /*####%A3Ax*/
	ser_encode_buffer(&_ctx.encoder, addr, sizeof(bt_addr_le_t));            /*#####@8HM*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_UNPAIR_RPC_CMD,                  /*####%BJYf*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@xsY*/

	return _result;                                                          /*##BX7TDLc*/
}
#endif /* defined(CONFIG_BT_CONN) || defined(__GENERATOR) */

#if (defined(CONFIG_BT_CONN) && defined(CONFIG_BT_SMP)) || defined(__GENERATOR)
void bt_bond_info_dec(CborValue *_value, struct bt_bond_info *_data)             /*####%BrU8*/
{                                                                                /*#####@tRo*/

	ser_decode_buffer(_value, &_data->addr, sizeof(bt_addr_le_t));           /*##CgG4yJo*/

}                                                                                /*##B9ELNqo*/

static void bt_foreach_bond_cb_callback_rpc_handler(CborValue *_value, void *_handler_data)/*####%Bogp*/
{                                                                                          /*#####@hUU*/

	struct bt_bond_info info;                                                          /*######%AU*/
	void * user_data;                                                                  /*######3TW*/
	bt_foreach_bond_cb callback_slot;                                                  /*######@88*/

	bt_bond_info_dec(_value, &info);                                                   /*######%Cg*/
	user_data = (void *)ser_decode_uint(_value);                                       /*######w5b*/
	callback_slot = (bt_foreach_bond_cb)ser_decode_callback_call(_value);              /*######@2o*/

	if (!ser_decoding_done_and_check(_value)) {                                        /*######%FE*/
		goto decoding_error;                                                       /*######QTM*/
	}                                                                                  /*######@1Y*/

	callback_slot(&info, user_data);                                                   /*##Djd0hGA*/

	ser_rsp_send_void();                                                               /*##BEYGLxw*/

	return;                                                                            /*######%Fa*/
decoding_error:                                                                            /*######8IZ*/
	report_decoding_error(BT_FOREACH_BOND_CB_CALLBACK_RPC_CMD, _handler_data);         /*######@D4*/

}                                                                                          /*##B9ELNqo*/

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_foreach_bond_cb_callback, BT_FOREACH_BOND_CB_CALLBACK_RPC_CMD,/*####%Bi02*/
	bt_foreach_bond_cb_callback_rpc_handler, NULL);                                               /*#####@CkI*/

void bt_foreach_bond(uint8_t id, void (*func)(const struct bt_bond_info *info,
					   void *user_data),
		     void *user_data)
{
	SERIALIZE(TYPE(func, bt_foreach_bond_cb));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*####%AYVb*/
	size_t _buffer_size_max = 12;                                            /*#####@PYw*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, id);                                      /*######%A8*/
	ser_encode_callback(&_ctx.encoder, func);                                /*######9qY*/
	ser_encode_uint(&_ctx.encoder, (uintptr_t)user_data);                    /*######@D0*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_FOREACH_BOND_RPC_CMD,            /*####%BNqs*/
		&_ctx, ser_rsp_decode_void, NULL);                               /*#####@uN8*/
}
#endif /* (defined(CONFIG_BT_CONN) && defined(CONFIG_BT_SMP)) || defined(__GENERATOR) */
