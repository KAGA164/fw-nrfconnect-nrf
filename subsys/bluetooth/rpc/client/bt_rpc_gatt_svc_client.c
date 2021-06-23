/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/* Client side of bluetooth API over nRF RPC.
 */

#include <sys/types.h>

#include "nrf_rpc_cbor.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/att.h"
#include "bluetooth/gatt.h"

#include "bt_rpc_common.h"
#include "bt_rpc_gatt_common.h"
#include "serialize.h"
#include "cbkproxy.h"

#include <logging/log.h>

LOG_MODULE_DECLARE(BT_RPC, CONFIG_BT_RPC_LOG_LEVEL);


#ifndef SERIALIZE
#define SERIALIZE(...)
#endif

SERIALIZE(GROUP(bt_rpc_grp));
SERIALIZE(OPAQUE_STRUCT(void));
SERIALIZE(FILTERED_STRUCT(struct bt_conn, 3, bt_rpc_encode_bt_conn, bt_rpc_decode_bt_conn));
SERIALIZE(FILTERED_STRUCT(struct bt_gatt_attr, 5, bt_rpc_encode_gatt_attr, bt_rpc_decode_gatt_attr));
SERIALIZE(FIELD_TYPE(struct bt_gatt_notify_params, uint8_t *, data));
SERIALIZE(FIELD_TYPE(struct bt_gatt_indicate_params, uint8_t *, data));
SERIALIZE(FIELD_TYPE(struct bt_rpc_gatt_indication_params, uint8_t *, params.data));


#ifndef __GENERATOR
#define UNUSED __attribute__((unused)) /* TODO: Improve generator to avoid this workaround */
#else
#define UNUSED ;
#endif

static struct bt_uuid const * const uuid_primary = BT_UUID_GATT_PRIMARY;
static struct bt_uuid const * const uuid_secondary = BT_UUID_GATT_SECONDARY;
static struct bt_uuid const * const uuid_chrc = BT_UUID_GATT_CHRC;
static struct bt_uuid const * const uuid_ccc = BT_UUID_GATT_CCC;
static struct bt_uuid const * const uuid_cep = BT_UUID_GATT_CEP;
static struct bt_uuid const * const uuid_cud = BT_UUID_GATT_CUD;
static struct bt_uuid const * const uuid_cpf = BT_UUID_GATT_CPF;

#if !defined(__GNUC__)
#error Attribute read and write default function for services, characteristics and descriptors \
       are implemented only for GCC
#endif

#define GENERIC_ATTR_READ_FUNCTION_CREATE(_name) \
	ssize_t _CONCAT(bt_gatt_attr_read_, _name) (struct bt_conn *conn, \
						    const struct bt_gatt_attr *attr, \
						    void *buf, uint16_t len, uint16_t offset) \
	{ \
		__builtin_unreachable (); \
	}

GENERIC_ATTR_READ_FUNCTION_CREATE(service);
GENERIC_ATTR_READ_FUNCTION_CREATE(chrc);
GENERIC_ATTR_READ_FUNCTION_CREATE(included);
GENERIC_ATTR_READ_FUNCTION_CREATE(ccc);
GENERIC_ATTR_READ_FUNCTION_CREATE(cep);
GENERIC_ATTR_READ_FUNCTION_CREATE(cud);
GENERIC_ATTR_READ_FUNCTION_CREATE(cpf);

ssize_t bt_gatt_attr_write_ccc(struct bt_conn *conn,
			       const struct bt_gatt_attr *attr, const void *buf,
			       uint16_t len, uint16_t offset, uint8_t flags)
{
	__builtin_unreachable ();
}

void bt_rpc_encode_gatt_attr(CborEncoder *encoder, const struct bt_gatt_attr *attr)
{
	uint32_t attr_index;
	int err;

	err = bt_rpc_gatt_attr_to_index(attr, &attr_index);
	__ASSERT(err == 0, "Service attribute not found. Service database might be out of sync");

	ser_encode_uint(encoder, attr_index);
}
const struct bt_gatt_attr *bt_rpc_decode_gatt_attr(CborValue *value)
{
	uint32_t attr_index;

	attr_index = ser_decode_uint(value);

	return bt_rpc_gatt_index_to_attr(attr_index);
}

static void report_decoding_error(uint8_t cmd_evt_id, void *data)
{
	nrf_rpc_err(-EBADMSG, NRF_RPC_ERR_SRC_RECV, &bt_rpc_grp, cmd_evt_id,
		    NRF_RPC_PACKET_TYPE_CMD);
}

ssize_t bt_gatt_attr_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			  void *buf, uint16_t buf_len, uint16_t offset,
			  const void *value, uint16_t value_len)
{
	uint16_t len;

	if (offset > value_len) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	len = MIN(buf_len, value_len - offset);

	LOG_DBG("handle 0x%04x offset %u length %u", attr->handle, offset, len);

	memcpy(buf, (uint8_t *)value + offset, len);

	return len;
}

static void bt_gatt_complete_func_t_callback_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn *conn;
	bt_gatt_complete_func_t callback_slot;
	void *user_data;

	conn = bt_rpc_decode_bt_conn(_value);
	user_data = (void *)ser_decode_uint(_value);
	callback_slot = (bt_gatt_complete_func_t)ser_decode_callback_call(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	callback_slot(conn, user_data);

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_GATT_COMPLETE_FUNC_T_CALLBACK_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_gatt_complete_func_t_callback,
			 BT_GATT_COMPLETE_FUNC_T_CALLBACK_RPC_CMD,
			 bt_gatt_complete_func_t_callback_rpc_handler, NULL);

static void bt_rpc_gatt_ccc_cfg_changed_cb_rpc_handler(CborValue *_value, void *_handler_data)
{
	uint32_t attr_index;
	uint16_t value;
	const struct bt_gatt_attr *attr;
	struct _bt_gatt_ccc *ccc;

	attr_index = ser_decode_uint(_value);
	value = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	attr = bt_rpc_gatt_index_to_attr(attr_index);
	if (!attr) {
		return;
	}

	ccc = (struct _bt_gatt_ccc *) attr->user_data;

	if (ccc->cfg_changed) {
		ccc->cfg_changed(attr, value);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_RPC_GATT_CB_ATTR_READ_RPC_CMD, _handler_data);		
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_gatt_ccc_cfg_changed_cb,
			 BT_RPC_GATT_CB_CCC_CFG_CHANGED_RPC_CMD,
			 bt_rpc_gatt_ccc_cfg_changed_cb_rpc_handler, NULL);

static void bt_rpc_gatt_attr_read_cb_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct nrf_rpc_cbor_ctx _ctx;
	struct bt_conn *conn;
	struct ser_scratchpad _scratchpad;
	size_t _buffer_size_max = 9;
	const struct bt_gatt_attr *attr;
	uint32_t service_index;
	ssize_t read_len = 0;
	uint16_t offset;
	uint16_t len;
	uint8_t *buf = NULL;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	conn = bt_rpc_decode_bt_conn(_value);
	service_index = ser_decode_uint(_value);
	len = ser_decode_uint(_value);
	offset = ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	attr = bt_rpc_gatt_index_to_attr(service_index);
	if (!attr) {
		LOG_WRN("Service database may not be synchronized with client");
		read_len = BT_GATT_ERR(BT_ATT_ERR_ATTRIBUTE_NOT_FOUND);
	} else {
		buf = ser_scratchpad_add(&_scratchpad, len);

		if (attr->read) {
			read_len = attr->read(conn, attr, buf, len, offset);
		}

		_buffer_size_max += (read_len > 0) ? read_len : 0;
	}

	{
		NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

		ser_encode_int(&_ctx.encoder, read_len);
		ser_encode_buffer(&_ctx.encoder, buf, read_len);

		SER_SCRATCHPAD_FREE(&_scratchpad);

		nrf_rpc_cbor_rsp_no_err(&_ctx);
	}

	return;
decoding_error:
	report_decoding_error(BT_RPC_GATT_CB_ATTR_READ_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);	
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_gatt_attr_read_cb, BT_RPC_GATT_CB_ATTR_READ_RPC_CMD,
	bt_rpc_gatt_attr_read_cb_rpc_handler, NULL);

static void bt_rpc_gatt_attr_write_cb_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct ser_scratchpad _scratchpad;
	struct bt_conn *conn;
	const struct bt_gatt_attr *attr;
	int service_index;
	int write_len = 0;
	uint16_t len;
	uint16_t offset;
	uint8_t flags;
	uint8_t *buf;

	SER_SCRATCHPAD_ALLOC(&_scratchpad, _value);

	conn = bt_rpc_decode_bt_conn(_value);
	service_index = ser_decode_int(_value);
	len = ser_decode_uint(_value);
	offset = ser_decode_uint(_value);
	flags = ser_decode_uint(_value);
	buf = ser_decode_buffer_into_scratchpad(&_scratchpad);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	attr = bt_rpc_gatt_index_to_attr(service_index);
	if (!attr) {
		LOG_WRN("Service database may not be synchronized with client");
		write_len = BT_GATT_ERR(BT_ATT_ERR_ATTRIBUTE_NOT_FOUND);
	} else {
		if (attr->write) {
			write_len = attr->write(conn, attr, buf, len, offset, flags);
		}
	}

	SER_SCRATCHPAD_FREE(&_scratchpad);

	ser_rsp_send_int(write_len);

	return;
decoding_error:
	report_decoding_error(BT_RPC_GATT_CB_ATTR_WRITE_RPC_CMD, _handler_data);
	SER_SCRATCHPAD_FREE(&_scratchpad);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_rpc_gatt_attr_write_cb, BT_RPC_GATT_CB_ATTR_WRITE_RPC_CMD,
	bt_rpc_gatt_attr_write_cb_rpc_handler, NULL);

static int bt_rpc_gatt_start_service(uint8_t service_index, size_t attr_count)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AT*/
	int _result;                                                             /*######ewD*/
	size_t _buffer_size_max = 7;                                             /*######@6Y*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	ser_encode_uint(&_ctx.encoder, service_index);                           /*####%A53t*/
	ser_encode_uint(&_ctx.encoder, attr_count);                              /*#####@gs4*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_GATT_START_SERVICE_RPC_CMD,  /*####%BFOA*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@/C8*/

	return _result;                                                          /*##BX7TDLc*/
}

static size_t bt_uuid_buf_size(const struct bt_uuid *uuid) {
	switch (uuid->type) {
	case BT_UUID_TYPE_16:
		return sizeof(struct bt_uuid_16);
	
	case BT_UUID_TYPE_32:
		return sizeof(struct bt_uuid_32);
	
	case BT_UUID_TYPE_128:
		return sizeof(struct bt_uuid_128);
	
	default:
		return 0;
	}
}

static void bt_uuid_enc(CborEncoder *_encoder, const struct bt_uuid *_data)
{
	SERIALIZE(CUSTOM_STRUCT(struct bt_uuid));

	switch (_data->type) {
	case BT_UUID_TYPE_16:
		ser_encode_buffer(_encoder,
			(const struct bt_uuid_16 *)_data, sizeof(struct bt_uuid_16));
		break;
	
	case BT_UUID_TYPE_32:
		ser_encode_buffer(_encoder,
			(const struct bt_uuid_32 *)_data, sizeof(struct bt_uuid_32));
		break;
	
	case BT_UUID_TYPE_128:
		ser_encode_buffer(_encoder,
			(const struct bt_uuid_128 *)_data, sizeof(const struct bt_uuid_128));
		break;
	
	default:
		ser_encoder_invalid(_encoder);
		break;
	}
}

static int bt_rpc_gatt_send_simple_attr(uint8_t special_attr, const struct bt_uuid *uuid, uint16_t data)
{
	SERIALIZE(DEL(uuid));

	struct nrf_rpc_cbor_ctx _ctx;                                             /*######%Aa*/
	int _result;                                                              /*######Qso*/
	size_t _buffer_size_max = 5;                                              /*######@uA*/

	_buffer_size_max += bt_uuid_buf_size(uuid);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                               /*##AvrU03s*/

	bt_uuid_enc(&_ctx.encoder, uuid);

	ser_encode_uint(&_ctx.encoder, special_attr);                             /*####%AzFW*/
	ser_encode_uint(&_ctx.encoder, data);                                     /*#####@4LE*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_GATT_SEND_SIMPLE_ATTR_RPC_CMD,/*####%BGz8*/
		&_ctx, ser_rsp_decode_i32, &_result);                             /*#####@Csk*/

	return _result;                                                           /*##BX7TDLc*/
}

static int send_normal_attr(uint8_t special_attr, const struct bt_gatt_attr *attr)
{
	uint16_t data = attr->perm;

	if (attr->read) {
		data |= BT_RPC_GATT_ATTR_READ_PRESENT_FLAG;
	}

	if (attr->write) {
		data |= BT_RPC_GATT_ATTR_WRITE_PRESENT_FLAG;
	}

	return bt_rpc_gatt_send_simple_attr(special_attr, attr->uuid, data);
}

static int send_service_attr(uint8_t special_attr, const struct bt_gatt_attr *attr)
{
	struct bt_uuid *service_uuid = (struct bt_uuid *)attr->user_data;

	return bt_rpc_gatt_send_simple_attr(special_attr, service_uuid, 0);
}

static int send_chrc_attr(uint8_t special_attr, const struct bt_gatt_attr *attr)
{
	struct bt_gatt_chrc *chrc = (struct bt_gatt_chrc *) attr->user_data;

	__ASSERT(chrc->value_handle == 0, "Only default value of value_handle is implemented!");

	return bt_rpc_gatt_send_simple_attr(special_attr, chrc->uuid, chrc->properties);
}

static int bt_rpc_gatt_send_desc_attr(uint8_t special_attr, uint16_t param, uint8_t *buffer, size_t size)
{
	SERIALIZE(SIZE_PARAM(buffer, size));

	struct nrf_rpc_cbor_ctx _ctx;                                            /*#######%A*/
	size_t _buffer_size;                                                     /*#######YG*/
	int _result;                                                             /*#######tX*/
	size_t _scratchpad_size = 0;                                             /*#######I4*/
	size_t _buffer_size_max = 20;                                            /*########@*/

	_buffer_size = sizeof(uint8_t) * size;                                   /*####%CNdY*/
	_buffer_size_max += _buffer_size;                                        /*#####@FRU*/

	_scratchpad_size += SCRATCHPAD_ALIGN(_buffer_size);                      /*##EJIyO2c*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	ser_encode_uint(&_ctx.encoder, special_attr);                            /*######%A9*/
	ser_encode_uint(&_ctx.encoder, param);                                   /*#######Ar*/
	ser_encode_uint(&_ctx.encoder, size);                                    /*#######yL*/
	ser_encode_buffer(&_ctx.encoder, buffer, _buffer_size);                  /*#######@E*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_GATT_SEND_DESC_ATTR_RPC_CMD, /*####%BK/v*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@Th0*/

	return _result;                                                          /*##BX7TDLc*/
}

static int send_ccc_attr(uint8_t special_attr, const struct bt_gatt_attr *attr)
{
	struct _bt_gatt_ccc *ccc = (struct _bt_gatt_ccc *)attr->user_data;
	uint16_t data = attr->perm;

	if (ccc->cfg_changed) {
		data |= BT_RPC_GATT_CCC_CFG_CHANGE_PRESENT_FLAG;
	}

	if (ccc->cfg_write) {
		data |= BT_RPC_GATT_CCC_CFG_WRITE_PRESENT_FLAG;
	}

	if (ccc->cfg_match) {
		data |= BT_RPC_GATT_CCC_CFG_MATCH_PRESET_FLAG;
	}

	return bt_rpc_gatt_send_desc_attr(special_attr, data, NULL, 0);
}

static int send_cep_attr(uint8_t special_attr, const struct bt_gatt_attr *attr)
{
	struct bt_gatt_cep *cep = (struct bt_gatt_cep *)attr->user_data;
	
	return bt_rpc_gatt_send_desc_attr(special_attr, cep->properties, NULL, 0);
}

static int send_cud_attr(uint8_t special_attr, const struct bt_gatt_attr *attr)
{
	char *cud = (char *)attr->user_data;
	
	return bt_rpc_gatt_send_desc_attr(special_attr, attr->perm, (uint8_t *)cud, strlen(cud) + 1);
}

static int send_cpf_attr(uint8_t special_attr, const struct bt_gatt_attr *attr)
{
	struct bt_gatt_cpf *cpf = (struct bt_gatt_cpf *)attr->user_data;
	
	return bt_rpc_gatt_send_desc_attr(special_attr, 0, (uint8_t *)cpf, sizeof(struct bt_gatt_cpf));
}

static int bt_rpc_gatt_end_service(void)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AX*/
	int _result;                                                             /*######56+*/
	size_t _buffer_size_max = 0;                                             /*######@io*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_GATT_END_SERVICE_RPC_CMD,    /*####%BLFo*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@3Xo*/

	return _result;                                                          /*##BX7TDLc*/
}

static bool attr_type_check(const struct bt_gatt_attr *attr, const struct bt_uuid *uuid,
			    void *read_func, void *write_func)
{
	return (!bt_uuid_cmp(attr->uuid, uuid) &&
		(attr->read == read_func) &&
		(attr->write == write_func));
}

static uint8_t special_attr_get(const struct bt_gatt_attr *attr)
{
	uint8_t special_attr;

	if (attr_type_check(attr, uuid_primary, bt_gatt_attr_read_service, NULL)) {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_SERVICE;
	} else if (attr_type_check(attr, uuid_secondary, bt_gatt_attr_read_service, NULL)) {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_SECONDARY;
	} else if (attr_type_check(attr, uuid_chrc, bt_gatt_attr_read_chrc, NULL)) {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_CHRC;
	} else if (attr_type_check(attr, uuid_ccc, bt_gatt_attr_read_ccc, bt_gatt_attr_write_ccc)) {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_CCC;
	} else if (attr_type_check(attr, uuid_cep, bt_gatt_attr_read_cep, NULL)) {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_CEP;
	} else if (attr_type_check(attr, uuid_cud, bt_gatt_attr_read_cud, NULL)) {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_CUD;
	} else if (attr_type_check(attr, uuid_cpf, bt_gatt_attr_read_cpf, NULL)) {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_CPF;
	} else {
		special_attr = BT_RPC_GATT_ATTR_SPECIAL_USER;
	}

	return special_attr;
}

static int send_service(const struct bt_gatt_service *svc)
{
	int err;
	uint32_t service_index;
	uint8_t special_attr;
	const struct bt_gatt_attr *attr;

	err = bt_rpc_gatt_add_service(svc, &service_index);
	if (err) {
		return err;
	}

	LOG_DBG("Sending service %d", service_index);
	
	err = bt_rpc_gatt_start_service(service_index, svc->attr_count);
	if (err) {
		return err;
	}

	for (size_t i = 0; i < svc->attr_count; i++) {

		attr = &svc->attrs[i];

		special_attr = special_attr_get(attr);

		switch (special_attr) {
		case BT_RPC_GATT_ATTR_SPECIAL_USER:
			err = send_normal_attr(0, attr);
			break;

		case BT_RPC_GATT_ATTR_SPECIAL_SERVICE:
		case BT_RPC_GATT_ATTR_SPECIAL_SECONDARY:
			err = send_service_attr(special_attr, attr);
			break;

		case BT_RPC_GATT_ATTR_SPECIAL_CHRC:
			err = send_chrc_attr(special_attr, attr);
			break;
			
		case BT_RPC_GATT_ATTR_SPECIAL_CCC:
			err = send_ccc_attr(special_attr, attr);
			break;

		case BT_RPC_GATT_ATTR_SPECIAL_CEP:
			err = send_cep_attr(special_attr, attr);
			break;

		case BT_RPC_GATT_ATTR_SPECIAL_CUD:
			err = send_cud_attr(special_attr, attr);
			break;

		case BT_RPC_GATT_ATTR_SPECIAL_CPF:
			err = send_cpf_attr(special_attr, attr);
			break;

		default:
			err = -EINVAL;
			break;
		}
	}

	if (err) {
		return err;
	}
	
	return bt_rpc_gatt_end_service();
}

int bt_rpc_gatt_init(void)
{
	int err;

	Z_STRUCT_SECTION_FOREACH(bt_gatt_service_static, svc) {
		err = send_service((const struct bt_gatt_service *)svc);
		if (err) {
			LOG_ERR("Sending static service error: %d", err);
			return err;
		}
	}

	return 0;
}

#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
int bt_gatt_service_register(struct bt_gatt_service *svc)
{
	return send_service(svc);
}

int bt_gatt_service_unregister(struct bt_gatt_service *svc)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _buffer_size_max = 3;
	uint16_t svc_index;
	int err;

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);

	err = bt_rpc_gatt_service_to_index(svc, &svc_index);
	if (err) {
		return err;
	}

	ser_encode_uint(&_ctx.encoder, svc_index);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_RPC_GATT_SERVICE_UNREGISTER_RPC_CMD,
				&_ctx, ser_rsp_decode_i32, &_result);
	
	if (_result) {
		return _result;
	}
	
	return bt_rpc_gatt_remove_service(svc);
}
#endif /* defined(CONFIG_BT_GATT_DYNAMIC_DB) */

size_t bt_gatt_notify_params_buf_size(const struct bt_gatt_notify_params *_data) /*####%BrKt*/
{                                                                                /*#####@yBI*/

	size_t _buffer_size_max = 23;                                            /*##ATeLD5I*/

	_buffer_size_max += sizeof(uint8_t) * _data->len;                        /*##CCccUEE*/

	_buffer_size_max += _data->len;

	return _buffer_size_max;                                                 /*##BWmN6G8*/

}                                                                                /*##B9ELNqo*/

size_t bt_gatt_notify_params_sp_size(const struct bt_gatt_notify_params *_data)  /*####%BkZv*/
{                                                                                /*#####@tI8*/

	size_t _scratchpad_size = 0;                                             /*##ATz5YrA*/

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(uint8_t) * _data->len);      /*##EEnQBh8*/

	_scratchpad_size += _data->len;

	return _scratchpad_size;                                                 /*##BRWAmyU*/

}                                                                                /*##B9ELNqo*/

void bt_gatt_notify_params_enc(CborEncoder *_encoder, const struct bt_gatt_notify_params *_data)/*####%BiD8*/
{                                                                                               /*#####@Y84*/

	SERIALIZE(STRUCT(struct bt_gatt_notify_params));
	SERIALIZE(SIZE_PARAM(data, len));
	SERIALIZE(DEL(uuid));

	bt_rpc_encode_gatt_attr(_encoder, _data->attr);                                         /*#######%A*/
	ser_encode_uint(_encoder, _data->len);                                                  /*#######xo*/
	ser_encode_buffer(_encoder, _data->data, sizeof(uint8_t) * _data->len);                 /*#######Un*/
	ser_encode_callback(_encoder, _data->func);                                             /*#######Mo*/
	ser_encode_uint(_encoder, (uintptr_t)_data->user_data);                                 /*########@*/

	if (_data->uuid) {
		bt_uuid_enc(_encoder, _data->uuid);
	} else {
		ser_encode_null(_encoder);
	}

}                                                                                               /*##B9ELNqo*/

int bt_gatt_notify_cb(struct bt_conn *conn,
		      struct bt_gatt_notify_params *params)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Af*/
	int _result;                                                             /*#######LL*/
	size_t _scratchpad_size = 0;                                             /*#######kq*/
	size_t _buffer_size_max = 8;                                             /*#######@k*/

	_buffer_size_max += bt_gatt_notify_params_buf_size(params);              /*##CAHEO9k*/

	_scratchpad_size += bt_gatt_notify_params_sp_size(params);               /*##EAf8irI*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*####%AoDN*/
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);                        /*#####@BNc*/

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);                              /*####%A68W*/
	bt_gatt_notify_params_enc(&_ctx.encoder, params);                        /*#####@sVU*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_GATT_NOTIFY_CB_RPC_CMD,          /*####%BEKJ*/
		&_ctx, ser_rsp_decode_i32, &_result);                            /*#####@IiE*/

	return _result;                                                          /*##BX7TDLc*/
}

#if defined(CONFIG_BT_GATT_NOTIFY_MULTIPLE)
int bt_gatt_notify_multiple(struct bt_conn *conn, uint16_t num_params,
			    struct bt_gatt_notify_params *params)
{
	int i, ret;

	__ASSERT(params, "invalid parameters\n");
	__ASSERT(num_params, "invalid parameters\n");
	__ASSERT(params->attr, "invalid parameters\n");

	for (i = 0; i < num_params; i++) {
		ret = bt_gatt_notify_cb(conn, &params[i]);
		if (ret < 0) {
			return ret;
		}
	}

	return 0;
}
#endif /* CONFIG_BT_GATT_NOTIFY_MULTIPLE */

size_t bt_gatt_indicate_params_sp_size(const struct bt_gatt_indicate_params *_data)/*####%Bgrd*/
{                                                                                  /*#####@GsE*/

	size_t _scratchpad_size = 0;                                               /*##ATz5YrA*/

	_scratchpad_size += SCRATCHPAD_ALIGN(sizeof(uint8_t) * _data->len);        /*##EEnQBh8*/

	_scratchpad_size += _data->uuid ? bt_uuid_buf_size(_data->uuid) : 0;

	return _scratchpad_size;                                                   /*##BRWAmyU*/

}                                                                                  /*##B9ELNqo*/

size_t bt_gatt_indicate_params_buf_size(const struct bt_gatt_indicate_params *_data)/*####%BqJe*/
{                                                                                   /*#####@QPU*/

	size_t _buffer_size_max = 15;                                               /*##AetZpwM*/

	_buffer_size_max += sizeof(uint8_t) * _data->len;                           /*##CCccUEE*/

	_buffer_size_max += _data->uuid ? bt_uuid_buf_size(_data->uuid) : 1;

	return _buffer_size_max;                                                    /*##BWmN6G8*/

}                                                                                   /*##B9ELNqo*/

void bt_gatt_indicate_params_enc(CborEncoder *_encoder, const struct bt_gatt_indicate_params *_data)/*####%BqWS*/
{                                                                                                   /*#####@bEw*/

	SERIALIZE(STRUCT(struct bt_gatt_indicate_params));
	SERIALIZE(DEL(uuid));
	SERIALIZE(SIZE_PARAM(data, len));
	SERIALIZE(DEL(func));
	SERIALIZE(DEL(destroy));

	bt_rpc_encode_gatt_attr(_encoder, _data->attr);                                             /*######%A8*/
	ser_encode_uint(_encoder, _data->len);                                                      /*#######IW*/
	ser_encode_buffer(_encoder, _data->data, sizeof(uint8_t) * _data->len);                     /*#######ep*/
	ser_encode_uint(_encoder, _data->_ref);                                                     /*#######@w*/

	if (_data->uuid) {
		bt_uuid_enc(_encoder, _data->uuid);
	} else {
		ser_encode_null(_encoder);
	}

}                                                                                                   /*##B9ELNqo*/

int bt_gatt_indicate(struct bt_conn *conn, struct bt_gatt_indicate_params *params)
{
	struct nrf_rpc_cbor_ctx _ctx;
	int _result;
	size_t _scratchpad_size = 0;
	size_t _buffer_size_max = 13;
	uintptr_t params_addr = (uintptr_t)params;

	_buffer_size_max += bt_gatt_indicate_params_buf_size(params);
	_scratchpad_size += bt_gatt_indicate_params_sp_size(params);

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);
	ser_encode_uint(&_ctx.encoder, _scratchpad_size);

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);
	bt_gatt_indicate_params_enc(&_ctx.encoder, params);
	ser_encode_uint(&_ctx.encoder, params_addr);

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_GATT_INDICATE_RPC_CMD,
		&_ctx, ser_rsp_decode_i32, &_result);

	return _result;
}

static void bt_gatt_indicate_func_t_callback_rpc_handler(CborValue *_value, void *_handler_data)
{
	struct bt_conn * conn;
	uint8_t err;
	struct bt_gatt_indicate_params *params;

	conn = bt_rpc_decode_bt_conn(_value);
	err = ser_decode_uint(_value);
	params = (struct bt_gatt_indicate_params *) ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (params->func) {
		params->func(conn, params, err);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_GATT_INDICATE_FUNC_T_CALLBACK_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_gatt_indicate_func_t_callback,
			 BT_GATT_INDICATE_FUNC_T_CALLBACK_RPC_CMD,
			 bt_gatt_indicate_func_t_callback_rpc_handler, NULL);

static void bt_gatt_indicate_params_destroy_t_callback_rpc_handler(CborValue *_value,
								   void *_handler_data)
{
	struct bt_gatt_indicate_params *params;

	params = (struct bt_gatt_indicate_params *)ser_decode_uint(_value);

	if (!ser_decoding_done_and_check(_value)) {
		goto decoding_error;
	}

	if (params->destroy) {
		params->destroy(params);
	}

	ser_rsp_send_void();

	return;
decoding_error:
	report_decoding_error(BT_GATT_INDICATE_PARAMS_DESTROY_T_CALLBACK_RPC_CMD, _handler_data);
}

NRF_RPC_CBOR_CMD_DECODER(bt_rpc_grp, bt_gatt_indicate_params_destroy_t_callback,
			 BT_GATT_INDICATE_PARAMS_DESTROY_T_CALLBACK_RPC_CMD,
			 bt_gatt_indicate_params_destroy_t_callback_rpc_handler, NULL);


bool bt_gatt_is_subscribed(struct bt_conn *conn,
			   const struct bt_gatt_attr *attr, uint16_t ccc_value)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AT*/
	bool _result;                                                            /*######Hq9*/
	size_t _buffer_size_max = 11;                                            /*######@VY*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);                              /*######%A5*/
	bt_rpc_encode_gatt_attr(&_ctx.encoder, attr);                            /*######Qie*/
	ser_encode_uint(&_ctx.encoder, ccc_value);                               /*######@nc*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_GATT_IS_SUBSCRIBED_RPC_CMD,      /*####%BK+r*/
		&_ctx, ser_rsp_decode_bool, &_result);                           /*#####@Iuw*/

	return _result;                                                          /*##BX7TDLc*/
}

uint16_t bt_gatt_get_mtu(struct bt_conn *conn)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%AR*/
	uint16_t _result;                                                        /*######rIk*/
	size_t _buffer_size_max = 3;                                             /*######@H0*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	bt_rpc_encode_bt_conn(&_ctx.encoder, conn);                              /*##A0WTTl0*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_GATT_GET_MTU_RPC_CMD,            /*####%BHoo*/
		&_ctx, ser_rsp_decode_u16, &_result);                            /*#####@ioM*/

	return _result;                                                          /*##BX7TDLc*/
}

static uint8_t find_next(const struct bt_gatt_attr *attr, uint16_t handle,
			 void *user_data)
{
	struct bt_gatt_attr **next = user_data;

	*next = (struct bt_gatt_attr *)attr;

	return BT_GATT_ITER_STOP;
}
struct bt_gatt_attr *bt_gatt_attr_next(const struct bt_gatt_attr *attr)
{
	struct bt_gatt_attr *next = NULL;
	uint16_t handle = bt_gatt_attr_get_handle(attr);

	bt_gatt_foreach_attr(handle + 1, handle + 1, find_next, &next);

	return next;
}

void bt_gatt_foreach_attr_type(uint16_t start_handle, uint16_t end_handle,
			       const struct bt_uuid *uuid,
			       const void *attr_data, uint16_t num_matches,
			       bt_gatt_attr_func_t func,
			       void *user_data)
{
	bt_rpc_gatt_foreach_attr_type(start_handle, end_handle, uuid, attr_data,
				      num_matches, func, user_data);
}

uint16_t bt_gatt_attr_get_handle(const struct bt_gatt_attr *attr)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ae*/
	uint16_t _result;                                                        /*######tRx*/
	size_t _buffer_size_max = 5;                                             /*######@CE*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	bt_rpc_encode_gatt_attr(&_ctx.encoder, attr);                            /*##A8Ybph8*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_GATT_ATTR_GET_HANDLE_RPC_CMD,    /*####%BAbs*/
		&_ctx, ser_rsp_decode_u16, &_result);                            /*#####@gTA*/

	return _result;                                                          /*##BX7TDLc*/
}

uint16_t bt_gatt_attr_value_handle(const struct bt_gatt_attr *attr)
{
	SERIALIZE();

	struct nrf_rpc_cbor_ctx _ctx;                                            /*######%Ae*/
	uint16_t _result;                                                        /*######tRx*/
	size_t _buffer_size_max = 5;                                             /*######@CE*/

	NRF_RPC_CBOR_ALLOC(_ctx, _buffer_size_max);                              /*##AvrU03s*/

	bt_rpc_encode_gatt_attr(&_ctx.encoder, attr);                            /*##A8Ybph8*/

	nrf_rpc_cbor_cmd_no_err(&bt_rpc_grp, BT_GATT_ATTR_VALUE_HANDLE_RPC_CMD,  /*####%BBDc*/
		&_ctx, ser_rsp_decode_u16, &_result);                            /*#####@kEo*/

	return _result;                                                          /*##BX7TDLc*/
}
