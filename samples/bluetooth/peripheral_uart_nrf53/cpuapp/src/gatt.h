/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef GATT_H_
#define GATT_H_

#include <stddef.h>
#include <sys/types.h>
#include <sys/util.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/att.h>

/** @def BT_GATT_SERVICE
 *  @brief Service Structure Declaration Macro.
 *
 *  Helper macro to declare a service structure.
 *
 *  @param _attrs Service attributes.
 */
#define BT_GATT_SERVICE(_attrs)						\
{									\
	.attrs = _attrs,						\
	.attr_count = ARRAY_SIZE(_attrs),				\
}

/** @brief GATT Service structure */
struct bt_gatt_service {
	/** Service Attributes */
	struct bt_gatt_attr	*attrs;
	/** Service Attribute count */
	size_t			attr_count;
	sys_snode_t		node;
};

/* GATT attribute permission bit field values */
enum {
	/** No operations supported, e.g. for notify-only */
	BT_GATT_PERM_NONE = 0,

	/** Attribute read permission. */
	BT_GATT_PERM_READ = BIT(0),

	/** Attribute write permission. */
	BT_GATT_PERM_WRITE = BIT(1),

	/** Attribute read permission with encryption.
	 *
	 *  If set, requires encryption for read access.
	 */
	BT_GATT_PERM_READ_ENCRYPT = BIT(2),

	/** Attribute write permission with encryption.
	 *
	 *  If set, requires encryption for write access.
	 */
	BT_GATT_PERM_WRITE_ENCRYPT = BIT(3),

	/** Attribute read permission with authentication.
	 *
	 *  If set, requires encryption using authenticated link-key for read
	 *  access.
	 */
	BT_GATT_PERM_READ_AUTHEN = BIT(4),

	/** Attribute write permission with authentication.
	 *
	 *  If set, requires encryption using authenticated link-key for write
	 *  access.
	 */
	BT_GATT_PERM_WRITE_AUTHEN = BIT(5),

	/** Attribute prepare write permission.
	 *
	 *  If set, allows prepare writes with use of BT_GATT_WRITE_FLAG_PREPARE
	 *  passed to write callback.
	 */
	BT_GATT_PERM_PREPARE_WRITE = BIT(6),
};

/** @brief GATT Attribute structure. */
struct bt_gatt_attr {
	/** Attribute UUID */
	const struct bt_uuid	*uuid;

	/** Attribute read callback
	 *
	 *  The callback can also be used locally to read the contents of the
	 *  attribute in which case no connection will be set.
	 *
	 *  @param conn   The connection that is requesting to read
	 *  @param attr   The attribute that's being read
	 *  @param buf    Buffer to place the read result in
	 *  @param len    Length of data to read
	 *  @param offset Offset to start reading from
	 *
	 *  @return Number fo bytes read, or in case of an error
	 *          BT_GATT_ERR() with a specific ATT error code.
	 */
	ssize_t			(*read)(struct bt_conn *conn,
					const struct bt_gatt_attr *attr,
					void *buf, u16_t len,
					u16_t offset);

	/** Attribute write callback
	 *
	 *  The callback can also be used locally to read the contents of the
	 *  attribute in which case no connection will be set.
	 *
	 *  @param conn   The connection that is requesting to write
	 *  @param attr   The attribute that's being written
	 *  @param buf    Buffer with the data to write
	 *  @param len    Number of bytes in the buffer
	 *  @param offset Offset to start writing from
	 *  @param flags  Flags (BT_GATT_WRITE_*)
	 *
	 *  @return Number of bytes written, or in case of an error
	 *          BT_GATT_ERR() with a specific ATT error code.
	 */
	ssize_t			(*write)(struct bt_conn *conn,
					 const struct bt_gatt_attr *attr,
					 const void *buf, u16_t len,
					 u16_t offset, u8_t flags);

	/** Attribute user data */
	void			*user_data;
	/** Attribute handle */
	u16_t			handle;
	/** Attribute permissions */
	u8_t			perm;
};

/** @def BT_GATT_ATTRIBUTE
 *  @brief Attribute Declaration Macro.
 *
 *  Helper macro to declare an attribute.
 *
 *  @param _uuid Attribute uuid.
 *  @param _perm Attribute access permissions.
 *  @param _read Attribute read callback.
 *  @param _write Attribute write callback.
 *  @param _value Attribute value.
 */
#define BT_GATT_ATTRIBUTE(_uuid, _perm, _read, _write, _value)		\
{									\
	.uuid = _uuid,							\
	.perm = _perm,							\
	.read = _read,							\
	.write = _write,						\
	.user_data = _value,						\
}

/** @def BT_GATT_CHRC_BROADCAST
 *  @brief Characteristic broadcast property.
 *
 *  If set, permits broadcasts of the Characteristic Value using Server
 *  Characteristic Configuration Descriptor.
 */
#define BT_GATT_CHRC_BROADCAST			0x01
/** @def BT_GATT_CHRC_READ
 *  @brief Characteristic read property.
 *
 *  If set, permits reads of the Characteristic Value.
 */
#define BT_GATT_CHRC_READ			0x02
/** @def BT_GATT_CHRC_WRITE_WITHOUT_RESP
 *  @brief Characteristic write without response property.
 *
 *  If set, permits write of the Characteristic Value without response.
 */
#define BT_GATT_CHRC_WRITE_WITHOUT_RESP		0x04
/** @def BT_GATT_CHRC_WRITE
 *  @brief Characteristic write with response property.
 *
 *  If set, permits write of the Characteristic Value with response.
 */
#define BT_GATT_CHRC_WRITE			0x08
/** @def BT_GATT_CHRC_NOTIFY
 *  @brief Characteristic notify property.
 *
 *  If set, permits notifications of a Characteristic Value without
 *  acknowledgment.
 */
#define BT_GATT_CHRC_NOTIFY			0x10
/** @def BT_GATT_CHRC_INDICATE
 *  @brief Characteristic indicate property.
 *
 * If set, permits indications of a Characteristic Value with acknowledgment.
 */
#define BT_GATT_CHRC_INDICATE			0x20
/** @def BT_GATT_CHRC_AUTH
 *  @brief Characteristic Authenticated Signed Writes property.
 *
 *  If set, permits signed writes to the Characteristic Value.
 */
#define BT_GATT_CHRC_AUTH			0x40
/** @def BT_GATT_CHRC_EXT_PROP
 *  @brief Characteristic Extended Properties property.
 *
 * If set, additional characteristic properties are defined in the
 * Characteristic Extended Properties Descriptor.
 */
#define BT_GATT_CHRC_EXT_PROP			0x80

/** @brief Characteristic Attribute Value. */
struct bt_gatt_chrc {
	/** Characteristic UUID. */
	const struct bt_uuid	*uuid;
	/** Characteristic Value handle. */
	u16_t			value_handle;
	/** Characteristic properties. */
	u8_t			properties;
};

/** @brief GATT CCC configuration entry.
 *  @param id   Local identity, BT_ID_DEFAULT in most cases.
 *  @param peer Remote peer address
 *  @param value Configuration value.
 *  @param data Configuration pointer data.
 */
struct bt_gatt_ccc_cfg {
	u8_t                    id;
	bt_addr_le_t		peer;
	u16_t			value;
};

/* Internal representation of CCC value */
struct _bt_gatt_ccc {
	/** Configuration for each connection */
	struct bt_gatt_ccc_cfg cfg[10];

	/** Highest value of all connected peer's subscriptions */
	u16_t value;

	/** CCC attribute changed callback
	 *
	 *  @param attr   The attribute that's changed value
	 *  @param value  New value
	 */
	void (*cfg_changed)(const struct bt_gatt_attr *attr, u16_t value);

	/** CCC attribute write validation callback
	 *
	 *  @param conn   The connection that is requesting to write
	 *  @param attr   The attribute that's being written
	 *  @param value  CCC value to write
	 *
	 *  @return Number of bytes to write, or in case of an error
	 *          BT_GATT_ERR() with a specific error code.
	 */
	ssize_t (*cfg_write)(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr, u16_t value);

	/** CCC attribute match handler
	 * Indicate if it is OK to send a notification or indication
	 * to the subscriber.
	 *
	 *  @param conn   The connection that is being checked
	 *  @param attr   The attribute that's being checked
	 *
	 *  @return true  if application has approved notification/indication,
	 *          false if application does not approve.
	 */
	bool (*cfg_match)(struct bt_conn *conn,
			  const struct bt_gatt_attr *attr);
};


#define BT_GATT_SERVICE_DEFINE(_name, ...)                          \
	static struct bt_gatt_attr attr_##_name[] = { __VA_ARGS__ }; \
	static struct bt_gatt_service _name = BT_GATT_SERVICE(attr_##_name)

#define BT_GATT_PRIMARY_SERVICE(_service)				\
	BT_GATT_ATTRIBUTE(BT_UUID_GATT_PRIMARY, BT_GATT_PERM_READ,	\
			 NULL, NULL, _service)

#endif /* GATT_H_ */

#define BT_GATT_CHARACTERISTIC(_uuid, _props, _perm, _read, _write, _value) \
	BT_GATT_ATTRIBUTE(BT_UUID_GATT_CHRC, BT_GATT_PERM_READ,		\
			  NULL, NULL,			\
			  ((struct bt_gatt_chrc[]) { { .uuid = _uuid,	\
						       .value_handle = 0U, \
						       .properties = _props, } })), \
	BT_GATT_ATTRIBUTE(_uuid, _perm, _read, _write, _value)

/** @def BT_GATT_CCC_INITIALIZER
 *  @brief Initialize Client Characteristic Configuration Declaration Macro.
 *
 *  Helper macro to initialize a Managed CCC attribute value.
 *
 *  @param _changed Configuration changed callback.
 *  @param _write Configuration write callback.
 *  @param _match Configuration match callback.
 */
#define BT_GATT_CCC_INITIALIZER(_changed, _write, _match) \
	{                                            \
		.cfg = {},                           \
		.cfg_changed = _changed,             \
		.cfg_write = _write,                 \
		.cfg_match = _match,                 \
	}

/** @def BT_GATT_CCC_MANAGED
 *  @brief Managed Client Characteristic Configuration Declaration Macro.
 *
 *  Helper macro to declare a Managed CCC attribute.
 *
 *  @param _ccc CCC attribute user data, shall point to a _bt_gatt_ccc.
 *  @param _perm CCC access permissions.
 */
#define BT_GATT_CCC_MANAGED(_ccc, _perm)				\
	BT_GATT_ATTRIBUTE(BT_UUID_GATT_CCC, _perm,			\
			NULL, NULL,  \
			_ccc)

#define BT_GATT_CCC(_changed, _perm)				\
	BT_GATT_CCC_MANAGED(((struct _bt_gatt_ccc[])			\
		{BT_GATT_CCC_INITIALIZER(_changed, NULL, NULL)}), _perm)
