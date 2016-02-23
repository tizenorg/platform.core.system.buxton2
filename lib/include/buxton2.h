/*
 * Buxton
 *
 * Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __BUXTON_H__
#define __BUXTON_H__

/**
 * @file buxton2.h Buxton2 public header
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @struct buxton_client
 *
 * The buxton_client struct is an opaque data structure to communicate with
 * the Buxton daemon
 */
struct buxton_client;

/**
 * Connection status enum
 */
enum buxton_status {
	BUXTON_STATUS_UNINITIALIZED = 0, /**< uninitialized */
	BUXTON_STATUS_CONNECTED,         /**< connected */
	BUXTON_STATUS_DISCONNECTED,      /**< disconnected */
	BUXTON_STATUS_MAX /* sentinel value */
};

/**
 * Status callback function. this function is invoked when the connection
 * status is changed
 *
 * @param[in] status the status of the connection
 * @param[in] user_data user data passed to the callback function
 *
 * @see buxton_open
 */
typedef void (*buxton_status_callback)(enum buxton_status status,
		void *user_data);

/**
 * Open a connection to the Buxton daemon
 *
 * @param[out] client A pointer #buxton_client is allocated to
 *                    (this value should be released by #buxton_close)
 * @param[in] callback status callback function. If this is NULL, no callback
 *                     function is invoked
 * @param[in] user_data User data to be used with status callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 *
 * @see buxton_close
 */
int buxton_open(struct buxton_client **client,
		buxton_status_callback callback, void *user_data);

/**
 * Close the connection to the Buxton daemon and release #buxton_client struct
 *
 * @param[in] client #buxton_client structure
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 *
 * @see buxton_open
 */
int buxton_close(struct buxton_client *client);


/**
 * data type enum
 */
enum buxton_key_type {
	BUXTON_TYPE_UNKNOWN = 0, /**< Unknown type */
	BUXTON_TYPE_STRING,      /**< String type */
	BUXTON_TYPE_INT32,       /**< 32bit integer type */
	BUXTON_TYPE_UINT32,      /**< 32bit unsigned integer type */
	BUXTON_TYPE_INT64,       /**< 64bit integer type */
	BUXTON_TYPE_UINT64,      /**< 64bit unsigned integer type */
	BUXTON_TYPE_DOUBLE,      /**< double-precision float type */
	BUXTON_TYPE_BOOLEAN,     /**< boolean type */
	BUXTON_TYPE_MAX /* sentinel value */
};

/**
 * privilege is treated as string
 */
#define BUXTON_TYPE_PRIVILEGE BUXTON_TYPE_STRING

/**
 * @struct buxton_value
 *
 * The buxton_value struct is an opaque data structure to represent
 * the value of a key
 */
struct buxton_value;

/**
 * Create string type #buxton_value
 *
 * @param[in] s string value
 * @return #buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_create_string(const char *s);

/**
 * Create 32bit integer type #buxton_value
 *
 * @param[in] i 32bit integer value
 * @return buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_create_int32(int32_t i);

/**
 * Create 32bit unsigned integer type #buxton_value
 *
 * @param[in] u 32bit unsigned integer value
 * @return buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_create_uint32(uint32_t u);

/**
 * Create 64bit integer type #buxton_value
 *
 * @param[in] i64 64bit integer value
 * @return buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_create_int64(int64_t i64);

/**
 * Create 64bit unisigned integer type #buxton_value
 *
 * @param[in] u64 64bit unsigned integer value
 * @return buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_create_uint64(uint64_t u64);

/**
 * Create double-precision float type #buxton_value
 *
 * @param[in] d double-precision float value
 * @return buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_create_double(double d);

/**
 * Create boolean type #buxton_value
 *
 * @param[in] b boolean value
 * @return buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_create_boolean(int32_t b);

/**
 * Get the type of the #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] type the type of the #buxton_value
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_type(const struct buxton_value *val,
		enum buxton_key_type *type);

/**
 * Get string value from #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] s string value. This value is valid until val is freed
 *               by #buxton_value_free. We don't need to free this
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_string(const struct buxton_value *val, const char **s);

/**
 * Get 32bit integer value from #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] i 32bit integer value
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_int32(const struct buxton_value *val, int32_t *i);

/**
 * Get 32bit unsigned integer value from #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] u 32bit unsigned integer value
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_uint32(const struct buxton_value *val, uint32_t *u);

/**
 * Get 64bit integer value from #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] i64 64bit integer value
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_int64(const struct buxton_value *val, int64_t *i64);

/**
 * Get 64bit unsigned integer value from #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] u64 64bit unsigned integer value
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_uint64(const struct buxton_value *val, uint64_t *u64);

/**
 * Get double-precision float value from #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] d double-precision float value
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_double(const struct buxton_value *val, double *d);

/**
 * Get boolean value from #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @param[out] b boolean value
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_value_get_boolean(const struct buxton_value *val, int32_t *b);

/**
 * Duplicate the #buxton_value
 *
 * @param[in] val #buxton_value struct
 * @return a new #buxton_value on success, NULL on error(errno is set)
 *         return value should be released by #buxton_value_free
 *
 * @see buxton_value_free
 */
struct buxton_value *buxton_value_duplicate(const struct buxton_value *val);

/**
 * Free the #buxton_value
 *
 * @param[in] val #buxton_value struct
 */
void buxton_value_free(struct buxton_value *val);


/**
 * @struct buxton_layer
 *
 * The buxton_layer struct is an opaque data structure to represent the layer
 */
struct buxton_layer;

/**
 * Create the #buxton_layer struct
 *
 * @param[in] layer_name the name of a layer
 * @return #buxton_layer on success, NULL on error(errno is set)
 */
struct buxton_layer *buxton_create_layer(const char *layer_name);

/**
 * Get the name of the layer
 *
 * @param[in] layer #buxton_layer struct
 * @return layer name on success, NULL on error.
 *         return value is valid until layer is freed by #buxton_free_layer.
 *         We don't need to free this value
 */
const char *buxton_layer_get_name(const struct buxton_layer *layer);

/**
 * Free the #buxton_layer struct
 *
 * @param[in] layer #buxton_layer struct
 */
void buxton_free_layer(struct buxton_layer *layer);


/**
 * Response callback function
 *
 * @param[in] status the result of the request
 *                   0 on success, an negative value(errno) on error
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] val #buxton_value struct
 *                val is NULL when this function is invoked by
 *                #buxton_set_value,
 *                #buxton_register_notification,
 *                #buxton_unregister_notification,
 *                #buxton_create_value,
 *                #buxton_unset_value,
 *                #buxton_set_privilege.
 *                val is a privilege string when this function is invoked by
 *                #buxton_get_privilege.
 *                otherwise, val is the value of the key
 * @param[in] user_data user data passed to the callback function
 *
 * @remark layer, key and val are valid until this callback returns.
 */
typedef void (*buxton_response_callback)(int status,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val, void *user_data);

/**
 * Set a value of the key
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] val a value to be set
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_set_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data);

/**
 * Set a value of the key synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] val a value to be set
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_set_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val);

/**
 * Get a value of the key
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_get_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data);

/**
 * Get a value of the key synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[out] val #buxton_value of the key.
 *                 This value should be freed by #buxton_value_free
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_get_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		struct buxton_value **val);


/**
 * List callback function
 *
 * @param[in] status the result of the request
 *                   0 on success, an negative value(errno) on error
 * @param[in] layer #buxton_layer struct
 * @param[in] names a null-terminated array of key names
 * @param[in] len the length of the array
 * @param[in] user_data user data passed to the callback function
 *
 * @remark layer and names are valid until this callback returns.
 * @see buxton_list_keys
 */
typedef void (*buxton_list_callback)(int status,
		const struct buxton_layer *layer,
		char * const *names, unsigned int len,
		void *user_data);

/**
 * List all keys within the layer
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] callback list callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_list_keys(struct buxton_client *client,
		const struct buxton_layer *layer,
		buxton_list_callback callback, void *user_data);

/**
 * List all keys within the layer synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[out] names a null-terminated array of key names.
 *                   This should be freed by #buxton_free_keys
 * @param[out] len the length of the array. An input value can be NULL
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_list_keys_sync(struct buxton_client *client,
		const struct buxton_layer *layer,
		char ***names, unsigned int *len);

/**
 * Free the array of key names which comes from #buxton_list_keys_sync
 *
 * @param[in] names the array of key names
 */
static inline void buxton_free_keys(char **names)
{
	char **k;

	if (!names)
		return;

	k = names;
	while (*k) {
		free(*k);
		k++;
	}

	free(names);
}

/**
 * Key change notify callback
 *
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] val the changed value of the key
 * @param[in] user_data user data passed to the callback function
 *
 * @remark layer, key and val are valid until this callback returns.
 */
typedef void (*buxton_notify_callback)(const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data);

/**
 * Register a key change notify callback
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] notify key change notify callback function
 * @param[in] notify_data data to be used with notify callback function
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with response callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 *
 * @remark multiple notify callback can be registered. But, the same function
 *         should not be registered for the same key.
 */
int buxton_register_notification(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify, void *notify_data,
		buxton_response_callback callback, void *user_data);

/**
 * Register a key change notify callback synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] notify key change notify callback function
 * @param[in] notify_data data to be used with notify callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 *
 * @remark multiple notify callback can be registered. But, the same function
 *         should not be registered for the same key.
 */
int buxton_register_notification_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify, void *notify_data);

/**
 * Unregister the key change notify callback
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] notify key change notify callback function
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with response callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_unregister_notification(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify,
		buxton_response_callback callback, void *user_data);


/**
 * Unregister the key change notify callback synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] notify key change notify callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_unregister_notification_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify);


/* Admin APIs  ------------------- */

/**
 * Set a user ID to #buxton_layer struct
 *
 * @param[in] layer #buxton_layer struct
 * @param[in] uid a user ID to be set
 *
 * @remark Only root can access other user's data.
 */
void buxton_layer_set_uid(struct buxton_layer *layer, uid_t uid);

/**
 * layer type enum
 */
enum buxton_layer_type {
	BUXTON_LAYER_NORMAL = 0, /**< Normal layer type */
	BUXTON_LAYER_BASE,       /**< Base layer type */
	BUXTON_LAYER_MAX /* sentinel value */
};

/**
 * Set a type of the layer
 *
 * @param[in] layer #buxton_layer struct
 * @param[in] type a type to be set
 *
 * @remark Only root can access the base type layer.
 */
void buxton_layer_set_type(struct buxton_layer *layer,
		enum buxton_layer_type type);

/**
 * Create a new key
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] read_privilege a privilege string for read access
 * @param[in] write_privilege a privilege string for write access
 * @param[in] val an initial value of the key
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 *
 * @remark Only root can create a new key. A Null value is not permitted
 *         in privilege string. But, an empty string is permitted.
 */
int buxton_create_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const char *read_privilege, const char *write_privilege,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data);

/**
 * Create a new key synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] read_privilege a privilege string for read access
 * @param[in] write_privilege a privilege string for write access
 * @param[in] val an initial value of the key
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 *
 * @remark Only root can create a new key. A Null value is not permitted
 *         in privilege string. But, an empty string is permitted.
 */
int buxton_create_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const char *read_privilege, const char *write_privilege,
		const struct buxton_value *val);

/**
 * Unset the key
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_unset_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data);

/**
 * Unset the key synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_unset_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key);

/**
 * privilege type enum
 */
enum buxton_priv_type {
	BUXTON_PRIV_UNKNOWN = 0, /**< Unknown privilege type */
	BUXTON_PRIV_READ,        /**< Read privilege type */
	BUXTON_PRIV_WRITE,       /**< Write privilege type */
	BUXTON_PRIV_MAX /* sentinel value */
};

/**
 * Set a read/write privilege
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] type a type of the privilege to be set
 * @param[in] privilege a privilege string to be set
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_set_privilege(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		const char *privilege,
		buxton_response_callback callback, void *user_data);

/**
 * Set a read/write privilege synchronously
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] type a type of the privilege to be set
 * @param[in] privilege a privilege string
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_set_privilege_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		const char *privilege);

/**
 * Get the read/write privilege of the key
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] type a type of the privilege
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_get_privilege(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		buxton_response_callback callback, void *user_data);

/**
 * Get the read/write privilege of the key
 *
 * @param[in] client #buxton_client struct
 * @param[in] layer #buxton_layer struct
 * @param[in] key the name of the key
 * @param[in] type a type of the privilege
 * @param[out] privilege the privilege string of the key.
 *                       This value should be freed by free()
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_get_privilege_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		char **privilege);

/**
 * Enable buxton cynara check
 *
 * @param[in] client #buxton_client struct
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_enable_security(struct buxton_client *client,
		buxton_response_callback callback, void *user_data);

/**
 * Enable buxton cynara check synchronously
 *
 * @param[in] client #buxton_client struct
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_enable_security_sync(struct buxton_client *client);

/**
 * Disable buxton cynara check
 *
 * @param[in] client #buxton_client struct
 * @param[in] callback response callback function
 * @param[in] user_data User data to be used with callback function
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_disable_security(struct buxton_client *client,
		buxton_response_callback callback, void *user_data);

/**
 * Disable buxton cynara check synchronously
 *
 * @param[in] client #buxton_client struct
 * @return 0 on success, -1 on error(when an error occurred, errno is set)
 */
int buxton_disable_security_sync(struct buxton_client *client);

#ifdef __cplusplus
}
#endif
#endif /* __BUXTON_H__ */
