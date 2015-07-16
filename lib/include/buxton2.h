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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

/*
 *
 */
struct buxton_client;

enum buxton_status {
	BUXTON_STATUS_UNINITIALIZED = 0,
	BUXTON_STATUS_CONNECTED,
	BUXTON_STATUS_DISCONNECTED,
	BUXTON_STATUS_MAX /* sentinel value */
};

/*
 *
 */
typedef void (*buxton_status_callback)(enum buxton_status status,
		void *user_data);

/*
 *
 */
int buxton_open(struct buxton_client **client,
		buxton_status_callback callback, void *user_data);

/*
 *
 */
int buxton_close(struct buxton_client *client);


/*
 *
 */
enum buxton_key_type {
	BUXTON_TYPE_UNKNOWN = 0,
	BUXTON_TYPE_STRING,
	BUXTON_TYPE_INT32,
	BUXTON_TYPE_UINT32,
	BUXTON_TYPE_INT64,
	BUXTON_TYPE_UINT64,
	BUXTON_TYPE_DOUBLE,
	BUXTON_TYPE_BOOLEAN,
	BUXTON_TYPE_MAX /* sentinel value */
};
#define BUXTON_TYPE_PRIVILEGE BUXTON_TYPE_STRING

/*
 *
 */
struct buxton_value;

/*
 *
 */
struct buxton_value *buxton_value_create_string(const char *s);
struct buxton_value *buxton_value_create_int32(int32_t i);
struct buxton_value *buxton_value_create_uint32(uint32_t u);
struct buxton_value *buxton_value_create_int64(int64_t i64);
struct buxton_value *buxton_value_create_uint64(uint64_t u64);
struct buxton_value *buxton_value_create_double(double d);
struct buxton_value *buxton_value_create_boolean(int32_t b);

int buxton_value_get_type(const struct buxton_value *val,
		enum buxton_key_type *type);
int buxton_value_get_string(const struct buxton_value *val, const char **s);
int buxton_value_get_int32(const struct buxton_value *val, int32_t *i);
int buxton_value_get_uint32(const struct buxton_value *val, uint32_t *u);
int buxton_value_get_int64(const struct buxton_value *val, int64_t *i64);
int buxton_value_get_uint64(const struct buxton_value *val, uint64_t *u64);
int buxton_value_get_double(const struct buxton_value *val, double *d);
int buxton_value_get_boolean(const struct buxton_value *val, int32_t *b);

struct buxton_value *buxton_value_duplicate(const struct buxton_value *val);
void buxton_value_free(struct buxton_value *val);


/*
 *
 */
struct buxton_layer;

/*
 *
 */
typedef void (*buxton_response_callback)(int status,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val, void *user_data);

/*
 *
 */
struct buxton_layer *buxton_create_layer(const char *layer_name);

/*
 *
 */
const char *buxton_layer_get_name(const struct buxton_layer *layer);

/*
 *
 */
void buxton_free_layer(struct buxton_layer *layer);

/*
 *
 */
int buxton_set_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_set_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val);

/*
 *
 */
int buxton_get_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_get_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		struct buxton_value **val);


/*
 *
 */
typedef void (*buxton_list_callback)(int status,
		const struct buxton_layer *layer,
		char * const *names, unsigned int len,
		void *user_data);

/*
 *
 */
int buxton_list_keys(struct buxton_client *client,
		const struct buxton_layer *layer,
		buxton_list_callback callback, void *user_data);

/*
 *
 */
int buxton_list_keys_sync(struct buxton_client *client,
		const struct buxton_layer *layer,
		char ***names, unsigned int *len);

/*
 *
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

/*
 *
 */
typedef void (*buxton_notify_callback)(const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data);

/*
 *
 */
int buxton_register_notification(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify, void *notify_data,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_register_notification_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify, void *notify_data);

/*
 *
 */
int buxton_unregister_notification(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_unregister_notification_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify);

/* Wrapper APIs ------------------ */

/* Admin APIs  ------------------- */

/*
 *
 */
void buxton_layer_set_uid(struct buxton_layer *layer, uid_t uid);

enum buxton_layer_type {
	BUXTON_LAYER_NORMAL = 0,
	BUXTON_LAYER_BASE,
	BUXTON_LAYER_MAX /* sentinel value */
};

/*
 *
 */
void buxton_layer_set_type(struct buxton_layer *layer,
		enum buxton_layer_type type);

/*
 *
 */
int buxton_create_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const char *read_privilege, const char *write_privilege,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_create_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const char *read_privilege, const char *write_privilege,
		const struct buxton_value *val);

/*
 *
 */
int buxton_unset_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_unset_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key);

/*
 *
 */
enum buxton_priv_type {
	BUXTON_PRIV_UNKNOWN = 0,
	BUXTON_PRIV_READ,
	BUXTON_PRIV_WRITE,
	BUXTON_PRIV_MAX /* sentinel value */
};

/*
 *
 */
int buxton_set_privilege(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		const char *privilege,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_set_privilege_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		const char *privilege);

/*
 *
 */
int buxton_get_privilege(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		buxton_response_callback callback, void *user_data);

/*
 *
 */
int buxton_get_privilege_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		char **privilege);

#ifdef __cplusplus
}
#endif
#endif /* __BUXTON_H__ */
