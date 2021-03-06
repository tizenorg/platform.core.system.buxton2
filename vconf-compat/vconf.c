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

#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <buxton2.h>

#include "vconf.h"

#ifndef EXPORT
#  define EXPORT __attribute__((visibility("default")))
#endif

#define LOGE(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

static int _refcnt;
static struct buxton_client *client;
static struct buxton_layer *system_layer;
static struct buxton_layer *memory_layer;
static GHashTable *noti_tbl;

struct noti {
	char *key;
	GList *noti_list; /* struct noti_cb list */
};

struct noti_cb {
	vconf_callback_fn cb;
	void *user_data;
	gboolean deleted;
};

EXPORT char *vconf_keynode_get_name(keynode_t *keynode)
{
	if (!keynode || !keynode->keyname) {
		errno = EINVAL;
		return NULL;
	}

	return keynode->keyname;
}

EXPORT int vconf_keynode_get_type(keynode_t *keynode)
{
	if (!keynode) {
		errno = EINVAL;
		return -1;
	}

	return keynode->type;
}

EXPORT int vconf_keynode_get_int(keynode_t *keynode)
{
	if (!keynode) {
		errno = EINVAL;
		return -1;
	}

	if (keynode->type != VCONF_TYPE_INT) {
		errno = ENOTSUP;
		return -1;
	}

	return keynode->value.i;
}

EXPORT double vconf_keynode_get_dbl(keynode_t *keynode)
{
	if (!keynode) {
		errno = EINVAL;
		return -1;
	}

	if (keynode->type != VCONF_TYPE_DOUBLE) {
		errno = ENOTSUP;
		return -1;
	}

	return keynode->value.d;
}

EXPORT int vconf_keynode_get_bool(keynode_t *keynode)
{
	if (!keynode) {
		errno = EINVAL;
		return -1;
	}

	if (keynode->type != VCONF_TYPE_BOOL) {
		errno = ENOTSUP;
		return -1;
	}

	return !!(keynode->value.b);
}

EXPORT char *vconf_keynode_get_str(keynode_t *keynode)
{
	if (!keynode) {
		errno = EINVAL;
		return NULL;
	}

	if (keynode->type != VCONF_TYPE_STRING) {
		errno = ENOTSUP;
		return NULL;
	}

	return keynode->value.s;
}

static struct buxton_layer *get_layer(const char *key)
{
	if (key && !strncmp(key, "memory/", strlen("memory/")))
		return memory_layer;

	return system_layer;
}

static gboolean free_noti_cb(gpointer data)
{
	GList *list = data;
	GList *l;
	GList *n;

	if (!list)
		return G_SOURCE_REMOVE;

	for (l = list, n = g_list_next(l); l; l = n, n = g_list_next(n)) {
		struct noti_cb *noticb = l->data;

		if (!noticb->deleted)
			continue;

		list = g_list_delete_link(list, l);
		free(noticb);
	}

	return G_SOURCE_REMOVE;
}

static void free_noti(struct noti *noti)
{
	GList *l;

	assert(noti);

	for (l = noti->noti_list; l; l = g_list_next(l)) {
		struct noti_cb *noticb = l->data;

		noticb->deleted = TRUE;
	}
	g_idle_add(free_noti_cb, noti->noti_list);

	free(noti->key);
	free(noti);
}

static void _close(void)
{
	_refcnt--;
	if (_refcnt)
		return;

	buxton_free_layer(system_layer);
	system_layer = NULL;

	buxton_free_layer(memory_layer);
	memory_layer = NULL;

	g_hash_table_destroy(noti_tbl);
	noti_tbl = NULL;

	buxton_close(client);
	client = NULL;
}

static int _open(void)
{
	int r;

	_refcnt++;
	if (_refcnt > 1)
		return 0;

	r = buxton_open(&client, NULL, NULL);
	if (r == -1) {
		LOGE("Can't connect to buxton: %d", errno);
		return -1;
	}

	noti_tbl = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)free_noti);

	system_layer = buxton_create_layer("system");
	memory_layer = buxton_create_layer("memory");

	return 0;
}

static void to_vconf_t(const struct buxton_value *val, keynode_t *node)
{
	int r;
	enum buxton_key_type type;
	uint32_t u;
	int64_t i64;
	uint64_t u64;

	assert(val);
	assert(node);

	r = buxton_value_get_type(val, &type);
	if (r == -1)
		type = BUXTON_TYPE_UNKNOWN;

	switch (type) {
	case BUXTON_TYPE_STRING:
		node->type = VCONF_TYPE_STRING;
		buxton_value_get_string(val, (const char **)&node->value.s);
		break;
	case BUXTON_TYPE_INT32:
		node->type = VCONF_TYPE_INT;
		buxton_value_get_int32(val, &node->value.i);
		break;
	case BUXTON_TYPE_UINT32:
		node->type = VCONF_TYPE_INT;
		buxton_value_get_uint32(val, &u);
		node->value.i = (int)u;
		break;
	case BUXTON_TYPE_INT64:
		node->type = VCONF_TYPE_INT;
		buxton_value_get_int64(val, &i64);
		node->value.i = (int)i64;
		break;
	case BUXTON_TYPE_UINT64:
		node->type = VCONF_TYPE_INT;
		buxton_value_get_uint64(val, &u64);
		node->value.i = (int)u64;
		break;
	case BUXTON_TYPE_DOUBLE:
		node->type = VCONF_TYPE_DOUBLE;
		buxton_value_get_double(val, &node->value.d);
		break;
	case BUXTON_TYPE_BOOLEAN:
		node->type = VCONF_TYPE_BOOL;
		buxton_value_get_boolean(val, &node->value.b);
		break;
	default:
		node->type = VCONF_TYPE_NONE;
		break;
	}
}

static void notify_cb(const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val, void *user_data)
{
	struct noti *noti = user_data;
	keynode_t *node;
	GList *l;

	assert(noti);

	node = calloc(1, sizeof(*node));
	if (!node)
		return;

	node->keyname = (char *)key;
	to_vconf_t(val, node);

	for (l = noti->noti_list; l; l = g_list_next(l)) {
		struct noti_cb *noticb = l->data;

		if (noticb->deleted)
			continue;

		assert(noticb->cb);
		noticb->cb(node, noticb->user_data);
	}

	free(node);
}

static struct noti_cb *find_noti_cb(struct noti *noti, vconf_callback_fn cb)
{
	GList *l;

	assert(noti);
	assert(cb);

	for (l = noti->noti_list; l; l = g_list_next(l)) {
		struct noti_cb *noticb = l->data;

		if (noticb->cb == cb)
			return noticb;
	}

	return NULL;
}


static int add_noti(struct noti *noti, vconf_callback_fn cb, void *user_data)
{
	struct noti_cb *noticb;

	assert(noti);
	assert(cb);

	noticb = find_noti_cb(noti, cb);
	if (noticb) {
		if (noticb->deleted) { /* reuse */
			noticb->user_data = user_data;
			noticb->deleted = FALSE;
			return 0;
		}

		errno = EEXIST;
		return -1;
	}

	noticb = calloc(1, sizeof(*noticb));
	if (!noticb)
		return -1;

	noticb->cb = cb;
	noticb->user_data = user_data;
	noticb->deleted = FALSE;

	noti->noti_list = g_list_append(noti->noti_list, noticb);

	return 0;
}

static int register_noti(const char *key, vconf_callback_fn cb, void *user_data)
{
	int r;
	struct noti *noti;

	assert(key);
	assert(cb);

	noti = calloc(1, sizeof(*noti));
	if (!noti)
		return -1;

	noti->key = strdup(key);
	if (!noti->key) {
		free(noti);
		return -1;
	}

	r = add_noti(noti, cb, user_data);
	if (r == -1) {
		free(noti->key);
		free(noti);
		return -1;
	}

	r = buxton_register_notification_sync(client, get_layer(key), key,
			notify_cb, noti);
	if (r == -1) {
		LOGE("vconf_notify_key_changed: key '%s' add notify error %d",
				key, errno);
		free_noti(noti);
		return -1;
	}

	/* increase reference count */
	_open();
	g_hash_table_insert(noti_tbl, noti->key, noti);

	return 0;
}

EXPORT int vconf_notify_key_changed(const char *key, vconf_callback_fn cb,
		void *user_data)
{
	int r;
	struct noti *noti;

	if (!key || !cb) {
		errno = EINVAL;
		return -1;
	}

	r = _open();
	if (r == -1)
		return -1;

	noti = g_hash_table_lookup(noti_tbl, key);
	if (!noti)
		r = register_noti(key, cb, user_data);
	else
		r = add_noti(noti, cb, user_data);

	_close();

	return r;
}

static int unregister_noti(struct noti *noti)
{
	int r;
	int cnt;
	GList *l;

	assert(noti);

	cnt = 0;
	for (l = noti->noti_list; l; l = g_list_next(l)) {
		struct noti_cb *noticb = l->data;

		if (!noticb->deleted)
			cnt++;
	}

	if (cnt > 0)
		return 0;

	r = buxton_unregister_notification_sync(client, get_layer(noti->key),
			noti->key, notify_cb);
	if (r == -1)
		LOGE("unregister error '%s' %d", noti->key, errno);

	g_hash_table_remove(noti_tbl, noti->key);

	/* decrease reference count */
	_close();

	return r;
}

EXPORT int vconf_ignore_key_changed(const char *key, vconf_callback_fn cb)
{
	struct noti *noti;
	struct noti_cb *noticb;

	if (!key || !cb) {
		errno = EINVAL;
		return -1;
	}

	noti = g_hash_table_lookup(noti_tbl, key);
	if (!noti) {
		errno = ENOENT;
		return -1;
	}

	noticb = find_noti_cb(noti, cb);
	if (!noticb) {
		errno = ENOENT;
		return -1;
	}

	noticb->deleted = TRUE;

	return unregister_noti(noti);
}

static int vconf_set(const char *key, const struct buxton_value *val)
{
	int r;

	assert(key);
	assert(val);

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_set_value_sync(client, get_layer(key), key, val);
	if (r == -1)
		LOGE("set value: key '%s' errno %d", key, errno);

	_close();

	return r;
}

EXPORT int vconf_set_int(const char *key, int intval)
{
	int r;
	struct buxton_value *val;

	if (!key) {
		errno = EINVAL;
		return -1;
	}

	val = buxton_value_create_int32(intval);
	if (!val)
		return -1;

	r = vconf_set(key, val);

	buxton_value_free(val);

	return r;
}

EXPORT int vconf_set_bool(const char *key, int boolval)
{
	int r;
	struct buxton_value *val;

	if (!key) {
		errno = EINVAL;
		return -1;
	}

	val = buxton_value_create_boolean(boolval);
	if (!val)
		return -1;

	r = vconf_set(key, val);

	buxton_value_free(val);

	return r;
}

EXPORT int vconf_set_str(const char *key, const char *strval)
{
	int r;
	struct buxton_value *val;

	if (!key || !strval) {
		errno = EINVAL;
		return -1;
	}

	val = buxton_value_create_string(strval);
	if (!val)
		return -1;

	r = vconf_set(key, val);

	buxton_value_free(val);

	return r;
}

static int vconf_get(const char *key, enum buxton_key_type type,
		struct buxton_value **val)
{
	int r;
	struct buxton_value *v;

	assert(key);
	assert(val);

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_get_value_sync(client, get_layer(key), key, &v);
	if (r == -1) {
		LOGE("get value: key '%s' errno %d", key, errno);
	} else {
		enum buxton_key_type t;

		r = buxton_value_get_type(v, &t);
		if (r == -1)
			t = BUXTON_TYPE_UNKNOWN;

		if (t != type) {
			buxton_value_free(v);
			errno = ENOTSUP;
			r = -1;
		} else {
			*val = v;
		}
	}

	_close();

	return r;
}

EXPORT int vconf_get_int(const char *key, int *intval)
{
	int r;
	struct buxton_value *val;
	int32_t i;

	if (!key || !intval) {
		errno = EINVAL;
		return -1;
	}

	r = vconf_get(key, BUXTON_TYPE_INT32, &val);
	if (r == -1)
		return -1;

	r = buxton_value_get_int32(val, &i);

	buxton_value_free(val);

	if (r == -1)
		return -1;

	*intval = i;

	return 0;
}

EXPORT int vconf_get_bool(const char *key, int *boolval)
{
	int r;
	struct buxton_value *val;
	int32_t b;

	if (!key || !boolval) {
		errno = EINVAL;
		return -1;
	}

	r = vconf_get(key, BUXTON_TYPE_BOOLEAN, &val);
	if (r == -1)
		return -1;

	r = buxton_value_get_boolean(val, &b);

	buxton_value_free(val);

	if (r == -1)
		return -1;

	*boolval = b;

	return 0;
}

EXPORT char *vconf_get_str(const char *key)
{
	int r;
	struct buxton_value *val;
	const char *s;
	char *str;

	if (!key) {
		errno = EINVAL;
		return NULL;
	}

	r = vconf_get(key, BUXTON_TYPE_STRING, &val);
	if (r == -1)
		return NULL;

	r = buxton_value_get_string(val, &s);
	if (r == -1)
		s = NULL;

	str = s ? strdup(s) : NULL;

	buxton_value_free(val);

	return str;
}

