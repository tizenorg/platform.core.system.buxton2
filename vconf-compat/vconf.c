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
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>

#include <glib.h>

#include <buxton2.h>

#include "vconf.h"

#ifndef EXPORT
#  define EXPORT __attribute__((visibility("default")))
#endif

#define LOGE(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

static pthread_mutex_t vconf_lock = PTHREAD_MUTEX_INITIALIZER;
static int _refcnt;
static struct buxton_client *noti_client;
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
	int ref_cnt;
};

static bool last_result;

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

static void free_noti(struct noti *noti)
{
	GList *l;
	GList *n;

	assert(noti);

	for (l = noti->noti_list, n = g_list_next(l);
			l; l = n, n = g_list_next(n)) {
		struct noti_cb *noticb = l->data;
		noticb->ref_cnt--;
		if (noticb->ref_cnt == 0) {
			noti->noti_list = g_list_delete_link(noti->noti_list, l);
			free(noticb);
		}
	}

	free(noti->key);
	free(noti);
}

static void _close_for_noti(void)
{
	pthread_mutex_lock(&vconf_lock);

	_refcnt--;
	if (_refcnt) {
		pthread_mutex_unlock(&vconf_lock);
		return;
	}

	buxton_free_layer(system_layer);
	system_layer = NULL;

	buxton_free_layer(memory_layer);
	memory_layer = NULL;

	g_hash_table_destroy(noti_tbl);
	noti_tbl = NULL;

	buxton_close(noti_client);
	noti_client = NULL;

	pthread_mutex_unlock(&vconf_lock);
}

static int _open_for_noti(void)
{
	int r;

	pthread_mutex_lock(&vconf_lock);

	_refcnt++;
	if (_refcnt > 1) {
		pthread_mutex_unlock(&vconf_lock);
		return 0;
	}

	r = buxton_open(&noti_client, NULL, NULL);
	if (r == -1) {
		LOGE("Can't connect to buxton: %d", errno);
		pthread_mutex_unlock(&vconf_lock);
		return -1;
	}

	noti_tbl = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)free_noti);

	system_layer = buxton_create_layer("system");
	memory_layer = buxton_create_layer("memory");

	pthread_mutex_unlock(&vconf_lock);
	return 0;
}

static void _close(struct buxton_client *client, struct buxton_layer *layer)
{
	buxton_free_layer(layer);
	buxton_close(client);
}

static int _open(const char *key, struct buxton_client **client,
		struct buxton_layer **layer)
{
	int r;

	r = buxton_open_full(client, false, NULL, NULL);
	if (r == -1) {
		LOGE("Can't connect to buxton: %d", errno);
		return -1;
	}

	if (key && !strncmp(key, "memory/", strlen("memory/")))
		*layer = buxton_create_layer("memory");
	else
		*layer = buxton_create_layer("system");

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

static GList *copy_noti_list(GList *noti_list)
{
	GList *l;
	GList *copy;

	if (!noti_list)
		return NULL;

	pthread_mutex_lock(&vconf_lock);
	for (l = noti_list; l; l = g_list_next(l)) {
		struct noti_cb *noticb;
		noticb = noti_list->data;
		noticb->ref_cnt++;
	}
	copy = g_list_copy(noti_list);
	pthread_mutex_unlock(&vconf_lock);

	return copy;
}

static GList *free_copy_list(GList *noti_list, GList *copy_list)
{
	GList *l;
	GList *ll;

	pthread_mutex_lock(&vconf_lock);
	g_list_free(copy_list);

	for (l = noti_list, ll = g_list_next(l); l;
			l = ll, ll = g_list_next(ll)) {
		struct noti_cb *noticb = l->data;

		noticb->ref_cnt--;
		if (noticb->ref_cnt == 0) {
			noti_list = g_list_delete_link(noti_list, l);
			free(noticb);
		}
	}
	pthread_mutex_unlock(&vconf_lock);

	return noti_list;
}

static void notify_cb(const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val, void *user_data)
{
	struct noti *noti = user_data;
	keynode_t *node;
	GList *l;
	GList *copy;

	assert(noti);

	node = calloc(1, sizeof(*node));
	if (!node)
		return;

	node->keyname = (char *)key;
	to_vconf_t(val, node);

	copy = copy_noti_list(noti->noti_list);

	for (l = copy;	l; l = g_list_next(l)) {
		struct noti_cb *noticb = l->data;

		assert(noticb->cb);
		noticb->cb(node, noticb->user_data);
	}

	noti->noti_list = free_copy_list(noti->noti_list, copy);

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
		errno = EEXIST;
		return -1;
	}

	noticb = calloc(1, sizeof(*noticb));
	if (!noticb)
		return -1;

	noticb->cb = cb;
	noticb->user_data = user_data;
	noticb->ref_cnt = 1;

	noti->noti_list = g_list_append(noti->noti_list, noticb);

	return 0;
}

static struct noti *create_noti(const char *key, vconf_callback_fn cb,
		void *user_data)
{
	int r;
	struct noti *noti;

	assert(key);
	assert(cb);

	noti = calloc(1, sizeof(*noti));
	if (!noti)
		return NULL;

	noti->key = strdup(key);
	if (!noti->key) {
		free(noti);
		return NULL;
	}

	r = add_noti(noti, cb, user_data);
	if (r == -1) {
		free(noti->key);
		free(noti);
		return NULL;
	}

	g_hash_table_insert(noti_tbl, noti->key, noti);

	return noti;
}

EXPORT int vconf_notify_key_changed(const char *key, vconf_callback_fn cb,
		void *user_data)
{
	int r;
	struct noti *noti;
	last_result = false;

	if (!key || !cb) {
		errno = EINVAL;
		return -1;
	}

	r = _open_for_noti();
	if (r == -1)
		return -1;

	pthread_mutex_lock(&vconf_lock);
	noti = g_hash_table_lookup(noti_tbl, key);
	if (!noti) {
		noti = create_noti(key, cb, user_data);
		pthread_mutex_unlock(&vconf_lock);
		if (!noti) {
			_close_for_noti();
			return -1;
		}
		r = buxton_register_notification_sync(noti_client, get_layer(key), key,
				notify_cb, noti);
		if (r == -1) {
			LOGE("vconf_notify_key_changed: key '%s' add notify error %d",
					key, errno);
			pthread_mutex_lock(&vconf_lock);
			g_hash_table_remove(noti_tbl, key);
			pthread_mutex_unlock(&vconf_lock);
		}
		/* increase reference count */
		if (r == 0)
			_open_for_noti();
	} else {
		r = add_noti(noti, cb, user_data);
		pthread_mutex_unlock(&vconf_lock);
	}

	_close_for_noti();

	if (r == 0)
		last_result = true;

	return r;
}

static int unregister_noti(struct noti *noti)
{
	int cnt;
	GList *l;

	assert(noti);

	cnt = 0;
	for (l = noti->noti_list; l; l = g_list_next(l)) {
		cnt++;
	}

	if (cnt > 0)
		return cnt;

	g_hash_table_remove(noti_tbl, noti->key);

	return 0;
}

EXPORT int vconf_ignore_key_changed(const char *key, vconf_callback_fn cb)
{
	int r;
	int cnt;
	struct noti *noti;
	struct noti_cb *noticb;

	if (!key || !cb) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&vconf_lock);
	noti = g_hash_table_lookup(noti_tbl, key);
	if (!noti) {
		pthread_mutex_unlock(&vconf_lock);
		errno = ENOENT;
		return -1;
	}

	noticb = find_noti_cb(noti, cb);
	if (!noticb) {
		pthread_mutex_unlock(&vconf_lock);
		errno = ENOENT;
		return -1;
	}

	noticb->ref_cnt--;
	if (noticb->ref_cnt == 0) {
		noti->noti_list = g_list_remove(noti->noti_list, noticb);
		free(noticb);
	}

	cnt = unregister_noti(noti);
	pthread_mutex_unlock(&vconf_lock);

	if (cnt > 0)
		return 0;

	r = buxton_unregister_notification_sync(noti_client, get_layer(key),
			key, notify_cb);
	if (r == -1)
		LOGE("unregister error '%s' %d", noti->key, errno);

	/* decrease reference count */
	_close_for_noti();

	return 0;
}

static int _vconf_set(const char *key, const struct buxton_value *val)
{
	int r;
	struct buxton_client *client;
	struct buxton_layer *layer;

	assert(key);
	assert(val);

	r = _open(key, &client, &layer);
	if (r == -1)
		return -1;

	r = buxton_set_value_sync(client, layer, key, val);
	if (r == -1)
		LOGE("set value: key '%s' errno %d", key, errno);

	_close(client, layer);

	return r;
}

EXPORT int vconf_set_int(const char *key, int intval)
{
	int r;
	struct buxton_value *val;
	last_result = false;

	if (!key) {
		errno = EINVAL;
		return -1;
	}

	val = buxton_value_create_int32(intval);
	if (!val)
		return -1;

	r = _vconf_set(key, val);
	if (r == 0)
		last_result = true;

	buxton_value_free(val);

	return r;
}

EXPORT int vconf_set_bool(const char *key, int boolval)
{
	int r;
	struct buxton_value *val;
	last_result = false;

	if (!key) {
		errno = EINVAL;
		return -1;
	}

	val = buxton_value_create_boolean(boolval);
	if (!val)
		return -1;

	r = _vconf_set(key, val);
	if (r == 0)
		last_result = true;

	buxton_value_free(val);

	return r;
}

EXPORT int vconf_set_str(const char *key, const char *strval)
{
	int r;
	struct buxton_value *val;
	last_result = false;

	if (!key || !strval) {
		errno = EINVAL;
		return -1;
	}

	val = buxton_value_create_string(strval);
	if (!val)
		return -1;

	r = _vconf_set(key, val);
	if (r == 0)
		last_result = true;

	buxton_value_free(val);

	return r;
}

EXPORT int vconf_set_dbl(const char *key, double dblval)
{
	int r;
	struct buxton_value *val;
	last_result = false;

	if (!key) {
		errno = EINVAL;
		return -1;
	}

	val = buxton_value_create_double(dblval);
	if (!val)
		return -1;

	r = _vconf_set(key, val);
	if (r == 0)
		last_result = true;

	buxton_value_free(val);

	return r;
}

static int _vconf_get(const char *key, enum buxton_key_type type,
		struct buxton_value **val)
{
	int r;
	struct buxton_client *client;
	struct buxton_layer *layer;
	struct buxton_value *v;

	assert(key);
	assert(val);

	r = _open(key, &client, &layer);
	if (r == -1)
		return -1;

	r = buxton_get_value_sync(client, layer, key, &v);
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

	_close(client, layer);

	return r;
}

EXPORT int vconf_get_int(const char *key, int *intval)
{
	int r;
	struct buxton_value *val;
	int32_t i;
	last_result = false;

	if (!key || !intval) {
		errno = EINVAL;
		return -1;
	}

	r = _vconf_get(key, BUXTON_TYPE_INT32, &val);
	if (r == -1)
		return -1;

	r = buxton_value_get_int32(val, &i);

	buxton_value_free(val);

	if (r == -1)
		return -1;

	*intval = i;
	last_result = true;

	return 0;
}

EXPORT int vconf_get_bool(const char *key, int *boolval)
{
	int r;
	struct buxton_value *val;
	int32_t b;
	last_result = false;


	if (!key || !boolval) {
		errno = EINVAL;
		return -1;
	}

	r = _vconf_get(key, BUXTON_TYPE_BOOLEAN, &val);
	if (r == -1)
		return -1;

	r = buxton_value_get_boolean(val, &b);

	buxton_value_free(val);

	if (r == -1)
		return -1;

	*boolval = b;
	last_result = true;

	return 0;
}

EXPORT char *vconf_get_str(const char *key)
{
	int r;
	struct buxton_value *val;
	const char *s;
	char *str;
	last_result = false;

	if (!key) {
		errno = EINVAL;
		return NULL;
	}

	r = _vconf_get(key, BUXTON_TYPE_STRING, &val);
	if (r == -1)
		return NULL;

	r = buxton_value_get_string(val, &s);
	if (r == -1)
		s = NULL;
	else if (r == 0)
		last_result = true;

	str = s ? strdup(s) : NULL;

	buxton_value_free(val);

	return str;
}

EXPORT int vconf_get_dbl(const char *key, double *dblval)
{
	int r;
	struct buxton_value *val;
	double d;
	last_result = false;

	if (!key || !dblval) {
		errno = EINVAL;
		return -1;
	}

	r = _vconf_get(key, BUXTON_TYPE_DOUBLE, &val);
	if (r == -1)
		return -1;

	r = buxton_value_get_double(val, &d);

	buxton_value_free(val);

	if (r == -1)
		return -1;

	*dblval = d;
	last_result = true;

	return 0;
}

EXPORT int vconf_get_ext_errno(void)
{
	int ret;

	if (last_result)
		return VCONF_OK;

	switch(errno) {
	case ENOENT:
		ret = VCONF_ERROR_FILE_NO_ENT;
		break;
	case ENOMEM:
	case ENOSPC:
		ret = VCONF_ERROR_FILE_NO_MEM;
		break;
	case EAGAIN:
	case ETIMEDOUT:
	case EBUSY:
	case EMFILE:
		ret = VCONF_ERROR_FILE_BUSY;
		break;
	case EACCES:
	case EPERM:
		ret = VCONF_ERROR_FILE_PERM;
		break;
	default:
		ret = VCONF_ERROR;
	}

	return ret;
}

struct _keylist_t {
	GList *list; /* struct _keynode_t list */
	GList *cursor;
};

EXPORT keylist_t *vconf_keylist_new(void)
{
	return calloc(1, sizeof(struct _keylist_t));
}

static void free_keynode(struct _keynode_t *keynode)
{
	if (!keynode)
		return;

	if (keynode->type == VCONF_TYPE_STRING)
		free(keynode->value.s);

	free(keynode->keyname);
	free(keynode);
}

EXPORT int vconf_keylist_free(keylist_t *keylist)
{
	if (!keylist) {
		errno = EINVAL;
		return -1;
	}

	g_list_free_full(keylist->list, (GDestroyNotify)free_keynode);
	free(keylist);

	return 0;
}

static struct _keynode_t *find_keynode(struct _keylist_t *keylist,
		const char *keyname)
{
	struct _keynode_t *keynode;
	GList *l;

	assert(keylist);
	assert(keyname);

	for (l = keylist->list; l; l = g_list_next(l)) {
		keynode = l->data;

		if (keynode->keyname && !strcmp(keynode->keyname, keyname))
			return keynode;
	}

	return NULL;
}

static struct _keynode_t *get_keynode(struct _keylist_t *keylist,
		const char *keyname)
{
	struct _keynode_t *keynode;

	assert(keylist);
	assert(keyname);

	keynode = find_keynode(keylist, keyname);
	if (keynode)
		return keynode;

	keynode = calloc(1, sizeof(*keynode));
	if (!keynode)
		return NULL;

	keynode->keyname = strdup(keyname);
	if (!keynode->keyname) {
		free(keynode);
		return NULL;
	}

	keylist->list = g_list_append(keylist->list, keynode);
	keylist->cursor = g_list_last(keylist->list);

	return keynode;
}

EXPORT int vconf_keylist_add_int(keylist_t *keylist,
		const char *keyname, int value)
{
	struct _keynode_t *keynode;

	if (!keylist || !keyname) {
		errno = EINVAL;
		return -1;
	}

	keynode = get_keynode(keylist, keyname);
	if (!keynode)
		return -1;

	if (keynode->type == VCONF_TYPE_STRING)
		free(keynode->value.s);

	keynode->type = VCONF_TYPE_INT;
	keynode->value.i = value;

	return g_list_length(keylist->list);
}

EXPORT int vconf_keylist_add_bool(keylist_t *keylist,
		const char *keyname, int value)
{
	struct _keynode_t *keynode;

	if (!keylist || !keyname) {
		errno = EINVAL;
		return -1;
	}

	keynode = get_keynode(keylist, keyname);
	if (!keynode)
		return -1;

	if (keynode->type == VCONF_TYPE_STRING)
		free(keynode->value.s);

	keynode->type = VCONF_TYPE_BOOL;
	keynode->value.b = value;

	return g_list_length(keylist->list);
}

EXPORT int vconf_keylist_add_dbl(keylist_t *keylist,
		const char *keyname, double value)
{
	struct _keynode_t *keynode;

	if (!keylist || !keyname) {
		errno = EINVAL;
		return -1;
	}

	keynode = get_keynode(keylist, keyname);
	if (!keynode)
		return -1;

	if (keynode->type == VCONF_TYPE_STRING)
		free(keynode->value.s);

	keynode->type = VCONF_TYPE_DOUBLE;
	keynode->value.d = value;

	return g_list_length(keylist->list);
}

EXPORT int vconf_keylist_add_str(keylist_t *keylist,
		const char *keyname, const char *value)
{
	struct _keynode_t *keynode;
	char *s;

	if (!keylist || !keyname || !value) {
		errno = EINVAL;
		return -1;
	}

	s = strdup(value);
	if (!s)
		return -1;

	keynode = get_keynode(keylist, keyname);
	if (!keynode) {
		free(s);
		return -1;
	}

	if (keynode->type == VCONF_TYPE_STRING)
		free(keynode->value.s);

	keynode->type = VCONF_TYPE_STRING;
	keynode->value.s = s;

	return g_list_length(keylist->list);
}

EXPORT int vconf_keylist_add_null(keylist_t *keylist, const char *keyname)
{
	struct _keynode_t *keynode;

	if (!keylist || !keyname) {
		errno = EINVAL;
		return -1;
	}

	keynode = get_keynode(keylist, keyname);
	if (!keynode) {
		return -1;
	}

	return g_list_length(keylist->list);
}

EXPORT int vconf_keylist_del(keylist_t *keylist, const char *keyname)
{
	struct _keynode_t *keynode;

	if (!keylist || !keyname) {
		errno = EINVAL;
		return -1;
	}

	keynode = find_keynode(keylist, keyname);
	if (!keynode) {
		errno = ENOENT;
		return -1;
	}

	keylist->list = g_list_remove(keylist->list, keynode);
	free_keynode(keynode);

	return 0;
}

EXPORT keynode_t *vconf_keylist_nextnode(keylist_t *keylist)
{
	keynode_t *node = NULL;
	GList *next;

	if (!keylist) {
		errno = EINVAL;
		return NULL;
	}

	next = g_list_next(keylist->cursor);
	if (!next) {
		next = g_list_first(keylist->cursor);
	}

	node = next->data;
	keylist->cursor = next;

	return node;
}

EXPORT int vconf_keylist_rewind(keylist_t *keylist)
{
	GList *l;

	if (!keylist) {
		errno = EINVAL;
		return -1;
	}

	l = g_list_last(keylist->cursor);

	if (!l) {
		errno = ENOENT;
		return -1;
	}

	keylist->cursor = l;

	return 0;
}

static int set_keynode_value(struct buxton_value *v, struct _keynode_t *keynode)
{
	int r;
	enum buxton_key_type t;
	const char *s;

	assert(v);
	assert(keynode);

	r = buxton_value_get_type(v, &t);
	if (r == -1)
		t = BUXTON_TYPE_UNKNOWN;

	switch (t) {
	case BUXTON_TYPE_INT32:
		keynode->type = VCONF_TYPE_INT;
		r = buxton_value_get_int32(v, &keynode->value.i);
		break;
	case BUXTON_TYPE_BOOLEAN:
		keynode->type = VCONF_TYPE_BOOL;
		r = buxton_value_get_boolean(v, &keynode->value.b);
		break;
	case BUXTON_TYPE_DOUBLE:
		keynode->type = VCONF_TYPE_DOUBLE;
		r = buxton_value_get_double(v, &keynode->value.d);
		break;
	case BUXTON_TYPE_STRING:
		keynode->type = VCONF_TYPE_STRING;
		r = buxton_value_get_string(v, &s);
		if (r != -1) {
			if (s) {
				keynode->value.s = strdup(s);
				if (!keynode->value.s)
					r = -1;
			}
		}
		break;
	default:
		LOGE("set keynode: unsupported key type %d", t);
		r = 0; /* ignore error */
		break;
	}

	return r;
}

static struct _keynode_t *alloc_keynode(struct buxton_client *client,
		struct buxton_layer *layer,
		const char *keyname)
{
	int r;
	struct buxton_value *v;
	struct _keynode_t *keynode;

	assert(client);
	assert(layer);
	assert(keyname);

	r = buxton_get_value_sync(client, layer, keyname, &v);
	if (r == -1) {
		LOGE("get value: key '%s' errno %d", keyname, errno);
		return NULL;
	}

	keynode = calloc(1, sizeof(*keynode));
	if (!keynode) {
		buxton_value_free(v);
		return NULL;
	}

	keynode->keyname = strdup(keyname);
	if (!keynode->keyname) {
		free(keynode);
		buxton_value_free(v);
		return NULL;
	}

	r = set_keynode_value(v, keynode);
	if (r == -1) {
		free(keynode);
		buxton_value_free(v);
		return NULL;
	}

	buxton_value_free(v);

	return keynode;
}

EXPORT int vconf_get(keylist_t *keylist,
		const char *in_parentDIR, get_option_t option)
{
	int r;
	char **names;
	unsigned int len;
	int i;
	int dirlen;
	struct buxton_client *client;
	struct buxton_layer *layer;

	if (!keylist || !in_parentDIR) {
		errno = EINVAL;
		return -1;
	}

	dirlen = strlen(in_parentDIR);
	if (dirlen < 2) { /* minimum is "db" */
		errno = EINVAL;
		return -1;
	}

	r = _open(in_parentDIR, &client, &layer);
	if (r == -1)
		return -1;

	r = buxton_list_keys_sync(client, layer, &names, &len);
	if (r == -1) {
		LOGE("get key list: errno %d", errno);
		_close(client, layer);
		return -1;
	}

	g_list_free_full(keylist->list, (GDestroyNotify)free_keynode);
	keylist->list = NULL;

	for (i = 0; i < len; i++) {
		struct _keynode_t *keynode;

		if (strncmp(in_parentDIR, names[i], dirlen))
			continue;

		keynode = alloc_keynode(client, layer, names[i]);
		if (keynode)
			keylist->list = g_list_append(keylist->list, keynode);
	}

	buxton_free_keys(names);

	_close(client, layer);

	return 0;
}

EXPORT int vconf_set(keylist_t *keylist)
{
	GList *l;

	if (!keylist) {
		errno = EINVAL;
		return -1;
	}

	for (l = keylist->list; l; l = g_list_next(l)) {
		struct _keynode_t *keynode = l->data;
		int r;

		switch (keynode->type) {
		case VCONF_TYPE_STRING:
			r = vconf_set_str(keynode->keyname, keynode->value.s);
			break;
		case VCONF_TYPE_INT:
			r = vconf_set_int(keynode->keyname, keynode->value.i);
			break;
		case VCONF_TYPE_BOOL:
			r = vconf_set_bool(keynode->keyname, keynode->value.b);
			break;
		case VCONF_TYPE_DOUBLE:
			r = vconf_set_dbl(keynode->keyname, keynode->value.d);
			break;
		default:
			LOGE("unknown key type: %d", keynode->type);
			r = 0;
			break;
		}
		if (r == -1)
			LOGE("set key '%s' errno %d", keynode->keyname, errno);
	}

	return 0;
}

EXPORT int vconf_unset(const char *in_key)
{
	int r;
	struct buxton_client *client;
	struct buxton_layer *layer;

	if (getuid() != 0)
		return VCONF_ERROR_NOT_SUPPORTED;

	if (!in_key) {
		errno = EINVAL;
		return -1;
	}

	r = _open(in_key, &client, &layer);
	if (r == -1)
		return -1;

	r = buxton_unset_value_sync(client, layer, in_key);
	if (r == -1)
		LOGE("unset value: key '%s' errno %d", in_key, errno);

	_close(client, layer);

	return r;
}

EXPORT int vconf_unset_recursive(const char *in_dir)
{
	int r;
	int i;
	int dirlen;
	char **names;
	unsigned int len;
	struct buxton_client *client;
	struct buxton_layer *layer;

	if (getuid() != 0)
		return VCONF_ERROR_NOT_SUPPORTED;

	if (!in_dir) {
		errno = EINVAL;
		return -1;
	}

	dirlen = strlen(in_dir);
	if (dirlen < 2) { /* minimum is "db" */
		errno = EINVAL;
		return -1;
	}

	r = _open(in_dir, &client, &layer);
	if (r == -1)
		return -1;

	r = buxton_list_keys_sync(client, layer, &names, &len);
	if (r == -1) {
		LOGE("get key list: errno %d", errno);
		_close(client, layer);
		return -1;
	}

	for (i = 0; i < len; i++) {
		if (strncmp(in_dir, names[i], dirlen))
			continue;

		r = vconf_unset(names[i]);
		if (r == -1) {
			buxton_free_keys(names);
			_close(client, layer);
			return -1;
		}
	}

	buxton_free_keys(names);
	_close(client, layer);

	return 0;
}

EXPORT int vconf_sync_key(const char *in_key)
{
	int r;
	struct buxton_client *client;
	struct buxton_layer *layer;
	struct buxton_value *v;

	assert(in_key);

	r = _open(in_key, &client, &layer);
	if (r == -1)
		return -1;

	r = buxton_get_value_sync(client, layer, in_key, &v);
	if (r == -1) {
		LOGE("get value: key '%s'", in_key);
	} else {
		r = 0;
	}

	_close(client, layer);

	return r;
}

EXPORT int vconf_keylist_lookup(keylist_t *keylist, const char *keyname,
		keynode_t **return_node)
{
	struct _keynode_t *keynode;

	if (!keylist || !keyname || !return_node) {
		errno = EINVAL;
		return -1;
	}

	keynode = find_keynode(keylist, keyname);
	if (!keynode)
		return 0;

	*return_node = keynode;

	return keynode->type;
}

