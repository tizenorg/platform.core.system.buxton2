/*
 * Buxton
 *
 * Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License)
{
}
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


#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

#include <glib.h>
#include <glib-unix.h>

#include "buxton2.h"

#include "common.h"
#include "log.h"
#include "serialize.h"
#include "proto.h"

#ifndef EXPORT
#  define EXPORT __attribute__((visibility("default")))
#endif

struct bxt_req {
	guint32 msgid;
	struct buxton_layer *layer;
	char *key;

	buxton_response_callback callback;
	buxton_list_callback list_cb;
	void *data;

	buxton_notify_callback notify;
	void *notify_data;
};

struct bxt_noti_cb {
	gboolean deleted;
	buxton_notify_callback callback;
	void *data;
};

struct bxt_noti {
	guint id;
	char *layer_key; /* layer + <tab>(0x09) + key */
	gboolean reg;
	GList *callbacks; /* data: bxt_noti_cb */
};

struct bxt_noti_res {
	int res;
	struct buxton_layer *layer;
	char *key;
	buxton_response_callback callback;
	void *data;
};

struct buxton_client {
	int fd;
	guint fd_id;

	buxton_status_callback st_callback;
	void *st_data;

	GHashTable *req_cbs; /* key: msgid, value: bxt_req */
	GHashTable *noti_cbs; /* key: keyname, value: bxt_noti */
};

static GList *clients; /* data: buxton_client */
static guint32 client_msgid;

static struct buxton_value *value_create(enum buxton_key_type type, void *value)
{
	struct buxton_value *val;

	if (!value) {
		errno = EINVAL;
		return NULL;
	}

	val = calloc(1, sizeof(*val));
	if (!val)
		return NULL;

	switch (type) {
	case BUXTON_TYPE_STRING:
		val->value.s = *(char **)value;
		break;
	case BUXTON_TYPE_INT32:
		val->value.i = *(int32_t *)value;
		break;
	case BUXTON_TYPE_UINT32:
		val->value.u = *(uint32_t *)value;
		break;
	case BUXTON_TYPE_INT64:
		val->value.i64 = *(int64_t *)value;
		break;
	case BUXTON_TYPE_UINT64:
		val->value.u64 = *(uint64_t *)value;
		break;
	case BUXTON_TYPE_DOUBLE:
		val->value.d = *(double *)value;
		break;
	case BUXTON_TYPE_BOOLEAN:
		val->value.b = *(int32_t *)value;
		break;
	default:
		free(val);
		errno = EINVAL;
		return NULL;
	}
	val->type = type;

	return val;
}

EXPORT struct buxton_value *buxton_value_create_string(const char *s)
{
	struct buxton_value *v;
	char *str;

	if (!s) {
		errno = EINVAL;
		return NULL;
	}

	str = strdup(s);
	if (!str)
		return NULL;

	v = value_create(BUXTON_TYPE_STRING, &str);
	if (!v) {
		free(str);
		return NULL;
	}

	return v;
}

EXPORT struct buxton_value *buxton_value_create_int32(int32_t i)
{
	return value_create(BUXTON_TYPE_INT32, &i);
}

EXPORT struct buxton_value *buxton_value_create_uint32(uint32_t u)
{
	return value_create(BUXTON_TYPE_UINT32, &u);
}

EXPORT struct buxton_value *buxton_value_create_int64(int64_t i64)
{
	return value_create(BUXTON_TYPE_INT64, &i64);
}

EXPORT struct buxton_value *buxton_value_create_uint64(uint64_t u64)
{
	return value_create(BUXTON_TYPE_UINT64, &u64);
}

EXPORT struct buxton_value *buxton_value_create_double(double d)
{
	return value_create(BUXTON_TYPE_DOUBLE, &d);
}

EXPORT struct buxton_value *buxton_value_create_boolean(int32_t b)
{
	return value_create(BUXTON_TYPE_BOOLEAN, &b);
}

EXPORT int buxton_value_get_type(const struct buxton_value *val,
		enum buxton_key_type *type)
{
	if (!val || !type) {
		errno = EINVAL;
		return -1;
	}

	*type = val->type;

	return 0;
}

static int value_get(const struct buxton_value *val, void *dest,
		enum buxton_key_type type)
{
	if (!val || !dest) {
		errno = EINVAL;
		return -1;
	}

	if (val->type != type) {
		errno = ENOTSUP;
		return -1;
	}

	switch (type) {
	case BUXTON_TYPE_STRING:
		*(char **)dest = val->value.s;
		break;
	case BUXTON_TYPE_INT32:
		*(int32_t *)dest = val->value.i;
		break;
	case BUXTON_TYPE_UINT32:
		*(uint32_t *)dest = val->value.u;
		break;
	case BUXTON_TYPE_INT64:
		*(int64_t *)dest = val->value.i64;
		break;
	case BUXTON_TYPE_UINT64:
		*(uint64_t *)dest = val->value.u64;
		break;
	case BUXTON_TYPE_DOUBLE:
		*(double *)dest = val->value.d;
		break;
	case BUXTON_TYPE_BOOLEAN:
		*(int32_t *)dest = val->value.b;
		break;
	default:
		break;
	}

	return 0;
}

EXPORT int buxton_value_get_string(const struct buxton_value *val,
		const char **s)
{
	return value_get(val, s, BUXTON_TYPE_STRING);
}

EXPORT int buxton_value_get_int32(const struct buxton_value *val, int32_t *i)
{
	return value_get(val, i, BUXTON_TYPE_INT32);
}

EXPORT int buxton_value_get_uint32(const struct buxton_value *val, uint32_t *u)
{
	return value_get(val, u, BUXTON_TYPE_UINT32);
}

EXPORT int buxton_value_get_int64(const struct buxton_value *val, int64_t *i64)
{
	return value_get(val, i64, BUXTON_TYPE_INT64);
}

EXPORT int buxton_value_get_uint64(const struct buxton_value *val,
		uint64_t *u64)
{
	return value_get(val, u64, BUXTON_TYPE_UINT64);
}

EXPORT int buxton_value_get_double(const struct buxton_value *val, double *d)
{
	return value_get(val, d, BUXTON_TYPE_DOUBLE);
}

EXPORT int buxton_value_get_boolean(const struct buxton_value *val, int32_t *b)
{
	return value_get(val, b, BUXTON_TYPE_BOOLEAN);
}

EXPORT struct buxton_value *buxton_value_duplicate(
		const struct buxton_value *val)
{
	struct buxton_value *_val;

	if (!val) {
		errno = EINVAL;
		return NULL;
	}

	_val = malloc(sizeof(*_val));
	if (!_val)
		return NULL;

	*_val = *val;

	if (val->type == BUXTON_TYPE_STRING && val->value.s) {
		_val->value.s = strdup(val->value.s);
		if (!_val->value.s)
			return NULL;
	}

	return _val;
}

EXPORT void buxton_value_free(struct buxton_value *val)
{
	value_free(val);
	free(val);
}

EXPORT struct buxton_layer *buxton_create_layer(const char *layer_name)
{
	return layer_create(layer_name);
}

EXPORT const char *buxton_layer_get_name(const struct buxton_layer *layer)
{
	if (!layer)
		return NULL;

	return layer->name;
}

EXPORT void buxton_layer_set_uid(struct buxton_layer *layer, uid_t uid)
{
	if (!layer)
		return;

	layer->uid = uid;
}

EXPORT void buxton_layer_set_type(struct buxton_layer *layer,
		enum buxton_layer_type type)
{
	if (!layer)
		return;

	switch (type) {
	case BUXTON_LAYER_NORMAL:
	case BUXTON_LAYER_BASE:
		break;
	default:
		return;
	}

	layer->type = type;
}

EXPORT void buxton_free_layer(struct buxton_layer *layer)
{
	layer_unref(layer);
}

static struct bxt_req *create_req(const struct buxton_layer *layer,
		const char *key, buxton_response_callback callback,
		buxton_list_callback list_cb, void *data)
{
	struct bxt_req *req;

	assert(layer);
	assert(callback || list_cb);

	req = calloc(1, sizeof(*req));
	if (!req)
		return NULL;

	if (key) {
		req->key = strdup(key);
		if (!req->key) {
			free(req);
			return NULL;
		}
	}

	req->layer = layer_ref((struct buxton_layer *)layer);
	req->callback = callback;
	req->list_cb = list_cb;
	req->data = data;
	req->msgid = ++client_msgid;

	return req;
}

static int find_noti(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		struct bxt_noti **noti)
{
	char *lykey;
	struct bxt_noti *_noti;

	assert(client);
	assert(layer);
	assert(key && *key);
	assert(noti);

	lykey = get_search_key(layer, key, NULL);
	if (!lykey)
		return -1;

	_noti = g_hash_table_lookup(client->noti_cbs, lykey);

	free(lykey);

	*noti = _noti;

	return 0;
}

static int proc_msg_noti(struct buxton_client *client, uint8_t *data, int len)
{
	int r;
	struct request rqst;
	struct bxt_noti *noti;
	GList *l;

	assert(client);
	assert(data);
	assert(len > 0);

	r = deserialz_request(data, len, &rqst);
	if (r == -1) {
		bxt_err("proc noti: deserialize errno %d", errno);
		return -1;
	}

	noti = NULL;
	r = find_noti(client, rqst.layer, rqst.key, &noti);
	if (r == -1) {
		bxt_err("proc noti: '%s' '%s' not registered",
				rqst.layer->name, rqst.key);
		free_request(&rqst);
		return -1;
	}

	if (!noti) {
		bxt_err("proc noti: '%s' '%s' callback not exist",
				rqst.layer->name, rqst.key);
		free_request(&rqst);
		return -1;
	}

	for (l = noti->callbacks; l; l = g_list_next(l)) {
		struct bxt_noti_cb *noticb = l->data;

		if (noticb->deleted)
			continue;

		assert(noticb->callback);
		noticb->callback(rqst.layer, rqst.key, rqst.val, noticb->data);
	}

	free_request(&rqst);

	return 0;
}

static int add_noti(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		struct bxt_noti **noti)
{
	char *lykey;
	struct bxt_noti *_noti;

	assert(client);
	assert(layer);
	assert(key && *key);
	assert(noti);

	lykey = get_search_key(layer, key, NULL);
	if (!lykey)
		return -1;

	_noti = g_hash_table_lookup(client->noti_cbs, lykey);
	if (_noti) {
		free(lykey);
		*noti = _noti;
		return 0;
	}

	_noti = calloc(1, sizeof(*_noti));
	if (!_noti) {
		free(lykey);
		return -1;
	}
	_noti->layer_key = lykey;
	g_hash_table_insert(client->noti_cbs, lykey, _noti);

	*noti = _noti;

	return 0;
}

static int add_noticb(struct bxt_noti *noti, buxton_notify_callback notify,
		void *notify_data)
{
	GList *l;
	struct bxt_noti_cb *noticb;

	assert(noti);
	assert(notify);

	for (l = noti->callbacks; l; l = g_list_next(l)) {
		noticb = l->data;

		if (noticb->callback == notify) {
			if (noticb->deleted == FALSE) {
				errno = EEXIST;
				return -1;
			}

			noticb->deleted = FALSE;
			noticb->callback = notify;
			noticb->data = notify_data;

			return 0;
		}
	}

	noticb = calloc(1, sizeof(*noticb));
	if (!noticb)
		return -1;

	noticb->deleted = FALSE;
	noticb->callback = notify;
	noticb->data = notify_data;

	noti->callbacks = g_list_append(noti->callbacks, noticb);

	return 0;
}

static void del_noti(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key)
{
	char *lykey;

	assert(client);
	assert(layer);
	assert(key && *key);

	lykey = get_search_key(layer, key, NULL);
	if (!lykey)
		return;

	g_hash_table_remove(client->noti_cbs, lykey);

	free(lykey);
}

static void proc_msg_notify(struct buxton_client *client, struct bxt_req *req,
		struct response *resp)
{
	struct bxt_noti *noti;
	int r;

	assert(client);
	assert(req);
	assert(resp);

	if (resp->res == 0) {
		r = add_noti(client, req->layer, req->key, &noti);
		if (r == -1) {
			resp->res = errno;
			bxt_err("add noti: errno %d", errno);
		} else {
			if (noti->reg == FALSE)
				noti->reg = (resp->res == 0);

			r = add_noticb(noti, req->notify, req->notify_data);
			if (r == -1 && errno != EEXIST) {
				resp->res = errno;
				bxt_err("add noticb: errno %d", errno);
			}
		}
	}

	assert(req->callback);
	req->callback(resp->res, req->layer, req->key, resp->val, req->data);
}

static int proc_msg_res(struct buxton_client *client, uint8_t *data, int len)
{
	int r;
	struct response resp;
	struct bxt_req *req;

	assert(client);
	assert(data);
	assert(len > 0);

	r = deserialz_response(data, len, &resp);
	if (r == -1) {
		bxt_err("proc msg: deserialize errno %d", errno);
		return -1;
	}

	req = g_hash_table_lookup(client->req_cbs,
			GUINT_TO_POINTER(resp.msgid));
	if (!req) {
		bxt_err("proc msg: msgid %d not exist", resp.msgid);
		free_response(&resp);
		return 0;
	}

	switch (resp.type) {
	case MSG_LIST:
		assert(req->list_cb);
		req->list_cb(resp.res, req->layer, resp.names, resp.nmlen,
				req->data);
		break;
	case MSG_NOTIFY:
		proc_msg_notify(client, req, &resp);
		break;
	case MSG_UNNOTIFY:
		del_noti(client, req->layer, req->key);

		assert(req->callback);
		req->callback(resp.res, req->layer, req->key, resp.val,
				req->data);
		break;
	default:
		assert(req->callback);
		req->callback(resp.res, req->layer, req->key, resp.val,
				req->data);
		break;
	}

	free_response(&resp);

	g_hash_table_remove(client->req_cbs, GUINT_TO_POINTER(resp.msgid));

	return 0;
}

static void proc_msg_cb(void *user_data,
		enum message_type type, uint8_t *data, int32_t len)
{
	struct buxton_client *client = user_data;

	assert(client);

	switch (type) {
	case MSG_NOTI:
		proc_msg_noti(client, data, len);
		break;
	case MSG_SET:
	case MSG_GET:
	case MSG_CREAT:
	case MSG_UNSET:
	case MSG_LIST:
	case MSG_NOTIFY:
	case MSG_UNNOTIFY:
	case MSG_SET_WP:
	case MSG_SET_RP:
	case MSG_GET_WP:
	case MSG_GET_RP:
		proc_msg_res(client, data, len);
		break;
	default:
		bxt_err("proc msg: unknown message type %d", type);
		break;
	}
}

static int proc_msg(struct buxton_client *client)
{
	int r;

	r = proto_recv_frag(client->fd, proc_msg_cb, client);
	if (r == -1) {
		bxt_err("recv msg: fd %d errno %d", client->fd, errno);
		return -1;
	}

	return 0;
}

#define TS_SUB(a, b) (((a)->tv_sec - (b)->tv_sec) * 1000 \
		+ ((a)->tv_nsec - (b)->tv_nsec) / 1000000)
static int wait_msg(struct buxton_client *client, guint32 msgid)
{
	int r;
	struct pollfd fds[1];
	struct timespec to;
	struct timespec t;
	int32_t ms;
	struct bxt_req *req;

	assert(client);
	assert(client->fd >= 0);

	fds[0].fd = client->fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	clock_gettime(CLOCK_MONOTONIC, &t);
	to.tv_sec = t.tv_sec + 5; /* TIMEOUT 5 seconds */
	to.tv_nsec = t.tv_nsec;

	ms = TS_SUB(&to, &t);

	while (ms > 0) {
		r = poll(fds, 1, ms);
		switch (r) {
		case -1:
			bxt_err("wait response: poll: fd %d errno %d",
					client->fd, errno);
			break;
		case 0:
			bxt_err("wait response: poll: fd %d timeout",
					client->fd);
			errno = ETIMEDOUT;
			r = -1;
			break;
		default:
			r = proc_msg(client);
			break;
		}

		/* poll or proc error */
		if (r == -1)
			return -1;

		req = g_hash_table_lookup(client->req_cbs,
				GUINT_TO_POINTER(msgid));
		/* req is processed */
		if (!req)
			return 0;

		clock_gettime(CLOCK_MONOTONIC, &t);
		ms = TS_SUB(&to, &t);
	}

	bxt_err("wait response: timeout");

	return -1;
}

static void free_req(struct bxt_req *req)
{
	if (!req)
		return;

	layer_unref(req->layer);
	free(req->key);
	free(req);
}

static int send_req(struct buxton_client *client, const struct request *rqst)
{
	int r;
	uint8_t *data;
	int len;

	assert(client);
	assert(rqst);

	if (client->fd == -1) {
		errno = ENOTCONN;
		return -1;
	}

	r = serialz_request(rqst, &data, &len);
	if (r == -1) {
		bxt_err("send req: serialize errno %d", errno);
		return -1;
	}

	r = proto_send(client->fd, rqst->type, data, len);
	if (r == -1)
		bxt_err("send req: errno %d", errno);

	free(data);

	return r;
}

static struct bxt_req *set_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	if (!client || !layer || !key || !*key || !val || !callback) {
		errno = EINVAL;
		return NULL;
	}

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = MSG_SET;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;
	rqst.val = (struct buxton_value *)val;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_set_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data)
{
	struct bxt_req *req;

	req = set_value(client, layer, key, val, callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void set_value_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;
}

EXPORT int buxton_set_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const struct buxton_value *val)
{
	int r;
	struct bxt_req *req;
	struct response resp;

	memset(&resp, 0, sizeof(resp));

	req = set_value(client, layer, key, val, set_value_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	return 0;
}

static struct bxt_req *get_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	if (!client || !layer || !key || !*key || !callback) {
		errno = EINVAL;
		return NULL;
	}

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = MSG_GET;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_get_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data)
{
	struct bxt_req *req;

	req = get_value(client, layer, key, callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void get_value_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;

	if (!status)
		resp->val = buxton_value_duplicate(val);
}

EXPORT int buxton_get_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		struct buxton_value **val)
{
	int r;
	struct bxt_req *req;
	struct response resp;

	if (!val) {
		errno = EINVAL;
		return -1;
	}

	memset(&resp, 0, sizeof(resp));

	req = get_value(client, layer, key, get_value_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	*val = resp.val;

	return 0;
}

static struct bxt_req *list_keys(struct buxton_client *client,
		const struct buxton_layer *layer,
		buxton_list_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	if (!client || !layer || !callback) {
		errno = EINVAL;
		return NULL;
	}

	req = create_req(layer, NULL, NULL, callback, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = MSG_LIST;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_list_keys(struct buxton_client *client,
		const struct buxton_layer *layer,
		buxton_list_callback callback, void *user_data)
{
	struct bxt_req *req;

	req = list_keys(client, layer, callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void list_keys_sync_cb(int status, const struct buxton_layer *layer,
		char * const *names, unsigned int len, void *user_data)
{
	struct response *resp = user_data;
	char **nms;
	char **_names;
	int i;

	assert(resp);

	resp->res = status;

	if (resp->res)
		return;

	nms = calloc(len + 1, sizeof(void *));
	if (!nms) {
		resp->res = ENOMEM;
		return;
	}

	/* steal allocated names */
	_names = (char **)names;
	for (i = 0; i < len; i++) {
		nms[i] = _names[i];
		_names[i] = NULL;
	}
	nms[i] = NULL; /* NULL-terminated */

	resp->names = nms;
	resp->nmlen = len;
}

EXPORT int buxton_list_keys_sync(struct buxton_client *client,
		const struct buxton_layer *layer,
		char ***names, unsigned int *len)
{
	int r;
	struct bxt_req *req;
	struct response resp;

	if (!names) {
		errno = EINVAL;
		return -1;
	}

	memset(&resp, 0, sizeof(resp));

	req = list_keys(client, layer, list_keys_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	*names = resp.names;

	if (len)
		*len = resp.nmlen;

	return 0;
}

static gboolean call_resp_cb(gpointer data)
{
	struct bxt_noti_res *res = data;

	assert(res);
	assert(res->callback);

	res->callback(res->res, res->layer, res->key, NULL, res->data);

	layer_unref(res->layer);
	free(res->key);
	free(res);

	return G_SOURCE_REMOVE;
}

static int call_resp(int status, const struct buxton_layer *layer,
		const char *key, buxton_response_callback callback,
		void *user_data)
{
	struct bxt_noti_res *res;

	assert(layer);
	assert(key);
	assert(callback);

	res = calloc(1, sizeof(*res));
	if (!res)
		return -1;

	res->key = strdup(key);
	if (!res->key) {
		free(res);
		return -1;
	}

	res->layer = layer_ref((struct buxton_layer *)layer);
	res->res = status;
	res->callback = callback;
	res->data = user_data;

	g_idle_add(call_resp_cb, res);

	return 0;
}

static struct bxt_req *register_noti(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify, void *notify_data,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	assert(client);
	assert(layer);
	assert(key && *key);
	assert(notify);
	assert(callback);

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	req->notify = notify;
	req->notify_data = notify_data;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = MSG_NOTIFY;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_register_notification(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify, void *notify_data,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_noti *noti;
	struct bxt_req *req;

	if (!client || !layer || !key || !*key || !notify || !callback) {
		errno = EINVAL;
		return -1;
	}

	r = find_noti(client, layer, key, &noti);
	if (r == -1)
		return -1;

	if (noti && noti->reg == TRUE) {
		r = add_noticb(noti, notify, notify_data);
		return call_resp(r == -1 ? errno : 0, layer, key,
				callback, user_data);
	}

	req = register_noti(client, layer, key, notify, notify_data, callback,
			user_data);
	if (!req)
		return -1;

	return 0;
}

static void reg_noti_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;
}

EXPORT int buxton_register_notification_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify, void *notify_data)
{
	int r;
	struct bxt_noti *noti;
	struct bxt_req *req;
	struct response resp;

	if (!client || !layer || !key || !*key || !notify) {
		errno = EINVAL;
		return -1;
	}

	r = find_noti(client, layer, key, &noti);
	if (r == -1)
		return -1;

	if (noti && noti->reg == TRUE)
		return add_noticb(noti, notify, notify_data);

	memset(&resp, 0, sizeof(resp));

	req = register_noti(client, layer, key, notify, notify_data,
			reg_noti_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	return 0;
}

static gboolean del_noticb_cb(gpointer data)
{
	struct bxt_noti *noti = data;
	struct bxt_noti_cb *noticb;
	GList *l;
	GList *ll;

	assert(noti);

	for (l = noti->callbacks, ll = g_list_next(l); l;
			l = ll, ll = g_list_next(ll)) {
		noticb = l->data;

		if (noticb->deleted) {
			noti->callbacks = g_list_delete_link(noti->callbacks,
					l);
			free(noticb);
		}
	}

	noti->id = 0;

	return G_SOURCE_REMOVE;
}

static int del_noticb(struct bxt_noti *noti, buxton_notify_callback notify,
		int *count)
{
	GList *l;
	gboolean f;
	int cnt;

	assert(noti);
	assert(notify);

	cnt = 0;
	f = FALSE;
	for (l = noti->callbacks; l; l = g_list_next(l)) {
		struct bxt_noti_cb *noticb = l->data;

		if (noticb->callback == notify) {
			f = TRUE;
			noticb->deleted = TRUE;
			if (!noti->id)
				noti->id = g_idle_add(del_noticb_cb, noti);
		}

		if (noticb->deleted == FALSE)
			cnt++;
	}

	if (!f) {
		errno = ENOENT;
		return -1;
	}

	if (count)
		*count = cnt;

	return 0;
}

static struct bxt_req *unregister_noti(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	assert(client);
	assert(layer);
	assert(key && *key);
	assert(callback);

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = MSG_UNNOTIFY;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_unregister_notification(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_noti *noti;
	struct bxt_req *req;
	int cnt;

	if (!client || !layer || !key || !*key || !notify || !callback) {
		errno = EINVAL;
		return -1;
	}

	r = find_noti(client, layer, key, &noti);
	if (r == -1)
		return -1;

	if (!noti) {
		errno = ENOENT;
		return -1;
	}

	r = del_noticb(noti, notify, &cnt);
	if (r == -1)
		return call_resp(errno, layer, key, callback, user_data);

	if (cnt || noti->reg == FALSE)
		return call_resp(0, layer, key, callback, user_data);

	req = unregister_noti(client, layer, key, callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void unreg_noti_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;
}

EXPORT int buxton_unregister_notification_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_notify_callback notify)
{
	int r;
	struct bxt_noti *noti;
	struct bxt_req *req;
	int cnt;
	struct response resp;

	if (!client || !layer || !key || !*key || !notify) {
		errno = EINVAL;
		return -1;
	}

	r = find_noti(client, layer, key, &noti);
	if (r == -1)
		return -1;

	if (!noti) {
		errno = ENOENT;
		return -1;
	}

	r = del_noticb(noti, notify, &cnt);
	if (r == -1)
		return -1;

	if (cnt || noti->reg == FALSE)
		return 0;

	memset(&resp, 0, sizeof(resp));

	req = unregister_noti(client, layer, key, unreg_noti_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	return 0;
}

static struct bxt_req *create_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const char *read_privilege, const char *write_privilege,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	if (!client || !layer || !key || !*key || !read_privilege
			|| !write_privilege || !val || !callback) {
		errno = EINVAL;
		return NULL;
	}

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = MSG_CREAT;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;
	rqst.rpriv = (char *)read_privilege;
	rqst.wpriv = (char *)write_privilege;
	rqst.val = (struct buxton_value *)val;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_create_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const char *read_privilege, const char *write_privilege,
		const struct buxton_value *val,
		buxton_response_callback callback, void *user_data)
{
	struct bxt_req *req;

	req = create_value(client, layer, key, read_privilege, write_privilege,
			val, callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void create_value_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;
}

EXPORT int buxton_create_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		const char *read_privilege, const char *write_privilege,
		const struct buxton_value *val)
{
	int r;
	struct bxt_req *req;
	struct response resp;

	memset(&resp, 0, sizeof(resp));

	req = create_value(client, layer, key, read_privilege, write_privilege,
			val, create_value_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	return 0;
}

static struct bxt_req *unset_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	if (!client || !layer || !key || !*key || !callback) {
		errno = EINVAL;
		return NULL;
	}

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = MSG_UNSET;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_unset_value(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		buxton_response_callback callback, void *user_data)
{
	struct bxt_req *req;

	req = unset_value(client, layer, key, callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void unset_value_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;
}

EXPORT int buxton_unset_value_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key)
{
	int r;
	struct bxt_req *req;
	struct response resp;

	memset(&resp, 0, sizeof(resp));

	req = unset_value(client, layer, key, unset_value_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	return 0;
}

static struct bxt_req *set_priv(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		const char *privilege,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;
	struct buxton_value val;

	if (!client || !layer || !key || !*key || !privilege || !callback) {
		errno = EINVAL;
		return NULL;
	}

	if (type <= BUXTON_PRIV_UNKNOWN || type >= BUXTON_PRIV_MAX) {
		errno = EINVAL;
		return NULL;
	}

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = type == BUXTON_PRIV_READ ? MSG_SET_RP : MSG_SET_WP;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;
	rqst.val = &val;

	val.type = BUXTON_TYPE_PRIVILEGE;
	val.value.s = (char *)privilege;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_set_privilege(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		const char *privilege,
		buxton_response_callback callback, void *user_data)
{
	struct bxt_req *req;

	req = set_priv(client, layer, key, type, privilege,
			callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void set_priv_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;
}

EXPORT int buxton_set_privilege_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		const char *privilege)
{
	int r;
	struct bxt_req *req;
	struct response resp;

	memset(&resp, 0, sizeof(resp));

	req = set_priv(client, layer, key, type, privilege,
			set_priv_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	return 0;
}

static struct bxt_req *get_priv(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		buxton_response_callback callback, void *user_data)
{
	int r;
	struct bxt_req *req;
	struct request rqst;

	if (!client || !layer || !key || !*key || !callback) {
		errno = EINVAL;
		return NULL;
	}

	if (type <= BUXTON_PRIV_UNKNOWN || type >= BUXTON_PRIV_MAX) {
		errno = EINVAL;
		return NULL;
	}

	req = create_req(layer, key, callback, NULL, user_data);
	if (!req)
		return NULL;

	memset(&rqst, 0, sizeof(rqst));
	rqst.type = type == BUXTON_PRIV_READ ? MSG_GET_RP : MSG_GET_WP;
	rqst.msgid = req->msgid;
	rqst.layer = req->layer;
	rqst.key = (char *)key;

	r = send_req(client, &rqst);
	if (r == -1) {
		free_req(req);
		return NULL;
	}

	g_hash_table_insert(client->req_cbs, GUINT_TO_POINTER(req->msgid), req);

	return req;
}

EXPORT int buxton_get_privilege(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		buxton_response_callback callback, void *user_data)
{
	struct bxt_req *req;

	req = get_priv(client, layer, key, type, callback, user_data);
	if (!req)
		return -1;

	return 0;
}

static void get_priv_sync_cb(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val,
		void *user_data)
{
	struct response *resp = user_data;

	assert(resp);

	resp->res = status;

	if (!status)
		resp->val = buxton_value_duplicate(val);
}

EXPORT int buxton_get_privilege_sync(struct buxton_client *client,
		const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type,
		char **privilege)
{
	int r;
	struct bxt_req *req;
	struct response resp;

	if (!privilege) {
		errno = EINVAL;
		return -1;
	}

	memset(&resp, 0, sizeof(resp));

	req = get_priv(client, layer, key, type, get_priv_sync_cb, &resp);
	if (!req)
		return -1;

	r = wait_msg(client, req->msgid);
	if (r == -1)
		return -1;

	if (resp.res) {
		errno = resp.res;
		return -1;
	}

	*privilege = resp.val->value.s;
	resp.val->value.s = NULL;
	buxton_value_free(resp.val);

	return 0;
}

static void free_noti(struct bxt_noti *noti)
{
	if (!noti)
		return;

	g_list_free_full(noti->callbacks, (GDestroyNotify)free);

	if (noti->id) {
		g_source_remove(noti->id);
		noti->id = 0;
	}

	free(noti->layer_key);
	free(noti);
}

static gboolean close_conn(gpointer data)
{
	struct buxton_client *cli = data;

	assert(cli);

	if (cli->fd == -1)
		return G_SOURCE_REMOVE;

	if (cli->fd_id) {
		g_source_remove(cli->fd_id);
		cli->fd_id = 0;
	}

	close(cli->fd);
	cli->fd = -1;
	if (cli->st_callback)
		cli->st_callback(BUXTON_STATUS_DISCONNECTED, cli->st_data);

	return G_SOURCE_REMOVE;
}

static void free_client(struct buxton_client *cli)
{
	if (!cli)
		return;

	clients = g_list_remove(clients, cli);

	if (cli->req_cbs)
		g_hash_table_destroy(cli->req_cbs);

	if (cli->noti_cbs)
		g_hash_table_destroy(cli->noti_cbs);

	close_conn(cli);

	free(cli);
}

int connect_server(const char *addr)
{
	int fd;
	struct sockaddr_un sa;
	int r;

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		bxt_err("connect: socket errno %d", errno);
		return -1;
	}

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, addr, sizeof(sa.sun_path));
	sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

	r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r == -1) {
		if (errno == ENOENT)
			bxt_dbg("connect: '%s' not exist", addr);
		else
			bxt_err("connect: connect errno %d", errno);
		close(fd);
		return -1;
	}

	return fd;
}

static gboolean recv_cb(gint fd, GIOCondition cond, gpointer data)
{
	struct buxton_client *cli = data;
	int r;

	assert(cli);

	bxt_dbg("recv %d: cond %x", fd, cond);

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		bxt_err("recv %d: IO cond %x errno %d", fd, cond, errno);

		cli->fd_id = 0;
		g_idle_add(close_conn, cli);
		return G_SOURCE_REMOVE;
	}

	r = proc_msg(cli);
	if (r == -1) {
		cli->fd_id = 0;
		g_idle_add(close_conn, cli);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

EXPORT int buxton_close(struct buxton_client *client)
{
	GList *l;

	if (!client) {
		errno = EINVAL;
		return -1;
	}

	l = g_list_find(clients, client);
	if (!l) {
		errno = ENOENT;
		return -1;
	}

	free_client(client);

	return 0;
}

EXPORT int buxton_open(struct buxton_client **client,
		buxton_status_callback callback, void *user_data)
{
	struct buxton_client *cli;

	if (!client) {
		errno = EINVAL;
		return -1;
	}

	cli = calloc(1, sizeof(*cli));
	if (!cli)
		return -1;

	cli->fd = -1;
	cli->st_callback = callback;
	cli->st_data = user_data;

	cli->req_cbs = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, (GDestroyNotify)free_req);
	if (!cli->req_cbs) {
		free_client(cli);
		errno = ENOMEM;
		return -1;
	}

	cli->noti_cbs = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)free_noti);
	if (!cli->noti_cbs) {
		free_client(cli);
		errno = ENOMEM;
		return -1;
	}

	cli->fd = connect_server(SOCKPATH);
	if (cli->fd == -1) {
		free_client(cli);
		return -1;
	}

	cli->fd_id = g_unix_fd_add(cli->fd,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			recv_cb, cli);

	clients = g_list_append(clients, cli);
	*client = cli;

	if (callback)
		callback(BUXTON_STATUS_CONNECTED, user_data);

	return 0;
}

__attribute__((destructor))
static void buxton_client_exit(void)
{
	GList *l;
	GList *n;

	for (l = clients, n = g_list_next(l); l; l = n, n = g_list_next(n))
		free_client(l->data);

	clients = NULL;
}

