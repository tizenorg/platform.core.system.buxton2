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

#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <glib.h>
#include <glib-unix.h>
#include <cynara-client-async.h>

#include "log.h"

#include "cynara.h"

#define BUXTON_CYNARA_PERMISSIVE_MODE "BUXTON_CYNARA_PERMISSIVE_MODE"

struct bxt_cyn_cb {
	cynara_check_id id;

	struct bxt_client *cli;
	buxton_cynara_callback callback;
	void *user_data;
};

static cynara_async *cynara;
static int cynara_fd = -1;
static guint cynara_fd_id;
static gboolean cynara_skip;
static GHashTable *cynara_tbl;

static void cyn_err(const char *prefix, int err)
{
	char errmsg[128];

	errmsg[0] = '\0';
	cynara_strerror(err, errmsg, sizeof(errmsg));
	bxt_err("Cynara: %s%s%d : %s", prefix ? prefix : "", prefix ? ": " : "",
			err, errmsg);
}

static void free_cb(gpointer data)
{
	struct bxt_cyn_cb *cyn_cb = data;

	if (!cyn_cb)
		return;

	if (cyn_cb->callback) {
		if (cynara) {
			int r;

			r = cynara_async_cancel_request(cynara, cyn_cb->id);
			if (r != CYNARA_API_SUCCESS)
				cyn_err("cancel", r);
		}

		cyn_cb->callback(cyn_cb->cli, BUXTON_CYNARA_CANCELED,
				cyn_cb->user_data);
	}

	free(cyn_cb);
	bxt_dbg("Cynara: free %p", cyn_cb);
}

static gboolean proc_cb(gint fd, GIOCondition cond, gpointer data)
{
	int r;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		cynara_fd_id = 0;
		return G_SOURCE_REMOVE;
	}

	r = cynara_async_process(cynara);
	if (r != CYNARA_API_SUCCESS)
		cyn_err("process", r);

	return G_SOURCE_CONTINUE;
}

static void status_cb(int old_fd, int new_fd, cynara_async_status status,
		void *data)
{
	if (old_fd != -1) {
		if (cynara_fd_id) {
			g_source_remove(cynara_fd_id);
			cynara_fd_id = 0;
		}
		cynara_fd = -1;
	}

	if (new_fd != -1) {
		GIOCondition cond;

		cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;

		if (status == CYNARA_STATUS_FOR_RW)
			cond |= G_IO_OUT;

		cynara_fd_id = g_unix_fd_add(new_fd, cond, proc_cb, data);
		cynara_fd = new_fd;
	}
}

static enum buxton_cynara_res check_cache(const char *clabel, const char *sess,
		const char *uid, const char *priv)
{
	int r;

	assert(cynara);
	assert(clabel);
	assert(sess);
	assert(uid);
	assert(priv);

	r = cynara_async_check_cache(cynara, clabel, sess, uid, priv);
	switch (r) {
	case CYNARA_API_ACCESS_ALLOWED:
		r = BUXTON_CYNARA_ALLOWED;
		break;
	case CYNARA_API_ACCESS_DENIED:
		r = BUXTON_CYNARA_DENIED;
		break;
	case CYNARA_API_CACHE_MISS:
		r = BUXTON_CYNARA_UNKNOWN;
		break;
	default:
		cyn_err("cache", r);
		r = BUXTON_CYNARA_UNKNOWN;
		break;
	}

	return r;
}

static void resp_cb(cynara_check_id id, cynara_async_call_cause cause,
		int resp, void *data)
{
	struct bxt_cyn_cb *cyn_cb;
	enum buxton_cynara_res res;

	bxt_dbg("check id %u, cause %d, resp %d", id, cause, resp);

	if (!cynara_tbl)
		return;

	cyn_cb = g_hash_table_lookup(cynara_tbl, GUINT_TO_POINTER(id));
	if (!cyn_cb || cyn_cb != data) {
		bxt_err("Cynara: resp: %u not exist in table", id);
		return;
	}

	switch (cause) {
	case CYNARA_CALL_CAUSE_ANSWER:
		if (resp == CYNARA_API_ACCESS_ALLOWED)
			res = BUXTON_CYNARA_ALLOWED;
		else
			res = BUXTON_CYNARA_DENIED;
		break;
	case CYNARA_CALL_CAUSE_CANCEL:
	case CYNARA_CALL_CAUSE_FINISH:
	case CYNARA_CALL_CAUSE_SERVICE_NOT_AVAILABLE:
	default:
		bxt_err("Cynara: resp: not answer");
		res = BUXTON_CYNARA_ERROR;
		break;
	}

	if (res == BUXTON_CYNARA_DENIED) {
		bxt_info("id %u denied%s", id,
				cynara_skip ? "(ignored)" : "");
		if (cynara_skip)
			res = BUXTON_CYNARA_ALLOWED;
	}

	if (cyn_cb->callback) {
		cyn_cb->callback(cyn_cb->cli, res, cyn_cb->user_data);
		cyn_cb->callback = NULL;
	}
	g_hash_table_remove(cynara_tbl, GUINT_TO_POINTER(id));
}

static enum buxton_cynara_res check_server(struct bxt_client *client,
		const char *clabel, const char *sess,
		const char *uid, const char *priv,
		buxton_cynara_callback callback, void *user_data)
{
	int r;
	struct bxt_cyn_cb *cyn_cb;

	assert(cynara);
	assert(cynara_tbl);

	assert(client);
	assert(clabel);
	assert(sess);
	assert(uid);
	assert(priv);
	assert(callback);

	cyn_cb = calloc(1, sizeof(*cyn_cb));
	if (!cyn_cb)
		return BUXTON_CYNARA_ERROR;

	r = cynara_async_create_request(cynara, clabel, sess, uid, priv,
			&cyn_cb->id, resp_cb, cyn_cb);
	if (r != CYNARA_API_SUCCESS) {
		cyn_err("request", r);
		free(cyn_cb);
		return BUXTON_CYNARA_ERROR;
	}

	bxt_info("'%s;%s;%s;%s' id %u", clabel, sess, uid, priv, cyn_cb->id);

	cyn_cb->cli = client;
	cyn_cb->callback = callback;
	cyn_cb->user_data = user_data;

	g_hash_table_insert(cynara_tbl, GUINT_TO_POINTER(cyn_cb->id), cyn_cb);
	bxt_dbg("Cynara: %p added", cyn_cb);

	return BUXTON_CYNARA_UNKNOWN;
}

enum buxton_cynara_res buxton_cynara_check(struct bxt_client *client,
		const char *client_label, const char *session,
		uid_t uid, const char *priv,
		buxton_cynara_callback callback, void *user_data)
{
	int r;
	char uid_str[16];

	if (!client || !client_label || !session || !priv || !callback) {
		errno = EINVAL;
		bxt_err("cynara check: invalid argument:%s%s%s%s%s",
				client ? "" : " client",
				client_label ? "" : " client_label",
				session ? "" : " session",
				priv ? "" : " privilege",
				callback ? "" : " callback");
		return BUXTON_CYNARA_ERROR;
	}

	if (!*priv)
		return BUXTON_CYNARA_ALLOWED;

	if (!cynara) {
		bxt_err("Cynara is not initialized");
		errno = ENOTCONN;
		return BUXTON_CYNARA_ERROR;
	}

	snprintf(uid_str, sizeof(uid_str), "%d", uid);

	r = check_cache(client_label, session, uid_str, priv);
	if (r != BUXTON_CYNARA_UNKNOWN) {
		/* r should be ALLOWED or DENIED */
		if (r == BUXTON_CYNARA_DENIED) {
			bxt_info("'%s;%s;%s;%s' denied%s",
					client_label, session, uid_str, priv,
					cynara_skip ? "(ignored)" : "");
			if (cynara_skip)
				r = BUXTON_CYNARA_ALLOWED;
		}
		return r;
	}

	return check_server(client, client_label, session, uid_str, priv,
			callback, user_data);
}

void buxton_cynara_cancel(struct bxt_client *client)
{
	GHashTableIter iter;
	struct bxt_cyn_cb *cyn_cb;

	if (!cynara || !cynara_tbl || !client)
		return;

	g_hash_table_iter_init(&iter, cynara_tbl);

	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&cyn_cb)) {
		if (cyn_cb->cli == client)
			g_hash_table_iter_remove(&iter);
	}
}

int buxton_cynara_init(void)
{
	int r;
	char *skip;

	if (cynara)
		return 0;

	skip = getenv(BUXTON_CYNARA_PERMISSIVE_MODE);
	if (skip && skip[0] == '1') {
		bxt_info("Permissive mode enabled");
		cynara_skip = TRUE;
	}

	cynara_tbl = g_hash_table_new_full(NULL, NULL, NULL, free_cb);
	if (!cynara_tbl)
		return -1;

	r = cynara_async_initialize(&cynara, NULL, status_cb, NULL);
	if (r != CYNARA_API_SUCCESS) {
		cyn_err("init", r);
		return -1;
	}

	return 0;
}

void buxton_cynara_exit(void)
{
	if (!cynara)
		return;

	if (cynara_fd_id) {
		g_source_remove(cynara_fd_id);
		cynara_fd_id = 0;
	}

	g_hash_table_destroy(cynara_tbl);
	cynara_tbl = NULL;

	cynara_async_finish(cynara);
	cynara = NULL;
	cynara_fd = -1;
}

