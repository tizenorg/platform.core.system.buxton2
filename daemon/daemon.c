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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <string.h>

#include <glib.h>
#include <glib-unix.h>

#include "common.h"
#include "log.h"
#include "direct.h"
#include "proto.h"
#include "serialize.h"
#include "config.h"

#include "daemon.h"
#include "socks.h"
#include "cynara.h"
#include "dbus.h"

struct bxt_noti {
	char *layer_key;
	GList *clients; /* struct bxt_client */
};

static gboolean signal_cb(gint fd, GIOCondition cond, gpointer data)
{
	struct bxt_daemon *bxtd = data;
	int r;
	struct signalfd_siginfo si;

	assert(bxtd);

	r = read(fd, &si, sizeof(struct signalfd_siginfo));
	if (r == -1) {
		bxt_err("Read signalfd: %d", errno);
		return G_SOURCE_REMOVE;
	}

	if (r != sizeof(struct signalfd_siginfo)) {
		bxt_err("Invalid siginfo received");
		return G_SOURCE_CONTINUE;
	}

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		assert(bxtd->loop);
		g_main_loop_quit(bxtd->loop);
		break;
	case SIGPIPE:
		/* Ignore signal */
		break;
	}

	return G_SOURCE_CONTINUE;
}

static int create_sigfd(void)
{
	int r;
	int fd;
	sigset_t mask;
	sigset_t old;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGPIPE);

	r = sigprocmask(SIG_BLOCK, &mask, &old);
	if (r == -1) {
		bxt_err("sigprocmask: %d", errno);
		return -1;
	}

	fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (fd == -1) {
		bxt_err("signalfd: %d", errno);
		sigprocmask(SIG_SETMASK, &old, NULL);
		return -1;
	}

	return fd;
}

static void remove_noti_cli(struct bxt_daemon *bxtd, struct bxt_client *cli)
{
	GList *l;
	struct bxt_noti *noti;

	for (l = cli->notilist; l; l = g_list_next(l)) {
		noti = l->data;

		noti->clients = g_list_remove(noti->clients, cli);
		bxt_dbg("client %p deleted from noti %p list", cli, noti);

		if (!noti->clients) {
			g_hash_table_remove(bxtd->notis, noti->layer_key);
			bxt_dbg("noti %p deleted from table", noti);
		}
	}
}

static void remove_notilist(struct bxt_noti *noti)
{
	GList *l;
	struct bxt_client *cli;

	for (l = noti->clients; l; l = g_list_next(l)) {
		cli = l->data;

		cli->notilist = g_list_remove(cli->notilist, noti);
		bxt_dbg("noti %p deleted from client %p", noti, cli);
	}
}

static void free_noti(struct bxt_noti *noti)
{
	if (!noti)
		return;

	remove_notilist(noti);
	g_list_free(noti->clients);
	noti->clients = NULL;
	free(noti->layer_key);

	free(noti);
	bxt_dbg("free noti %p", noti);
}

static gboolean del_client(gpointer data)
{
	struct bxt_client *cli = data;

	assert(cli);
	assert(cli->bxtd);
	assert(cli->bxtd->clients);

	buxton_cynara_cancel(cli);

	bxt_dbg("Client %p removed", cli);
	g_hash_table_remove(cli->bxtd->clients, cli);

	return G_SOURCE_REMOVE;
}

static void send_res(struct bxt_client *cli, struct response *resp)
{
	int r;
	uint8_t *data;
	int len;

	r = serialz_response(resp->type, resp->msgid, resp->res, resp->val,
			resp->nmlen, resp->names, &data, &len);
	if (r == -1) {
		bxt_err("send res: fd %d msgid %u: serialize error %d",
				cli->fd, resp->msgid, errno);
		return;
	}

	r = proto_send_block(cli->fd, resp->type, data, len);

	free(data);

	if (r == -1)
		bxt_err("send res: error %d", errno);
}

static char *get_search_key_u(const struct buxton_layer *layer, const char *key)
{
	char uid[16];
	char *u;
	const struct layer *ly;

	ly = conf_get_layer(layer->name);
	if (!ly)
		return NULL;

	if (ly->type == LAYER_USER) {
		snprintf(uid, sizeof(uid), "%d", layer->uid);
		u = uid;
	} else {
		u = NULL;
	}

	return get_search_key(layer, key, u);
}

static void send_notis(struct bxt_daemon *bxtd, struct request *rqst)
{
	int r;
	char *lykey;
	struct bxt_noti *noti;
	GList *l;
	struct request req;
	uint8_t *data;
	int len;

	assert(bxtd);
	assert(rqst);

	lykey = get_search_key_u(rqst->layer, rqst->key);
	if (!lykey)
		return;

	noti = g_hash_table_lookup(bxtd->notis, lykey);

	free(lykey);

	if (!noti)
		return;

	memset(&req, 0, sizeof(req));
	req.type = MSG_NOTI;
	req.layer = rqst->layer;
	req.key = rqst->key;
	req.val = rqst->val;

	r = serialz_request(&req, &data, &len);
	if (r == -1)
		return;

	for (l = noti->clients; l; l = g_list_next(l)) {
		struct bxt_client *cli = l->data;

		r = proto_send(cli->fd, req.type, data, len);
		if (r == -1)
			bxt_err("send notis: cli %p error %d", cli, errno);
	}

	free(data);
}

static void proc_set(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;

	assert(rqst);
	assert(resp);

	r = direct_set(rqst->layer, rqst->key, rqst->val);
	if (r == -1) {
		resp->res = errno;
		return;
	}
	resp->res = 0;

	send_notis(cli->bxtd, rqst);
}

static void proc_get(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;
	struct buxton_value *val;

	assert(rqst);
	assert(resp);

	val = calloc(1, sizeof(*val));
	if (!val) {
		resp->res = ENOMEM;
		return;
	}

	r = direct_get(rqst->layer, rqst->key, val);
	if (r == -1) {
		free(val);
		resp->res = errno;
		return;
	}

	resp->res = 0;
	resp->val = val;
}

static void proc_list(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;

	assert(rqst);
	assert(resp);

	r = direct_list(rqst->layer, &resp->names, &resp->nmlen);
	resp->res = (r == -1) ? errno : 0;
}

static void proc_create(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;

	assert(cli);
	assert(rqst);
	assert(resp);

	if (cli->cred.uid != 0) {
		resp->res = EPERM;
		return;
	}

	r = direct_create(rqst->layer, rqst->key, rqst->rpriv, rqst->wpriv,
			rqst->val);
	resp->res = (r == -1) ? errno : 0;
}

static void proc_unset(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;

	assert(cli);
	assert(rqst);
	assert(resp);

	if (cli->cred.uid != 0) {
		resp->res = EPERM;
		return;
	}

	r = direct_unset(rqst->layer, rqst->key);
	resp->res = (r == -1) ? errno : 0;
}

static void add_cli(struct bxt_noti *noti, struct bxt_client *client)
{
	GList *l;

	for (l = noti->clients; l; l = g_list_next(l)) {
		if (l->data == client)
			return;
	}

	noti->clients = g_list_append(noti->clients, client);
	client->notilist = g_list_append(client->notilist, noti);
	bxt_dbg("proc notify: noti %p '%s' client %p added",
			noti, noti->layer_key, client);
}

static void proc_notify(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;
	char *lykey;
	struct bxt_noti *noti;

	assert(cli);
	assert(rqst);
	assert(resp);

	assert(rqst->layer);
	assert(rqst->key);

	r = direct_check(rqst->layer, rqst->key);
	if (r == -1) {
		resp->res = errno;
		return;
	}

	lykey = get_search_key_u(rqst->layer, rqst->key);
	if (!lykey) {
		resp->res = errno;
		return;
	}

	noti = g_hash_table_lookup(cli->bxtd->notis, lykey);
	if (!noti) {
		noti = calloc(1, sizeof(*noti));
		if (!noti) {
			resp->res = errno;
			return;
		}
		noti->layer_key = lykey;

		g_hash_table_insert(cli->bxtd->notis, noti->layer_key, noti);
		bxt_dbg("proc notify: noti %p '%s' added", noti, lykey);
	} else {
		free(lykey);
	}

	add_cli(noti, cli);
	resp->res = 0;
}

static void proc_unnotify(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	char *lykey;
	struct bxt_noti *noti;

	assert(cli);
	assert(rqst);
	assert(resp);

	assert(rqst->layer);
	assert(rqst->key);

	lykey = get_search_key_u(rqst->layer, rqst->key);
	if (!lykey) {
		resp->res = errno;
		return;
	}

	noti = g_hash_table_lookup(cli->bxtd->notis, lykey);
	if (!noti) {
		free(lykey);
		resp->res = ENOENT;
		return;
	}

	cli->notilist = g_list_remove(cli->notilist, noti);
	noti->clients = g_list_remove(noti->clients, cli);
	bxt_dbg("proc notify: noti %p '%s' client %p deleted",
			noti, noti->layer_key, cli);

	if (!noti->clients) /* no client */
		g_hash_table_remove(cli->bxtd->notis, lykey);

	resp->res = 0;

	free(lykey);
}

static void proc_set_priv(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;
	enum buxton_priv_type type;

	assert(cli);
	assert(rqst);
	assert(resp);

	if (cli->cred.uid != 0) {
		resp->res = EPERM;
		return;
	}

	if (rqst->type == MSG_SET_WP)
		type = BUXTON_PRIV_WRITE;
	else
		type = BUXTON_PRIV_READ;

	r = direct_set_priv(rqst->layer, rqst->key, type, rqst->val->value.s);
	resp->res = (r == -1) ? errno : 0;
}

static void proc_get_priv(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	int r;
	enum buxton_priv_type type;
	struct buxton_value *val;

	assert(rqst);
	assert(resp);

	val = calloc(1, sizeof(*val));
	if (!val) {
		resp->res = ENOMEM;
		return;
	}

	if (rqst->type == MSG_GET_WP)
		type = BUXTON_PRIV_WRITE;
	else
		type = BUXTON_PRIV_READ;

	val->type = BUXTON_TYPE_PRIVILEGE;
	r = direct_get_priv(rqst->layer, rqst->key, type, &val->value.s);
	if (r == -1) {
		free(val);
		resp->res = errno;
		return;
	}

	resp->res = 0;
	resp->val = val;
}

typedef void (*proc_func)(struct bxt_client *cli,
		struct request *, struct response *);

static proc_func proc_funcs[MSG_MAX] = {
	[MSG_SET] = proc_set,
	[MSG_GET] = proc_get,
	[MSG_LIST] = proc_list,
	[MSG_CREAT] = proc_create,
	[MSG_UNSET] = proc_unset,
	[MSG_NOTIFY] = proc_notify,
	[MSG_UNNOTIFY] = proc_unnotify,
	[MSG_SET_WP] = proc_set_priv,
	[MSG_SET_RP] = proc_set_priv,
	[MSG_GET_WP] = proc_get_priv,
	[MSG_GET_RP] = proc_get_priv,
};

static void proc_msg(struct bxt_client *cli,
		struct request *rqst, struct response *resp)
{
	assert(cli);
	assert(rqst);
	assert(resp);

	if (rqst->type <= MSG_UNKNOWN || rqst->type >= MSG_MAX) {
		bxt_err("proc msg: invalid type %d", rqst->type);
		resp->res = EINVAL;
		return;
	}

	assert(rqst->layer);
	if (cli->cred.uid != 0 && cli->cred.uid != rqst->layer->uid) {
		/* Only root can access other user's */
		resp->res = EPERM;
		return;
	}

	if (!proc_funcs[rqst->type]) {
		bxt_err("proc msg: %d not supported", rqst->type);
		resp->res = ENOTSUP;
		return;
	}

	proc_funcs[rqst->type](cli, rqst, resp);
}

static void cyn_cb(struct bxt_client *cli, enum buxton_cynara_res res,
		void *data)
{
	struct request *rqst = data;
	struct response resp;

	assert(rqst);

	memset(&resp, 0, sizeof(resp));
	resp.type = rqst->type;
	resp.msgid = rqst->msgid;

	switch (res) {
	case BUXTON_CYNARA_ALLOWED:
		proc_msg(cli, rqst, &resp);
		break;
	case BUXTON_CYNARA_DENIED:
	default:
		resp.res = EPERM;
		break;
	}

	send_res(cli, &resp);

	free_response(&resp);
	free_request(rqst);
	free(rqst);
}

static int check_priv(struct bxt_client *cli, struct request *rqst)
{
	int r;
	enum buxton_priv_type type;
	char *priv;

	assert(cli);
	assert(rqst);

	switch (rqst->type) {
	case MSG_SET:
	case MSG_GET:
	case MSG_NOTIFY:
		if (rqst->type == MSG_SET)
			type = BUXTON_PRIV_WRITE;
		else
			type = BUXTON_PRIV_READ;

		r = direct_get_priv(rqst->layer, rqst->key, type, &priv);
		if (r == -1) {
			r = BUXTON_CYNARA_ERROR;
			break;
		}

		bxt_dbg("priv '%s'", priv);

		r = buxton_cynara_check(cli, cli->label, "", cli->cred.uid,
				priv, cyn_cb, rqst);
		free(priv);
		break;
	default:
		r = BUXTON_CYNARA_ALLOWED;
		break;
	}

	return r;
}

static int proc_serialized_msg(struct bxt_client *cli, uint8_t *data, int len)
{
	int r;
	struct request *rqst;
	struct response resp;

	rqst = calloc(1, sizeof(*rqst));
	if (!rqst)
		return -1;

	r = deserialz_request(data, len, rqst);
	if (r == -1) {
		free(rqst);
		return -1;
	}

	r = check_priv(cli, rqst);

	/* wait for cynara response, rqst should be freed in callback */
	if (r == BUXTON_CYNARA_UNKNOWN)
		return 0;

	memset(&resp, 0, sizeof(resp));

	resp.type = rqst->type;
	resp.msgid = rqst->msgid;

	if (r != BUXTON_CYNARA_ALLOWED)
		resp.res = r == BUXTON_CYNARA_DENIED ? EPERM : errno;
	else
		proc_msg(cli, rqst, &resp);

	send_res(cli, &resp);

	free_response(&resp);
	free_request(rqst);
	free(rqst);

	return 0;
}

static int proc_client_msg(struct bxt_client *cli)
{
	int r;
	uint8_t *data;
	int len;
	enum message_type type;

	r = proto_recv(cli->fd, &type, &data, &len);
	if (r == -1)
		return -1;

	switch (type) {
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
		r = proc_serialized_msg(cli, data, len);
		break;
	case MSG_NOTI:
	default:
		bxt_err("proc msg: Invalid message type %d", type);
		r = -1;
		break;
	}

	free(data);

	return r;
}

static gboolean client_cb(gint fd, GIOCondition cond, gpointer data)
{
	int r;
	struct bxt_client *cli = data;

	assert(cli);

	bxt_dbg("Client %d: cond %x", fd, cond);

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		if (cond & (G_IO_ERR | G_IO_NVAL))
			bxt_err("Client %d: PID %d(%s) IO %s", fd,
					cli->cred.pid,
					cli->label ? cli->label : "",
					cond & G_IO_ERR ?  "error" : "nval");

		cli->fd_id = 0;
		g_idle_add(del_client, cli);
		return G_SOURCE_REMOVE;
	}

	if (cli->cred.pid == 0) {
		sock_get_client_cred(fd, &cli->cred);
		sock_get_client_label(fd, &cli->label);
	}

	r = proc_client_msg(cli);
	if (r == -1) {
		cli->fd_id = 0;
		g_idle_add(del_client, cli);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static void add_client(struct bxt_daemon *bxtd, int fd)
{
	int r;
	struct bxt_client *cli;

	r = sock_set_client(fd);
	if (r == -1) {
		close(fd);
		return;
	}

	cli = calloc(1, sizeof(*cli));
	if (!cli) {
		bxt_err("Client %d: %d", fd, errno);
		close(fd);
		return;
	}

	cli->fd = fd;
	cli->bxtd = bxtd;

	cli->fd_id = g_unix_fd_add(fd,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			client_cb, cli);

	g_hash_table_insert(bxtd->clients, cli, cli);
	bxt_dbg("Client %p added, fd %d", cli, fd);
}

static gboolean accept_cb(gint fd, GIOCondition cond, gpointer data)
{
	struct bxt_daemon *bxtd = data;
	int cfd;
	struct sockaddr sa;
	socklen_t addrlen;

	assert(bxtd);

	bxt_dbg("Accept: fd %d cond %x", fd, cond);

	addrlen = sizeof(sa);
	cfd = accept(fd, (struct sockaddr *)&sa, &addrlen);
	if (cfd == -1) {
		if (errno == EMFILE) {
			bxt_err("Too many open files, stop calling accept()");
			bxtd->sk_id = 0;
			return G_SOURCE_REMOVE;
		}
		bxt_err("Accept: %d", errno);
		return G_SOURCE_CONTINUE;
	}

	add_client(bxtd, cfd);

	return G_SOURCE_CONTINUE;
}

static void resume_accept(struct bxt_daemon *bxtd)
{
	assert(bxtd);

	if (bxtd->sk_id == 0) {
		bxt_err("Resume calling accept()");
		bxtd->sk_id = g_unix_fd_add(bxtd->sk, G_IO_IN, accept_cb, bxtd);
	}
}

static void free_client(struct bxt_client *cli)
{
	if (!cli)
		return;

	resume_accept(cli->bxtd);

	remove_noti_cli(cli->bxtd, cli);
	g_list_free(cli->notilist);
	cli->notilist = NULL;

	if (cli->fd_id)
		g_source_remove(cli->fd_id);

	if (cli->fd != -1)
		close(cli->fd);

	free(cli->label);
	free(cli);
	bxt_dbg("free client %p", cli);
}

static void bxt_exit(struct bxt_daemon *bxtd)
{
	buxton_cynara_exit();

	if (bxtd->notis)
		g_hash_table_destroy(bxtd->notis);

	if (bxtd->clients)
		g_hash_table_destroy(bxtd->clients);

	if (bxtd->loop)
		g_main_loop_unref(bxtd->loop);

	if (bxtd->sk != -1)
		close(bxtd->sk);

	direct_exit();
	buxton_dbus_exit();

	if (bxtd->sigfd != -1)
		close(bxtd->sigfd);
}

static int bxt_init(struct bxt_daemon *bxtd, const char *confpath)
{
	int r;

	assert(bxtd);

	bxtd->clients = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			(GDestroyNotify)free_client, NULL);
	if (!bxtd->clients)
		return -1;

	bxtd->notis = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)free_noti);
	if (!bxtd->notis)
		return -1;

	bxtd->sigfd = create_sigfd();
	g_unix_fd_add(bxtd->sigfd, G_IO_IN, signal_cb, bxtd);

	r = direct_init(MODULE_DIR, confpath);
	if (r == -1)
		return -1;

	bxtd->sk = sock_get_server(SOCKPATH);
	if (bxtd->sk == -1)
		return -1;

	bxtd->sk_id = g_unix_fd_add(bxtd->sk, G_IO_IN, accept_cb, bxtd);

	buxton_cynara_init();

	r = buxton_dbus_init();
	if (r == -1)
		return -1;

	bxtd->loop = g_main_loop_new(NULL, FALSE);

	return 0;
}

int start_daemon(struct bxt_daemon *bxtd, const char *confpath)
{
	int r;

	assert(bxtd);

	if (!confpath)
		confpath = CONFPATH;

	r = bxt_init(bxtd, confpath);
	if (r == -1) {
		bxt_exit(bxtd);
		return EXIT_FAILURE;
	}

	g_main_loop_run(bxtd->loop);
	bxt_exit(bxtd);

	return EXIT_SUCCESS;
}

