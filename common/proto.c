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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <poll.h>
#include <pthread.h>

#include "common.h"
#include "log.h"
#include "proto.h"

#define SEND_TIMEOUT_MSEC 1000
#define SEND_PACKET_MAX 8192

struct recv_info {
	int fd;

	recv_callback callback;
	void *user_data;

	enum message_type type;
	uint8_t *data;
	int32_t len;

	int32_t recved;
};

static GList *recv_list;
static pthread_mutex_t recv_lock = PTHREAD_MUTEX_INITIALIZER;

static struct recv_info *find_rif(int fd)
{
	GList *l;

	for (l = recv_list; l; l = g_list_next(l)) {
		if (((struct recv_info *)l->data)->fd == fd)
			return l->data;
	}

	return NULL;
}

static int recv_first(int fd, recv_callback callback, void *user_data)
{
	int r;
	struct recv_info *rif;
	uint32_t hdr;

	rif = calloc(1, sizeof(*rif));
	if (!rif)
		return -1;

	rif->fd = fd;
	rif->callback = callback;
	rif->user_data = user_data;

	r = recv(fd, &hdr, sizeof(uint32_t), 0);
	if (r <= 0) {
		free(rif);
		if (r == 0) {
			bxt_dbg("recv: fd %d closed", fd);
		} else {
			if (errno == EAGAIN)
				return 0;

			bxt_err("recv: fd %d errno %d", fd, errno);
		}

		return -1;
	}

	rif->type = hdr >> 24;
	rif->len = hdr & 0xffffff;
	if (rif->len == 0) {
		free(rif);
		bxt_err("recv: fd %d invalid header %x", fd, hdr);
		return -1;
	}

	rif->data = malloc(rif->len);
	if (!rif->data) {
		free(rif);
		return -1;
	}

	recv_list = g_list_append(recv_list, rif);

	bxt_dbg("rif %p type %d len %d added", rif, rif->type, rif->len);

	return 0;

}

static void remove_rif(struct recv_info *rif)
{
	if (!rif)
		return;

	recv_list = g_list_remove(recv_list, rif);
	free(rif->data);
	free(rif);
}

static int recv_cont(struct recv_info *rif)
{
	int r;

	assert(rif);

	r = recv(rif->fd, &rif->data[rif->recved], rif->len - rif->recved, 0);
	if (r <= 0) {
		if (r == 0) {
			bxt_dbg("recv: fd %d closed", rif->fd);
		} else {
			if (errno == EAGAIN)
				return 0;

			bxt_err("recv: fd %d errno %d", rif->fd, errno);
		}

		remove_rif(rif);
		return -1;
	}
	rif->recved += r;

	if (rif->recved > rif->len) {
		bxt_err("recv: fd %d expected %d > received %d", rif->fd,
				rif->len, rif->recved);
		remove_rif(rif);
		return -1;
	}

	if (rif->recved == rif->len) {
		bxt_dbg("rif %p received %d / %d", rif, rif->recved, rif->len);

		assert(rif->callback);
		recv_list = g_list_remove(recv_list, rif);
		pthread_mutex_unlock(&recv_lock);
		rif->callback(rif->user_data, rif->type, rif->data, rif->len);
		pthread_mutex_lock(&recv_lock);
		remove_rif(rif);
	}

	return 0;
}

int proto_recv_frag(int fd, recv_callback callback, void *user_data)
{
	int r;
	struct recv_info *rif;

	if (fd < 0 || !callback) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&recv_lock);
	rif = find_rif(fd);
	if (!rif)
		r = recv_first(fd, callback, user_data);
	else
		r = recv_cont(rif);
	pthread_mutex_unlock(&recv_lock);

	return r;
}


int proto_send_block(int fd, enum message_type type, uint8_t *data, int32_t len)
{
	int r;
	uint32_t hdr;
	int sent;
	struct pollfd fds[1];
	int s;

	if (fd < 0 || !data || len <= 0) {
		errno = EINVAL;
		return -1;
	}

	bxt_dbg("send: fd %d type %d len %d start", fd, type, len);
	hdr = (type << 24) | (len & 0xffffff);

	r = send(fd, &hdr, sizeof(uint32_t), 0);
	if (r == -1) {
		bxt_err("send: fd %d errno %d", fd, errno);
		return -1;
	}

	sent = 0;
	while (len > sent) {
		fds[0].fd = fd;
		fds[0].events = POLLOUT;
		fds[0].revents = 0;

		/* CAN BE BLOCKED ! */
		r = poll(fds, 1, SEND_TIMEOUT_MSEC);
		if (r == -1) {
			bxt_err("send: fd %d poll errno %d", fd, errno);
			return -1;
		}
		if (r == 0) {
			bxt_err("send: fd %d timeout", fd);
			return -1;
		}

		s = len - sent;
		if (s > SEND_TIMEOUT_MSEC)
			s = SEND_TIMEOUT_MSEC;

		r = send(fd, &data[sent], s, 0);
		if (r == -1) {
			bxt_err("send: fd %d errno %d", fd, errno);
			return -1;
		}

		sent += r;
	}
	bxt_dbg("send: fd %d sent %d", fd, sent);

	return 0;
}

int proto_send(int fd, enum message_type type, uint8_t *data, int32_t len)
{
	int r;
	uint32_t hdr;
	uint8_t *buf;

	assert(fd >= 0);
	assert(data);
	assert(len > 0);

	buf = malloc(len + sizeof(uint32_t));
	if (!buf) {
		bxt_err("send: send buffer alloc error");
		return -1;
	}

	hdr = (type << 24) | (len & 0xffffff);

	memcpy(buf, &hdr, sizeof(uint32_t));
	memcpy(buf + sizeof(uint32_t), data, len);

	r = send(fd, buf, len + sizeof(uint32_t), 0);

	free(buf);

	if (r == -1) {
		bxt_err("send: fd %d errno %d", fd, errno);
		return -1;
	}

	if (r != len + sizeof(uint32_t))
		bxt_err("send: %d / %d byte", r,
				(int32_t)(len + sizeof(uint32_t)));

	return 0;
}

int proto_recv(int fd, enum message_type *type, uint8_t **data, int32_t *len)
{
	int r;
	uint32_t hdr;
	uint8_t *_data;
	int32_t _len;
	enum message_type _type;

	assert(fd >= 0);
	assert(type);
	assert(data);
	assert(len);

	r = recv(fd, &hdr, sizeof(uint32_t), 0);
	if (r <= 0) {
		if (r == 0)
			bxt_dbg("recv: fd %d closed", fd);
		else
			bxt_err("recv: fd %d errno %d", fd, errno);

		return -1;
	}

	_type = hdr >> 24;
	_len = hdr & 0xffffff;

	if (_len == 0) {
		bxt_err("recv: fd %d Invalid message", fd);
		return -1;
	}

	_data = malloc(_len);
	if (!_data) {
		/* flush ? */
		return -1;
	}

	r = recv(fd, _data, _len, 0);
	if (r <= 0) {
		if (r == 0)
			bxt_dbg("recv: fd %d closed", fd);
		else
			bxt_err("recv: fd %d errno %d", fd, errno);

		free(_data);

		return -1;
	}

	if (r != _len) {
		bxt_err("recv: fd %d expect size %d > received %d",
				fd, _len, r);
		free(_data);
		return -1;
	}

	*type = _type;
	*data = _data;
	*len = _len;

	return 0;
}
