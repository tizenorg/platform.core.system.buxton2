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

#define SEND_TIMEOUT 1000 /* milliseconds */

struct recv_info {
	int fd;
	uint16_t seq;

	recv_callback callback;
	void *user_data;

	enum message_type type;
	int32_t len;

	int32_t recved;
	uint8_t *data;
	uint8_t _data[0];
};

static GList *recv_list;
static pthread_mutex_t recv_lock = PTHREAD_MUTEX_INITIALIZER;
static uint16_t __seq;

static struct recv_info *find_rif(int fd, uint16_t seq)
{
	GList *l;
	struct recv_info *rif;

	for (l = recv_list; l; l = g_list_next(l)) {
		rif = l->data;
		if (rif->fd == fd && rif->seq == seq)
			return rif;
	}

	return NULL;
}

static void remove_rif(struct recv_info *rif)
{
	GList *l;

	if (!rif)
		return;

	l = g_list_find(recv_list, rif);
	if (l)
		recv_list = g_list_delete_link(recv_list, l);

	bxt_dbg("rif %p seq %u type %d len %d/%d freed",
			rif, rif->seq, rif->type, rif->recved, rif->len);
	free(rif);
}

static struct recv_info *add_rif(int fd, struct header *hdr,
		recv_callback callback, void *user_data)
{
	struct recv_info *rif;
	struct recv_info *f;

	assert(callback);
	assert(hdr);

	/* 8 is pad for alignment */
	rif = malloc(sizeof(*rif) + hdr->total + 8);
	if (!rif)
		return NULL;

	memset(rif, 0, sizeof(*rif));

	rif->fd = fd;
	rif->seq = hdr->seq;

	rif->callback = callback;
	rif->user_data = user_data;

	rif->type = hdr->mtype;
	rif->len = hdr->total;

	/* 8 byte alignment */
	rif->data = (uint8_t *)(((uintptr_t)rif->_data + 0x7) & ~0x7);

	f = find_rif(rif->fd, rif->seq);
	if (f) {
		bxt_err("rif %p seq %u already exists in list", f, f->seq);
		remove_rif(f);
	}

	recv_list = g_list_append(recv_list, rif);

	bxt_dbg("rif %p seq %u type %d len %d added",
			rif, rif->seq, rif->type, rif->len);

	return rif;
}

static void flush_data(int fd, uint32_t len)
{
	int r;
	uint32_t s;
	char buf[4096];

	while (len > 0) {
		s = len > sizeof(buf) ? sizeof(buf) : len;

		r = recv(fd, buf, s, 0);
		if (r == -1)
			break;

		len -= r;
	}
}

static int proto_recv_single(int fd, recv_callback callback, void *user_data)
{
	int r;
	enum message_type type;
	uint8_t *data;
	int32_t len;

	assert(fd >= 0);
	assert(callback);

	r = proto_recv(fd, &type, &data, &len);
	if (r == -1)
		return -1;

	callback(user_data, type, data, len);
	free(data);

	return 0;
}

static int recv_data(struct recv_info *rif, uint32_t len)
{
	int r;
	struct header *hdr;
	uint8_t buf[MSG_MTU];

	assert(rif);

	r = recv(rif->fd, buf, sizeof(*hdr) + len, 0);
	if (r <= 0) {
		if (r == 0) {
			bxt_dbg("recv: fd %d closed", rif->fd);
		} else {
			if (errno == EAGAIN)
				return 0;

			bxt_err("recv: fd %d errno %d", rif->fd, errno);
		}

		return -1;
	}

	if (r < sizeof(*hdr) + len) {
		bxt_err("recv: fd %d expect %d > received %d",
				rif->fd, sizeof(*hdr) + len, r);
		return -1;
	}

	hdr = (struct header *)buf;
	memcpy(&rif->data[rif->recved], hdr->data, len);
	rif->recved += len;

	return 0;
}

static int proto_recv_frag(int fd, struct header *hdr,
		recv_callback callback, void *user_data)
{
	int r;
	struct recv_info *rif;

	assert(fd >= 0);
	assert(hdr);
	assert(callback);

	pthread_mutex_lock(&recv_lock);
	switch (hdr->type) {
	case MSG_FIRST:
		rif = add_rif(fd, hdr, callback, user_data);
		if (!rif) {
			flush_data(fd, sizeof(*hdr) + hdr->len);
			pthread_mutex_unlock(&recv_lock);
			return -1;
		}
		r = recv_data(rif, hdr->len);
		break;
	case MSG_MIDDLE:
	case MSG_LAST:
		rif = find_rif(fd, hdr->seq);
		if (!rif) {
			bxt_err("recv: fd %d seq %u not exist", fd, hdr->seq);
			flush_data(fd, sizeof(*hdr) + hdr->len);
			pthread_mutex_unlock(&recv_lock);
			return -1;
		}
		r = recv_data(rif, hdr->len);
		if (hdr->type == MSG_LAST && r == 0 && rif->recved < rif->len) {
			bxt_err("recv: fd %d packet lost %d/%d",
					fd, rif->recved, rif->len);
			r = -1;
		}
		break;
	default:
		bxt_err("recv: fd %d unknown type %x", fd, hdr->type);
		rif = NULL;
		r = -1;
		break;
	}

	if (r == -1) {
		remove_rif(rif);
		pthread_mutex_unlock(&recv_lock);
		return -1;
	}

	if (hdr->type == MSG_LAST) {
		recv_list = g_list_remove(recv_list, rif);
		pthread_mutex_unlock(&recv_lock);

		assert(rif->callback);
		rif->callback(rif->user_data, rif->type, rif->data, rif->len);
		remove_rif(rif);
	} else {
		pthread_mutex_unlock(&recv_lock);
	}

	return 0;
}

int proto_recv_async(int fd, recv_callback callback, void *user_data)
{
	int r;
	struct header hdr;

	if (fd < 0 || !callback) {
		errno = EINVAL;
		return -1;
	}

	r = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);
	if (r <= 0) {
		if (r == 0) {
			bxt_dbg("recv: fd %d closed", fd);
		} else {
			if (errno == EAGAIN || errno == EINTR)
				return 0;

			bxt_err("recv: fd %d errno %d", fd, errno);
		}

		return -1;
	}

	if (hdr.type == MSG_SINGLE)
		return proto_recv_single(fd, callback, user_data);

	return proto_recv_frag(fd, &hdr, callback, user_data);
}

int proto_send_block(int fd, enum message_type type, uint8_t *data, int32_t len)
{
	int r;
	struct header *hdr;
	int sent;
	struct pollfd fds[1];
	uint8_t buf[MSG_MTU];

	if (fd < 0 || !data || len <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (len <= (MSG_MTU - sizeof(*hdr)))
		return proto_send(fd, type, data, len);

	bxt_dbg("send: fd %d type %d len %d start", fd, type, len);

	hdr = (struct header *)buf;
	hdr->mtype = type;
	hdr->seq = __atomic_fetch_add(&__seq, 1, __ATOMIC_RELAXED);
	hdr->total = len;

	fds[0].fd = fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	sent = 0;
	while (len > sent) {
		/* CAN BE BLOCKED ! */
		r = poll(fds, 1, -1);
		if (r == -1) {
			if (errno == EINTR)
				continue;

			bxt_err("send: fd %d poll errno %d", fd, errno);
			return -1;
		}

		hdr->len = len - sent;
		if (hdr->len > (MSG_MTU - sizeof(*hdr))) {
			hdr->type = sent == 0 ? MSG_FIRST : MSG_MIDDLE;
			hdr->len = MSG_MTU - sizeof(*hdr);
		} else {
			hdr->type = MSG_LAST;
		}

		memcpy(hdr->data, &data[sent], hdr->len);

		r = send(fd, hdr, sizeof(*hdr) + hdr->len, 0);
		if (r == -1) {
			bxt_err("send: fd %d errno %d", fd, errno);
			return -1;
		}

		sent += hdr->len;
	}
	bxt_dbg("send: fd %d sent %d", fd, sent);

	return 0;
}

int proto_send(int fd, enum message_type type, uint8_t *data, int32_t len)
{
	int r;
	struct header *hdr;
	uint8_t *buf;
	struct pollfd fds[1];

	assert(fd >= 0);
	assert(data);
	assert(len > 0);

	bxt_dbg("send: fd %d type %d len %d start", fd, type, len);

	buf = malloc(sizeof(*hdr) + len);
	if (!buf) {
		bxt_err("send: send buffer alloc error");
		return -1;
	}

	hdr = (struct header *)buf;
	hdr->type = MSG_SINGLE;
	hdr->mtype = type;
	hdr->seq = __atomic_fetch_add(&__seq, 1, __ATOMIC_RELAXED);
	hdr->total = len;
	hdr->len = len;

	memcpy(hdr->data, data, len);

	fds[0].fd = fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	do {
		r = poll(fds, 1, SEND_TIMEOUT);
		if (r == -1) {
			if (errno == EINTR)
				continue;

			bxt_err("send: fd %d poll errno %d", fd, errno);
			free(buf);

			return -1;
		}

		if (r == 0) {
			bxt_err("send: fd %d poll timeout", fd);
			free(buf);
			errno = ETIMEDOUT;

			return -1;
		}
	} while (r < 0);

	r = send(fd, buf, sizeof(*hdr) + len, 0);

	free(buf);

	if (r == -1) {
		bxt_err("send: fd %d errno %d", fd, errno);
		return -1;
	}

	if (r != sizeof(*hdr) + len)
		bxt_err("send: %d / %d byte", r,
				(int32_t)(sizeof(*hdr) + len));

	bxt_dbg("send: fd %d sent %d", fd, r - sizeof(*hdr));

	return 0;
}

int proto_recv(int fd, enum message_type *type, uint8_t **data, int32_t *len)
{
	int r;
	struct header hdr;
	uint8_t *_data;

	assert(fd >= 0);
	assert(type);
	assert(data);
	assert(len);

	r = recv(fd, &hdr, sizeof(hdr), 0);
	if (r <= 0) {
		if (r == 0)
			bxt_dbg("recv: fd %d closed", fd);
		else
			bxt_err("recv: fd %d errno %d", fd, errno);

		return -1;
	}

	if (r != sizeof(hdr) || hdr.len == 0 || hdr.type != MSG_SINGLE) {
		bxt_err("recv: fd %d Invalid message", fd);
		return -1;
	}

	_data = malloc(hdr.total);
	if (!_data) {
		flush_data(fd, hdr.total);
		return -1;
	}

	r = recv(fd, _data, hdr.total, 0);
	if (r <= 0) {
		if (r == 0)
			bxt_dbg("recv: fd %d closed", fd);
		else
			bxt_err("recv: fd %d errno %d", fd, errno);

		free(_data);

		return -1;
	}

	if (r != hdr.total) {
		bxt_err("recv: fd %d expect size %d > received %d",
				fd, hdr.total, r);
		free(_data);
		return -1;
	}

	*type = hdr.mtype;
	*data = _data;
	*len = hdr.total;

	return 0;
}
