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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>

#include <systemd/sd-daemon.h>

#include "log.h"

#include "socks.h"

#define SOCKET_TIMEOUT 5 /* seconds */

static int smack_not_supported;

static int sock_create(const char *path)
{
	int r;
	int fd;
	struct sockaddr_un sa;

	assert(path && *path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		bxt_err("Socket '%s': socket %d", path, errno);
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, path, sizeof(sa.sun_path));
	sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

	r = unlink(sa.sun_path);
	if (r == -1 && errno != ENOENT) {
		bxt_err("Socket '%s': unlink %d", path, errno);
		close(fd);
		return -1;
	}

	r = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r == -1) {
		bxt_err("Socket '%s': bind %d", path, errno);
		close(fd);
		return -1;
	}

	chmod(sa.sun_path, 0666);

	r = listen(fd, SOMAXCONN);
	if (r == -1) {
		bxt_err("Socket '%s': listen %d", path, errno);
		close(fd);
		return -1;
	}

	return fd;
}

int sock_get_server(const char *path)
{
	int n;
	int i;
	int r;
	int fd;

	if (!path || !*path) {
		errno = EINVAL;
		return -1;
	}

	n = sd_listen_fds(0);
	if (n < 0) {
		bxt_err("sd_listen_fds: %d", n);
		return -1;
	}

	if (n == 0)
		return sock_create(path);

	fd = -1;
	for (i = SD_LISTEN_FDS_START; i < SD_LISTEN_FDS_START + n; i++) {
		r = sd_is_socket_unix(i, SOCK_STREAM, -1, path, 0);
		if (r > 0) {
			fd = i;
			break;
		}
	}

	if (fd == -1) {
		bxt_err("Socket '%s' is not passed", path);
		return sock_create(path);
	}

	return fd;
}

int sock_set_client(int fd)
{
	int r;
	struct timeval tv;
	int on;

	r = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (r == -1) {
		bxt_err("Client %d: set NONBLOCK: %d", fd, errno);
		return -1;
	}

	/* need SO_PRIORITY ? */

	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	r = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv,
			sizeof(struct timeval));
	if (r == -1) {
		bxt_err("Client %d: set SO_RCVTIMEO: %d", fd, errno);
		return -1;
	}

	on = 1;
	r = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
	if (r == -1)
		bxt_err("Client %d: set SO_PASSCRED: %d", fd, errno);

	return 0;
}

int sock_get_client_cred(int fd, struct ucred *cred)
{
	int r;
	socklen_t len;

	if (fd < 0 || !cred) {
		errno = EINVAL;
		return -1;
	}

	len = sizeof(*cred);
	r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, cred, &len);
	if (r == -1) {
		bxt_err("Client %d: get SO_PEERCRED: %d", fd, errno);
		return -1;
	}

	bxt_dbg("Client %d: pid %d uid %u gid %u", fd,
			cred->pid, cred->uid, cred->gid);

	return 0;
}

int sock_get_client_label(int fd, char **label)
{
	char dummy;
	int r;
	socklen_t len;
	char *l;

	if (fd < 0 || !label) {
		errno = EINVAL;
		return -1;
	}

	if (smack_not_supported) {
		*label = NULL;
		return 0;
	}

	len = 0;
	r = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, &dummy, &len);

	if (r < 0 && errno != ERANGE) {
		if (errno == ENOPROTOOPT) {
			bxt_err("Client %d: get SO_PEERSEC: 0", fd);
			*label = NULL;
			smack_not_supported = 1;
			return 0;
		}
		bxt_err("Client %d: get SO_PEERSEC: %d", fd, errno);
		return -1;
	}

	l = calloc(1, len + 1);
	if (!l)
		return -1;

	r = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, l, &len);
	if (r == -1) {
		bxt_err("Cleint %d: get SO_PEERSEC: %d", fd, errno);
		free(l);
		return -1;
	}

	bxt_dbg("Client %d: Label '%s'", fd, l);

	*label = l;

	return 0;
}

