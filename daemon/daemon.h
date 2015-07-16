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

#pragma once

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>

#include <glib.h>

struct bxt_daemon {
	GMainLoop *loop;
	int sigfd;

	int sk; /* server socket */
	guint sk_id; /* source ID for sk */

	GHashTable *clients; /* struct bxt_client */
	GHashTable *notis; /* struct bxt_noti */
};

struct bxt_client {
	int fd;
	guint fd_id;

	struct ucred cred;
	char *label;

	GList *notilist; /* struct bxt_noti */

	struct bxt_daemon *bxtd;
};

int start_daemon(struct bxt_daemon *bxtd, const char *confpath);

