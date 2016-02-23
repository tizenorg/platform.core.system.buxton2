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

#include <stdint.h>
#include <sys/types.h>

#include <glib.h>

#include "buxton2.h"

#ifndef CONFPATH
#  warning "CONFPATH is not set. default value is used"
#  define CONFPATH "/etc/buxton.conf"
#endif

#ifndef MODULE_DIR
#  warning "MODULE_DIR is not set. default value is used"
#  define MODULE_DIR "/usr/lib/buxton"
#endif

#ifndef DB_DIR
#  warning "DB_DIR is not set. default value is used"
#  define DB_DIR "/var/lib/buxton"
#endif

#ifndef TMPFS_DIR
#  warning "TMPFS_DIR is not set. default value is used"
#  define TMPFS_DIR "/run/buxton"
#endif

#ifndef SOCKPATH
#  warning "SOCKPATH is not set. default value is used"
#  define SOCKPATH "/run/buxton-0"
#endif

enum layer_type {
	LAYER_UNKNWON = 0,
	LAYER_SYSTEM,
	LAYER_USER,
	LAYER_MAX, /* sentinel value */
};

enum storage_type {
	STORAGE_UNKNOWN = 0,
	STORAGE_PERSISTENT,
	STORAGE_VOLATILE,
	STORAGE_MAX, /* sentinel value */
};

struct layer {
	gchar *name;
	enum layer_type type;
	gchar *backend;
	enum storage_type storage;
	gchar *description;
};

enum message_type {
	MSG_UNKNOWN = 0,
	/* basic request */
	MSG_SET,
	MSG_GET,
	MSG_CREAT,
	MSG_UNSET,
	MSG_LIST,
	MSG_NOTIFY,
	MSG_UNNOTIFY,
	MSG_NOTI,
	/* privilege request */
	MSG_SET_WP,
	MSG_SET_RP,
	MSG_GET_WP,
	MSG_GET_RP,
	/* Security request */
	MSG_CYN_ON,
	MSG_CYN_OFF,
	MSG_MAX, /* sentinel value */
};

struct buxton_layer {
	int refcnt;
	char *name;
	uid_t uid;
	enum buxton_layer_type type;
};

struct buxton_layer *layer_create(const char *layer_name);
void layer_free(struct buxton_layer *layer);

struct buxton_layer *layer_ref(struct buxton_layer *layer);
struct buxton_layer *layer_unref(struct buxton_layer *layer);

struct buxton_value {
	enum buxton_key_type type;
	union {
		char *s;
		int32_t i;
		uint32_t u;
		int64_t i64;
		uint64_t u64;
		double d;
		int32_t b;
	} value;
};

void value_free(struct buxton_value *val);

char *get_search_key(const struct buxton_layer *layer, const char *key,
		const char *uid);

