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

#include <stdlib.h>

#ifndef EXPORT
#  define EXPORT __attribute__((visibility("default")))
#endif

typedef int (*backend_module_init)(void);
typedef void (*backend_module_exit)(void);

typedef int (*backend_open_db)(const char *dbpath);
typedef int (*backend_remove_db)(const char *dbpath);
typedef int (*backend_set_value)(const char *dbpath,
		const char *key, const void *data, int dlen);
typedef int (*backend_get_value)(const char *dbpath,
		const char *key, void **data, int *dlen);
typedef int (*backend_unset_value)(const char *dbpath, const char *key);
typedef int (*backend_list_keys)(const char *dbpath,
		char ***keys, unsigned int *klen);

struct backend {
	const char *name;

	backend_module_init module_init;
	backend_module_exit module_exit;

	backend_open_db open_db;
	backend_remove_db remove_db;
	backend_set_value set_value;
	backend_get_value get_value;
	backend_unset_value unset_value;
	backend_list_keys list_keys;

	void *reserved[7];
};

static inline void backend_list_free(char **keys)
{
	char **k;

	if (!keys)
		return;

	k = keys;
	while (*k) {
		free(*k);
		k++;
	}

	free(keys);
}

#define BUXTON_BACKEND_SYMBOL "buxton_backend"
#define DEFINE_BUXTON_BACKEND EXPORT const struct backend buxton_backend

