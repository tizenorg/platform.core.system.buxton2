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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>

#include <glib.h>

#include "backend.h"
#include "log.h"

static GHashTable *backends;

struct module {
	void *handle;
	const struct backend *backend;
};

static void free_backend(struct module *mod)
{
	if (!mod)
		return;

	if (mod->backend && mod->backend->module_exit)
		mod->backend->module_exit();

	if (mod->handle)
		dlclose(mod->handle);

	free(mod);
}

const struct backend *backend_get(const char *name)
{
	struct module *mod;

	if (!name || !*name) {
		errno = EINVAL;
		return NULL;
	}

	if (!backends) {
		errno = ENOENT;
		return NULL;
	}

	mod = g_hash_table_lookup(backends, name);
	if (!mod) {
		errno = ENOENT;
		return NULL;
	}

	return mod->backend;
}

static struct module *load_module(const char *moddir, const char *modname)
{
	struct module *mod;
	const struct backend *backend;
	void *handle;
	int r;
	char modpath[FILENAME_MAX];

	assert(moddir);
	assert(modname);

	snprintf(modpath, sizeof(modpath), "%s/%s", moddir, modname);

	handle = dlopen(modpath, RTLD_NOW);
	if (!handle) {
		bxt_err("load '%s' error: %s", modpath, dlerror());
		return NULL;
	}

	mod = calloc(1, sizeof(*mod));
	if (!mod) {
		bxt_err("load '%s' error: Not enough space", modpath);
		goto err;
	}

	dlerror();
	backend = dlsym(handle, BUXTON_BACKEND_SYMBOL);
	if (!backend) {
		bxt_err("load '%s' error: %s", modpath, dlerror());
		goto err;
	}

	if (!backend->name || !*backend->name) {
		bxt_err("load '%s' error: no name", modpath);
		goto err;
	}

	if (!backend->module_init) {
		bxt_err("load '%s' error: no init", modpath);
		goto err;
	}

	r = backend->module_init();
	if (r) {
		bxt_err("load '%s' error: init: %d", modpath, errno);
		goto err;
	}

	mod->handle = handle;
	mod->backend = backend;

	return mod;

err:
	dlclose(handle);
	free(mod);
	return NULL;
}

static int load_modules(const char *moddir)
{
	DIR *dir;
	struct dirent *de;
	char *ext;
	struct module *mod;

	assert(moddir);
	assert(backends);

	dir = opendir(moddir);
	if (!dir) {
		bxt_err("opendir error: %d", errno);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		ext = strrchr(de->d_name, '.');
		if (!ext)
			continue;

		if (strncmp(ext, ".so", sizeof(".so")))
			continue;

		mod = load_module(moddir, de->d_name);
		if (mod) {
			g_hash_table_insert(backends,
					(gpointer)mod->backend->name, mod);
		}
	}

	closedir(dir);

	return 0;
}

GList *backend_list(void)
{
	GList *list;

	if (!backends)
		return NULL;

	list = g_hash_table_get_keys(backends);

	return list;
}

void backend_exit(void)
{
	g_hash_table_destroy(backends);
	backends = NULL;
}

int backend_init(const char *moddir)
{
	if (!moddir || !*moddir) {
		errno = EINVAL;
		return -1;
	}

	if (backends)
		return 0;

	backends = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)free_backend);
	if (!backends) {
		errno = ENOMEM;
		return -1;
	}

	return load_modules(moddir);
}

