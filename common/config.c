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
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>

#include <glib.h>

#include "log.h"
#include "config.h"

#define K_TYPE     "Type"
#define K_BACKEND  "Backend"
#define K_STORAGE  "Storage"
#define K_DESC     "Description"

#define K_T_SYSTEM "System"
#define K_T_USER   "User"

#define K_B_DB     "persistent"
#define K_B_MEM    "volatile"

static GHashTable *layers;

static void free_layer(struct layer *layer)
{
	if (!layer)
		return;

	g_free(layer->name);
	g_free(layer->backend);
	g_free(layer->description);
	free(layer);
}

static GKeyFile *load_conf(const char *confpath)
{
	GKeyFile *kf;
	gboolean b;
	GError *err;

	assert(confpath);

	kf = g_key_file_new();
	if (!kf) {
		errno = ENOMEM;
		return NULL;
	}

	err = NULL;
	b = g_key_file_load_from_file(kf, confpath, G_KEY_FILE_NONE, &err);
	if (!b) {
		bxt_err("Load '%s' error: %s", confpath,
				err ? err->message : "");
		g_clear_error(&err);
		g_key_file_free(kf);
		return NULL;
	}

	return kf;
}

static struct layer *create_layer(GKeyFile *kf, gchar *name)
{
	GError *err;
	struct layer *layer;
	gchar *s;

	assert(name && *name);

	layer = calloc(1, sizeof(*layer));
	if (!layer)
		goto err;

	/* 'Type' */
	err = NULL;
	s = g_key_file_get_string(kf, name, K_TYPE, &err);
	if (!s) {
		bxt_err("Layer '%s' : %s",
				name, err ? err->message : "");
		g_clear_error(&err);
		goto err;
	}

	if (!strncmp(s, K_T_SYSTEM, sizeof(K_T_SYSTEM)))
		layer->type = LAYER_SYSTEM;
	else if (!strncmp(s, K_T_USER, sizeof(K_T_USER)))
		layer->type = LAYER_USER;

	g_free(s);

	/* 'Backend' */
	s = g_key_file_get_string(kf, name, K_BACKEND, &err);
	if (!s) {
		bxt_err("Layer '%s' : %s",
				name, err ? err->message : "");
		g_clear_error(&err);
		goto err;
	}

	layer->backend = s;

	/* 'Storage' */
	s = g_key_file_get_string(kf, name, K_STORAGE, &err);
	if (!s) {
		bxt_err("Layer '%s' : %s",
				name, err ? err->message : "");
		g_clear_error(&err);
		goto err;
	}

	if (!strncasecmp(s, K_B_DB, sizeof(K_B_DB)))
		layer->storage = STORAGE_PERSISTENT;
	else if (!strncasecmp(s, K_B_MEM, sizeof(K_B_MEM)))
		layer->storage = STORAGE_VOLATILE;

	g_free(s);

	/* 'Description' */
	s = g_key_file_get_string(kf, name, K_DESC, &err);
	if (!s) {
		bxt_err("Layer '%s' : %s",
				name, err ? err->message : "");
		g_clear_error(&err);
		goto err;
	}

	layer->description = s;

	/* Layer name */
	layer->name = name;

	return layer;

err:
	g_free(name);
	free_layer(layer);

	return NULL;
}

static gboolean has_backend(GList *backends, const char *name)
{
	GList *l;

	if (!name || !*name)
		return FALSE;

	for (l = backends; l; l = g_list_next(l)) {
		const char *nm = l->data;

		if (nm && !strcmp(name, nm))
			return TRUE;
	}

	return FALSE;
}

static void add_layers(GKeyFile *kf, GList *backends)
{
	gchar **lays;
	int i;
	struct layer *layer;
	struct layer *f;
	gboolean b;

	assert(kf);
	assert(layers);

	lays = g_key_file_get_groups(kf, NULL);
	if (!lays) {
		bxt_err("No specified layers");
		return;
	}

	i = 0;
	while (lays[i]) {
		layer = create_layer(kf, lays[i++]);
		if (!layer)
			continue;

		b = has_backend(backends, layer->backend);
		if (!b) {
			bxt_err("Layer '%s' : invalid backend", layer->name);
			free_layer(layer);
			continue;
		}

		f = g_hash_table_lookup(layers, layer->name);
		if (f) {
			bxt_err("Layer '%s' : already exists", layer->name);
			free_layer(layer);
			continue;
		}

		if (layer->type == LAYER_UNKNWON) {
			bxt_err("Layer '%s' : unknwon type", layer->name);
			free_layer(layer);
			continue;
		}

		if (layer->storage == STORAGE_UNKNOWN) {
			bxt_err("Layer '%s' : unknwon storage type",
					layer->name);
			free_layer(layer);
			continue;
		}

		g_hash_table_insert(layers, layer->name, layer);
	}

	g_free(lays);
}

const struct layer *conf_get_layer(const char *name)
{
	const struct layer *layer;

	if (!name || !*name) {
		errno = EINVAL;
		return NULL;
	}

	if (!layers) {
		errno = ENOENT;
		return NULL;
	}

	layer = g_hash_table_lookup(layers, name);
	if (!layer) {
		bxt_dbg("Layer '%s' not exist", name);
		errno = ENOENT;
	}

	return layer;
}

int conf_remove(const char *name)
{
	const struct layer *layer;
	gboolean b;

	layer = conf_get_layer(name);
	if (!layer)
		return -1;

	b = g_hash_table_remove(layers, name);

	return b ? 0 : -1;
}

void conf_exit(void)
{
	g_hash_table_destroy(layers);
	layers = NULL;
}

int conf_init(const char *confpath, GList *backends)
{
	GKeyFile *kf;

	if (!confpath || !*confpath) {
		errno = EINVAL;
		return -1;
	}

	if (layers)
		return 0;

	kf = load_conf(confpath);
	if (!kf)
		return -1;

	layers = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)free_layer);
	if (!layers) {
		errno = ENOMEM;
		g_key_file_free(kf);
		return -1;
	}

	add_layers(kf, backends);

	g_key_file_free(kf);

	return 0;
}
