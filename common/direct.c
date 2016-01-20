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
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "buxton2.h"

#include "common.h"
#include "log.h"
#include "direct.h"
#include "config.h"
#include "backends.h"
#include "serialize.h"

static int get_path(uid_t uid, enum buxton_layer_type type,
		const struct layer *ly, char *path, int sz)
{
	const char *prefix;
	char suffix[16];

	if (!ly || !path || sz <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (type == BUXTON_LAYER_NORMAL && ly->storage == STORAGE_VOLATILE)
		prefix = TMPFS_DIR;
	else
		prefix = DB_DIR;

	if (type == BUXTON_LAYER_NORMAL && ly->type == LAYER_USER)
		snprintf(suffix, sizeof(suffix), "-%u", uid);
	else
		suffix[0] = '\0';

	snprintf(path, sz, "%s/%s%s.db", prefix, ly->name, suffix);

	return 0;
}

static int get_raw(const struct layer *ly, uid_t uid,
		enum buxton_layer_type type, const char *key,
		uint8_t **data, int *len)
{
	int r;
	const struct backend *backend;
	char path[FILENAME_MAX];

	assert(ly);
	assert(key);
	assert(data);
	assert(len);

	backend = backend_get(ly->backend);
	assert(backend);

	if (!backend->get_value) {
		bxt_err("Get: backend '%s' has no get func", backend->name);
		return -1;
	}

	r = get_path(uid, type, ly, path, sizeof(path));
	if (r == -1)
		return -1;

	r = backend->get_value(path, key, (void **)data, len);
	if (r == -1) {
		if (errno != ENOENT)
			bxt_err("Get: get_value: %d", errno);
		return -1;
	}

	return 0;
}

static int get_val(const struct layer *ly, uid_t uid,
		enum buxton_layer_type type, const char *key,
		char **rpriv, char **wpriv, struct buxton_value *val)
{
	int r;
	uint8_t *data;
	int len;

	assert(ly);
	assert(key);

	r = get_raw(ly, uid, type, key, &data, &len);
	if (r == -1)
		return -1;

	r = deserialz_data(data, len, rpriv, wpriv, val);

	free(data);

	if (r == -1)
		return -1;

	return 0;
}

int direct_get(const struct buxton_layer *layer,
		const char *key, struct buxton_value *val)
{
	int r;
	const struct layer *ly;
	struct buxton_value base_val;
	struct buxton_value db_val;

	if (!layer || !key || !*key || !val) {
		errno = EINVAL;
		return -1;
	}

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	/* First, refer to base db */
	r = get_val(ly, layer->uid, BUXTON_LAYER_BASE, key, NULL, NULL,
			&base_val);
	if (r == -1)
		return -1;

	if (layer->type == BUXTON_LAYER_BASE) {
		*val = base_val;
		return 0;
	}

	/* DB backend System layer has no normal db */
	if (ly->type == LAYER_SYSTEM && ly->storage == STORAGE_PERSISTENT) {
		*val = base_val;
		return 0;
	}

	r = get_val(ly, layer->uid, BUXTON_LAYER_NORMAL, key, NULL, NULL,
			&db_val);
	if (r == -1 && errno != ENOENT) {
		value_free(&base_val);
		return -1;
	}

	if (errno == ENOENT) {
		*val = base_val;
		return 0;
	}

	value_free(&base_val);
	*val = db_val;

	return 0;
}

int direct_check(const struct buxton_layer *layer, const char *key)
{
	int r;
	const struct layer *ly;
	struct buxton_value val;

	if (!layer || !key || !*key) {
		errno = EINVAL;
		return -1;
	}

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	r = get_val(ly, layer->uid, BUXTON_LAYER_BASE, key, NULL, NULL, &val);
	if (r == -1)
		return -1;

	value_free(&val);

	return 0;
}

static int set_raw(const struct layer *ly, uid_t uid,
		enum buxton_layer_type type, const char *key,
		uint8_t *data, int len)
{
	int r;
	const struct backend *backend;
	char path[FILENAME_MAX];

	assert(ly);
	assert(key);
	assert(data);
	assert(len > 0);

	backend = backend_get(ly->backend);
	assert(backend);

	if (!backend->set_value) {
		bxt_err("Set: backend '%s' has no set func", backend->name);
		return -1;
	}

	r = get_path(uid, type, ly, path, sizeof(path));
	if (r == -1)
		return -1;

	r = backend->set_value(path, key, data, len);
	if (r == -1)
		return -1;

	return 0;
}

static int set_val(const struct layer *ly, uid_t uid,
		enum buxton_layer_type type, const char *key,
		const char *rpriv, const char *wpriv,
		const struct buxton_value *val)
{
	int r;
	uint8_t *data;
	int len;

	assert(val);

	r = serialz_data(rpriv ? rpriv : "", wpriv ? wpriv : "", val,
			&data, &len);
	if (r == -1)
		return -1;

	r = set_raw(ly, uid, type, key, data, len);

	free(data);

	if (r == -1)
		return -1;

	return 0;
}

int direct_set(const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val)
{
	int r;
	const struct layer *ly;
	char *rp;
	char *wp;

	if (!layer || !key || !*key || !val) {
		errno = EINVAL;
		return -1;
	}

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	r = get_val(ly, layer->uid, BUXTON_LAYER_BASE, key, &rp, &wp, NULL);
	if (r == -1)
		return -1;

	r = set_val(ly, layer->uid, layer->type, key, rp, wp, val);

	free(rp);
	free(wp);

	if (r == -1)
		return -1;

	return 0;
}

int direct_create(const struct buxton_layer *layer, const char *key,
		const char *rpriv, const char *wpriv,
		const struct buxton_value *val)
{
	int r;
	const struct layer *ly;

	if (!layer || !key || !*key || !val) {
		errno = EINVAL;
		return -1;
	}

	r = check_key_name(key);
	if (r == -1)
		return -1;

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	r = get_val(ly, layer->uid, BUXTON_LAYER_BASE, key, NULL, NULL, NULL);
	if (r == -1 && errno != ENOENT)
		return -1;

	if (r == 0) {
		errno = EEXIST;
		return -1;
	}

	r = set_val(ly, layer->uid, BUXTON_LAYER_BASE, key, rpriv, wpriv, val);
	if (r == -1)
		return -1;

	return 0;
}

int direct_unset(const struct buxton_layer *layer, const char *key)
{
	int r;
	const struct layer *ly;
	const struct backend *backend;
	char path[FILENAME_MAX];

	if (!layer || !key || !*key) {
		errno = EINVAL;
		return -1;
	}

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	backend = backend_get(ly->backend);
	assert(backend);

	if (!backend->unset_value) {
		bxt_err("Unset: backend '%s' has no unset func",
				backend->name);
		return -1;
	}

	r = get_path(layer->uid, layer->type, ly, path, sizeof(path));
	if (r == -1)
		return -1;

	r = backend->unset_value(path, key);
	if (r == -1) {
		bxt_err("Unset: unset_value: %d", errno);
		return -1;
	}

	return 0;
}

static int comp_str(const void *pa, const void *pb)
{
	const char *sa = pa ? *(char * const *)pa : "";
	const char *sb = pb ? *(char * const *)pb : "";

	return strcmp(sa, sb);
}

int direct_list(const struct buxton_layer *layer,
		char ***names, unsigned int *len)
{
	int r;
	const struct layer *ly;
	const struct backend *backend;
	char path[FILENAME_MAX];
	unsigned int _len;

	if (!layer || !names) {
		errno = EINVAL;
		return -1;
	}

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	backend = backend_get(ly->backend);
	assert(backend);

	if (!backend->list_keys) {
		bxt_err("List: backend '%s' has no list func",
				backend->name);
		return -1;
	}

	r = get_path(layer->uid, BUXTON_LAYER_BASE, ly, path, sizeof(path));
	if (r == -1)
		return -1;

	r = backend->list_keys(path, names, &_len);
	if (r == -1) {
		bxt_err("List: list_keys: %d", errno);
		return -1;
	}

	if (_len > 1)
		qsort(*names, _len, sizeof(char *), comp_str);

	if (len)
		*len = _len;

	return 0;
}

int direct_get_priv(const struct buxton_layer *layer,
		const char *key, enum buxton_priv_type type, char **priv)
{
	int r;
	const struct layer *ly;
	char **rp;
	char **wp;

	if (!layer || !key || !*key || !priv) {
		errno = EINVAL;
		return -1;
	}

	switch (type) {
	case BUXTON_PRIV_READ:
		rp = priv;
		wp = NULL;
		break;
	case BUXTON_PRIV_WRITE:
		rp = NULL;
		wp = priv;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	r = get_val(ly, layer->uid, BUXTON_LAYER_BASE, key, rp, wp, NULL);
	if (r == -1)
		return -1;

	return 0;
}

int direct_set_priv(const struct buxton_layer *layer,
		const char *key, enum buxton_priv_type type, const char *priv)
{
	int r;
	const struct layer *ly;
	char *rp;
	char *wp;
	const char *t_rp;
	const char *t_wp;
	struct buxton_value val;

	if (!layer || !key || !*key || !priv) {
		errno = EINVAL;
		return -1;
	}

	switch (type) {
	case BUXTON_PRIV_READ:
	case BUXTON_PRIV_WRITE:
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	ly = conf_get_layer(layer->name);
	if (!ly)
		return -1;

	r = get_val(ly, layer->uid, BUXTON_LAYER_BASE, key, &rp, &wp, &val);
	if (r == -1)
		return -1;

	switch (type) {
	case BUXTON_PRIV_READ:
		t_rp = priv;
		t_wp = wp;
		break;
	case BUXTON_PRIV_WRITE:
		t_rp = rp;
		t_wp = priv;
		break;
	default: /* Never reach */
		t_rp = rp;
		t_wp = wp;
		break;
	}

	r = set_val(ly, layer->uid, BUXTON_LAYER_BASE, key, t_rp, t_wp, &val);

	value_free(&val);
	free(rp);
	free(wp);

	if (r == -1)
		return -1;

	return 0;
}

void direct_remove_user_memory(uid_t uid)
{
	char path[FILENAME_MAX];
	const struct layer *ly;

	ly = conf_get_layer("user-memory");
	if (!ly)
		return;

	if (get_path(uid, BUXTON_LAYER_NORMAL, ly, path, sizeof(path)))
		return;

	if (!access(path, F_OK)) {
		if (remove(path))
			bxt_err("remote user memory db failed");
	}
}

void direct_exit(void)
{
	conf_exit();
	backend_exit();
}

int direct_init(const char *moddir, const char *confpath)
{
	int r;
	GList *backends;

	if (!moddir || !*moddir || !confpath || !*confpath) {
		errno = EINVAL;
		return -1;
	}

	r = backend_init(moddir);
	if (r == -1)
		return -1;

	backends = backend_list();
	if (!backends)
		return -1;

	r = conf_init(confpath, backends);

	g_list_free(backends);

	if (r == -1)
		return -1;

	return 0;
}

