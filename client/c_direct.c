/*
 * Buxton
 *
 * Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License)
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
#include <errno.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "direct.h"

#include "c_log.h"
#include "c_common.h"
#include "c_direct.h"

static const char *confpath;

void c_direct_set_conf(const char *conf)
{
	if (!conf || !*conf) {
		bxt_err("Invalid config path. Default path is used.");
		return;
	}

	confpath = conf;
}

static void change_user(const char *name)
{
	struct passwd pwd;
	struct passwd *result;
	char *buf;
	size_t bufsize;
	int r;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1) {
		bxt_err("sysconf: _SC_GETPW_R_SIZE_MAX errno %d", errno);
		return;
	}

	buf = malloc(bufsize);
	if (buf == NULL)
		return;

	r = getpwnam_r(name, &pwd, buf, bufsize, &result);

	free(buf);

	if (r != 0) {
		bxt_err("getpwnam_r: '%s' errno %d", name, errno);
		return;
	}

	if (result == NULL) {
		bxt_err("getpwnam_r: '%s' not exist", name);
		return;
	}

	r = setuid(pwd.pw_uid);
	if (r == -1)
		bxt_err("setuid: errno %d", errno);
}

static void c_exit(void)
{
	direct_exit();
}

static int c_init(void)
{
	int r;
	char err_buf[128] = {0,};

	/* TODO: configurable */
	change_user("buxton");

	r = direct_init(MODULE_DIR, confpath ? confpath : CONFPATH);
	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Init: %s", err_buf);
		return -1;
	}

	return 0;
}

int c_direct_get(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	int r;
	struct buxton_value val;
	char err_buf[128] = {0,};

	if (!layer || !key || !*key) {
		errno = EINVAL;
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Get: Layer '%s' Key '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", err_buf);
		return -1;
	}

	r = c_init();
	if (r == -1)
		return -1;

	r = direct_get(layer, key, &val);

	c_exit();

	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Get: Layer '%s' Key '%s': %s",
				buxton_layer_get_name(layer), key,
				err_buf);
		return -1;
	}

	c_print_value(layer, key, &val);

	value_free(&val);

	return 0;
}

static int c_direct_set(const struct buxton_layer *layer,
		const char *key, const char *value, enum buxton_key_type type)
{
	int r;
	struct buxton_value val;
	char err_buf[128] = {0,};

	if (!layer || !key || !*key || !value) {
		errno = EINVAL;
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Set: Layer '%s' Key '%s' Value '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", value ? value : "",
				err_buf);
		return -1;
	}

	r = c_set_value(type, value, &val);
	if (r == -1)
		return -1;

	r = c_init();
	if (r == -1)
		return -1;

	r = direct_set(layer, key, &val);

	c_exit();

	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Set: Layer '%s' Key '%s' Value '%s': %s",
				buxton_layer_get_name(layer), key, value,
				err_buf);
	}

	return r;
}

int c_direct_set_str(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set(layer, key, value, BUXTON_TYPE_STRING);
}

int c_direct_set_int32(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set(layer, key, value, BUXTON_TYPE_INT32);
}

int c_direct_set_uint32(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set(layer, key, value, BUXTON_TYPE_UINT32);
}

int c_direct_set_int64(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set(layer, key, value, BUXTON_TYPE_INT64);
}

int c_direct_set_uint64(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set(layer, key, value, BUXTON_TYPE_UINT64);
}

int c_direct_set_double(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set(layer, key, value, BUXTON_TYPE_DOUBLE);
}

int c_direct_set_bool(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set(layer, key, value, BUXTON_TYPE_BOOLEAN);
}


static int c_direct_create(const struct buxton_layer *layer,
		const char *key, const char *value, enum buxton_key_type type,
		const char *rpriv, const char *wpriv)
{
	int r;
	struct buxton_value val;
	char err_buf[128] = {0,};

	if (!layer || !key || !*key || !value || !rpriv || !wpriv) {
		errno = EINVAL;
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Create: '%s' '%s' '%s' Priv '%s' '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", value ? value : "",
				rpriv ? rpriv : "", wpriv ? wpriv : "",
				err_buf);
		return -1;
	}

	r = c_set_value(type, value, &val);
	if (r == -1)
		return -1;

	r = c_init();
	if (r == -1)
		return -1;

	r = direct_create(layer, key, rpriv, wpriv, &val);

	c_exit();

	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Create: '%s' '%s' '%s' Priv '%s' '%s': %s",
				buxton_layer_get_name(layer), key, value,
				rpriv, wpriv, err_buf);
	}

	return r;
}

int c_direct_create_str(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv)
{
	return c_direct_create(layer, key, value, BUXTON_TYPE_STRING,
			rpriv, wpriv);
}

int c_direct_create_int32(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv)
{
	return c_direct_create(layer, key, value, BUXTON_TYPE_INT32,
			rpriv, wpriv);
}

int c_direct_create_uint32(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv)
{
	return c_direct_create(layer, key, value, BUXTON_TYPE_UINT32,
			rpriv, wpriv);
}

int c_direct_create_int64(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv)
{
	return c_direct_create(layer, key, value, BUXTON_TYPE_INT64,
			rpriv, wpriv);
}

int c_direct_create_uint64(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv)
{
	return c_direct_create(layer, key, value, BUXTON_TYPE_UINT64,
			rpriv, wpriv);
}

int c_direct_create_double(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv)
{
	return c_direct_create(layer, key, value, BUXTON_TYPE_DOUBLE,
			rpriv, wpriv);
}

int c_direct_create_bool(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv)
{
	return c_direct_create(layer, key, value, BUXTON_TYPE_BOOLEAN,
			rpriv, wpriv);
}

static int c_direct_get_priv(const struct buxton_layer *layer,
		const char *key, enum buxton_priv_type type)
{
	int r;
	char *priv;
	char err_buf[128] = {0,};

	if (!layer || !key || !*key) {
		errno = EINVAL;
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Get-priv: Layer '%s' Key '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "",
				err_buf);
		return -1;
	}

	r = c_init();
	if (r == -1)
		return r;

	r = direct_get_priv(layer, key, type, &priv);

	c_exit();

	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Get-priv: Layer '%s' Key '%s': %s",
				buxton_layer_get_name(layer), key,
				err_buf);
		return -1;
	}

	c_print_priv(layer, key, type, priv);
	free(priv);

	return r;
}

int c_direct_get_rpriv(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_get_priv(layer, key, BUXTON_PRIV_READ);
}

int c_direct_get_wpriv(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_get_priv(layer, key, BUXTON_PRIV_WRITE);
}

static int c_direct_set_priv(const struct buxton_layer *layer,
		const char *key, const char *priv, enum buxton_priv_type type)
{
	int r;
	char err_buf[128] = {0,};

	if (!layer || !key || !*key || !priv) {
		errno = EINVAL;
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Set-priv: Layer '%s' Key '%s' Priv. '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", priv ? priv : "",
				err_buf);
		return -1;
	}

	r = c_init();
	if (r == -1)
		return -1;

	r = direct_set_priv(layer, key, type, priv);

	c_exit();

	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Set-priv: Layer '%s' Key '%s' Priv. '%s': %s",
				buxton_layer_get_name(layer), key, priv,
				err_buf);
	}

	return r;
}

int c_direct_set_rpriv(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set_priv(layer, key, value, BUXTON_PRIV_READ);
}

int c_direct_set_wpriv(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_direct_set_priv(layer, key, value, BUXTON_PRIV_WRITE);
}

int c_direct_unset(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	int r;
	char err_buf[128] = {0,};

	if (!layer || !key || !*key) {
		errno = EINVAL;
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Unset: Layer '%s' Key '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", err_buf);
		return -1;
	}

	r = c_init();
	if (r == -1)
		return -1;

	r = direct_unset(layer, key);

	c_exit();

	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("Unset: Layer '%s' Key '%s': %s",
				buxton_layer_get_name(layer), key,
				err_buf);
	}

	return r;
}

int c_direct_list(const struct buxton_layer *layer,
		UNUSED const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	int r;
	char **keys;
	char **k;
	char err_buf[128] = {0,};

	if (!layer) {
		errno = EINVAL;
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("List: Layer '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				err_buf);
		return -1;
	}

	r = c_init();
	if (r == -1)
		return -1;

	r = direct_list(layer, &keys, NULL);

	c_exit();

	if (r == -1) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		bxt_err("List: Layer '%s': %s", buxton_layer_get_name(layer),
				err_buf);
		return -1;
	}

	k = keys;
	while (k && *k) {
		printf("%s\n", *k);
		k++;
	}

	buxton_free_keys(keys);

	return 0;
}

