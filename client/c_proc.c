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

#include "buxton2.h"

#include "common.h"

#include "c_log.h"
#include "c_common.h"
#include "c_proc.h"

static struct buxton_client *client;

static void status_cb(enum buxton_status status, void *data)
{
	bxt_dbg("Status: %d", status);
}

static int _close(void)
{
	int r;

	if (!client)
		return 0;

	r = buxton_close(client);
	if (r == -1)
		bxt_err("close: %s", strerror(errno));

	client = NULL;

	return r;
}

static int _open(void)
{
	int r;

	if (client)
		return 0;

	r = buxton_open(&client, status_cb, NULL);
	if (r == -1)
		bxt_err("open: %s", strerror(errno));

	return r;
}

int c_open(void)
{
	return _open();
}

int c_check(UNUSED const struct buxton_layer *layer,
		UNUSED const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	int r;
	struct buxton_client *cli;

	r = buxton_open(&cli, NULL, NULL);
	if (r == -1) {
		printf("Failed to connect the Buxton service\n");
		return -1;
	}

	printf("Buxton service is available\n");

	buxton_close(cli);

	return 0;
}

int c_get(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	int r;
	struct buxton_value *val;

	if (!layer || !key || !*key) {
		errno = EINVAL;
		bxt_err("Get: Layer '%s' Key '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", strerror(errno));
		return -1;
	}

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_get_value_sync(client, layer, key, &val);

	_close();

	if (r == -1) {
		bxt_err("Get: Layer '%s' Key '%s': %s",
				buxton_layer_get_name(layer), key,
				strerror(errno));
		return -1;
	}

	c_print_value(layer, key, val);

	buxton_value_free(val);

	return 0;
}

static int c_set(const struct buxton_layer *layer,
		const char *key, const char *value, enum buxton_key_type type)
{
	int r;
	struct buxton_value val;

	if (!layer || !key || !*key || !value) {
		errno = EINVAL;
		bxt_err("Set: Layer '%s' Key '%s' Value '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", value ? value : "",
				strerror(errno));
		return -1;
	}

	r = c_set_value(type, value, &val);
	if (r == -1)
		return -1;

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_set_value_sync(client, layer, key, &val);

	_close();

	if (r == -1) {
		bxt_err("Set: Layer '%s' Key '%s' Value '%s': %s",
				buxton_layer_get_name(layer), key, value,
				strerror(errno));
	}

	return r;
}

int c_set_str(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set(layer, key, value, BUXTON_TYPE_STRING);
}

int c_set_int32(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set(layer, key, value, BUXTON_TYPE_INT32);
}

int c_set_uint32(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set(layer, key, value, BUXTON_TYPE_UINT32);
}

int c_set_int64(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set(layer, key, value, BUXTON_TYPE_INT64);
}

int c_set_uint64(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set(layer, key, value, BUXTON_TYPE_UINT64);
}

int c_set_double(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set(layer, key, value, BUXTON_TYPE_DOUBLE);
}

int c_set_bool(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set(layer, key, value, BUXTON_TYPE_BOOLEAN);
}

static int c_create(const struct buxton_layer *layer, const char *key,
		const char *value, enum buxton_key_type type,
		const char *rpriv, const char *wpriv)
{
	int r;
	struct buxton_value val;

	if (!layer || !key || !*key || !value || !rpriv || !wpriv) {
		errno = EINVAL;
		bxt_err("Create: '%s' '%s' '%s' Priv '%s' '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", value ? value : "",
				rpriv ? rpriv : "", wpriv ? wpriv : "",
				strerror(errno));
		return -1;
	}

	r = c_set_value(type, value, &val);
	if (r == -1)
		return -1;

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_create_value_sync(client, layer, key, rpriv, wpriv, &val);

	_close();

	if (r == -1) {
		bxt_err("Create: '%s' '%s' '%s' Priv '%s' '%s': %s",
				buxton_layer_get_name(layer), key, value,
				rpriv, wpriv, strerror(errno));
	}

	return r;
}

int c_create_str(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv)
{
	return c_create(layer, key, value, BUXTON_TYPE_STRING, rpriv, wpriv);
}

int c_create_int32(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv)
{
	return c_create(layer, key, value, BUXTON_TYPE_INT32, rpriv, wpriv);
}

int c_create_uint32(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv)
{
	return c_create(layer, key, value, BUXTON_TYPE_UINT32, rpriv, wpriv);
}

int c_create_int64(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv)
{
	return c_create(layer, key, value, BUXTON_TYPE_INT64, rpriv, wpriv);
}

int c_create_uint64(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv)
{
	return c_create(layer, key, value, BUXTON_TYPE_UINT64, rpriv, wpriv);
}

int c_create_double(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv)
{
	return c_create(layer, key, value, BUXTON_TYPE_DOUBLE, rpriv, wpriv);
}

int c_create_bool(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv)
{
	return c_create(layer, key, value, BUXTON_TYPE_BOOLEAN, rpriv, wpriv);
}

static int c_get_priv(const struct buxton_layer *layer,
		const char *key, enum buxton_priv_type type)
{
	int r;
	char *priv;

	if (!layer || !key || !*key) {
		errno = EINVAL;
		bxt_err("Get-priv: Layer '%s' Key '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", strerror(errno));
		return -1;
	}

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_get_privilege_sync(client, layer, key, type, &priv);

	_close();

	if (r == -1) {
		bxt_err("Get-priv: Layer '%s' Key '%s': %s",
				buxton_layer_get_name(layer), key,
				strerror(errno));
		return -1;
	}

	c_print_priv(layer, key, type, priv);
	free(priv);

	return r;
}

int c_get_rpriv(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_get_priv(layer, key, BUXTON_PRIV_READ);
}

int c_get_wpriv(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_get_priv(layer, key, BUXTON_PRIV_WRITE);
}

int c_set_priv(const struct buxton_layer *layer,
		const char *key, const char *priv, enum buxton_priv_type type)
{
	int r;

	if (!layer || !key || !*key || !priv) {
		errno = EINVAL;
		bxt_err("Set-priv: Layer '%s' Key '%s' Priv '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", priv ? priv : "",
				strerror(errno));
		return -1;
	}

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_set_privilege_sync(client, layer, key, type, priv);

	_close();

	if (r == -1) {
		bxt_err("Set-priv: Layer '%s' Key '%s' Priv '%s': %s",
				buxton_layer_get_name(layer), key, priv,
				strerror(errno));
	}

	return r;
}

int c_set_rpriv(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set_priv(layer, key, value, BUXTON_PRIV_READ);
}

int c_set_wpriv(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	return c_set_priv(layer, key, value, BUXTON_PRIV_WRITE);
}

int c_unset(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	int r;

	if (!layer || !key || !*key) {
		errno = EINVAL;
		bxt_err("Unset: Layer '%s' Key '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				key ? key : "", strerror(errno));
		return -1;
	}

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_unset_value_sync(client, layer, key);

	_close();

	if (r == -1) {
		bxt_err("Unset: Layer '%s' Key '%s': %s",
				buxton_layer_get_name(layer), key,
				strerror(errno));
	}

	return r;
}

int c_list(const struct buxton_layer *layer,
		UNUSED const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv)
{
	int r;
	char **keys;
	char **k;

	if (!layer) {
		errno = EINVAL;
		bxt_err("List: Layer '%s': %s",
				layer ? buxton_layer_get_name(layer) : "",
				strerror(errno));
		return -1;
	}

	r = _open();
	if (r == -1)
		return -1;

	r = buxton_list_keys_sync(client, layer, &keys, NULL);

	_close();

	if (r == -1) {
		bxt_err("List: Layer '%s': %s", buxton_layer_get_name(layer),
				strerror(errno));
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

