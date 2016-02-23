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
#include <errno.h>
#include <assert.h>

#include <glib.h>

#include "buxton2.h"

#include "serialize.h"
#include "log.h"

#define KEY_NAME_MAX 4096
#define VALUE_MAX 4096

int check_key_name(const char *key)
{
	const char *p;
	int len;

	len = 0;
	p = key;
	while (*p) {
		/* from 0x21 '!' to 0x7e '~' */
		if (*p < 0x21 || *p > 0x7e) {
			errno = EINVAL;
			bxt_err("Key name has invalid character '%x'", *p);
			return -1;
		}
		p++;
		len++;
		if (len > KEY_NAME_MAX) {
			errno = ENAMETOOLONG;
			bxt_err("Key name is too long");
			return -1;
		}
	}

	return 0;
}

static inline int check_val(const char *s)
{
	if (!s)
		return 0;

	if (strlen(s) > VALUE_MAX) {
		errno = EMSGSIZE;
		return -1;
	}

	return 0;
}

static int check_values(const char *rpriv, const char *wpriv,
		const struct buxton_value *val)
{
	int r;

	r = check_val(rpriv);
	if (r == -1) {
		bxt_err("Read priv. string length is too long");
		return -1;
	}

	r = check_val(wpriv);
	if (r == -1) {
		bxt_err("Write priv. string length is too long");
		return -1;
	}

	if (val && val->type == BUXTON_TYPE_STRING) {
		r = check_val(val->value.s);
		if (r == -1) {
			bxt_err("Value string length is too long");
			return -1;
		}
	}

	return 0;
}

static GVariant *val_to_gv(const struct buxton_value *val)
{
	GVariant *gv;

	if (!val)
		return g_variant_new_tuple(NULL, 0);

	switch (val->type) {
	case BUXTON_TYPE_STRING:
		if (!val->value.s) {
			bxt_err("Serialize: value has NULL string");
			return NULL;
		}

		gv = g_variant_new_string(val->value.s);
		break;
	case BUXTON_TYPE_INT32:
		gv = g_variant_new_int32(val->value.i);
		break;
	case BUXTON_TYPE_UINT32:
		gv = g_variant_new_uint32(val->value.u);
		break;
	case BUXTON_TYPE_INT64:
		gv = g_variant_new_int64(val->value.i64);
		break;
	case BUXTON_TYPE_UINT64:
		gv = g_variant_new_uint64(val->value.u64);
		break;
	case BUXTON_TYPE_DOUBLE:
		gv = g_variant_new_double(val->value.d);
		break;
	case BUXTON_TYPE_BOOLEAN:
		gv = g_variant_new_boolean(val->value.b);
		break;
	default:
		bxt_err("Serialize: Invalid value type: %d", val->type);
		gv = NULL;
		break;
	}

	return gv;
}

static uint8_t *gv_to_data(GVariant *gv, int *len)
{
	uint8_t *data;
	int _len;

	assert(gv);
	assert(len);

	_len = g_variant_get_size(gv);
	assert(_len > 0);

	data = malloc(_len);
	if (!data)
		return NULL;

	g_variant_store(gv, data);

	*len = _len;

	return data;
}

/*
 * Data format = v Variant v
 *
 * In an initial version,
 *   Variant v = (ssv) read privilege s, write priv. w, value v
 *
 */
int serialz_data(const char *rpriv, const char *wpriv,
		const struct buxton_value *val,
		uint8_t **data, int *len)
{
	GVariant *gv;
	GVariant *vv;
	GVariant *v;
	int _len;
	uint8_t *_data;
	int r;

	if (!rpriv || !wpriv || !val || !data || !len) {
		errno = EINVAL;
		bxt_err("serialize data: invalid argument:%s%s%s%s%s",
				rpriv ? "" : " read priv",
				wpriv ? "" : " write priv",
				val ? "" : " value",
				data ? "" : " data",
				len ? "" : " len");

		return -1;
	}

	r = check_values(rpriv, wpriv, val);
	if (r == -1)
		return -1;

	v = val_to_gv(val);
	if (!v) {
		errno = EINVAL;
		return -1;
	}

	vv = g_variant_new("(ssv)", rpriv, wpriv, v);
	assert(vv);

	gv = g_variant_new_variant(vv);
	assert(gv);

	_data = gv_to_data(gv, &_len);

	g_variant_unref(gv);

	if (!_data)
		return -1;

	*data = _data;
	*len = _len;

	return 0;
}

static int gv_to_val(GVariant *v, struct buxton_value *val)
{
	const char *t;
	const char *s;

	assert(v);
	assert(val);

	t = g_variant_get_type_string(v);
	assert(t);

	if (!strncmp(t, "()", sizeof("()"))) {
		val->type = BUXTON_TYPE_UNKNOWN;
		return 0;
	}

	switch (*t) {
	case 's':
		val->type = BUXTON_TYPE_STRING;

		s = g_variant_get_string(v, NULL);
		assert(s);

		val->value.s = strdup(s);
		if (!val->value.s)
			return -1;

		break;
	case 'i':
		val->type = BUXTON_TYPE_INT32;
		val->value.i = g_variant_get_int32(v);
		break;
	case 'u':
		val->type = BUXTON_TYPE_UINT32;
		val->value.u = g_variant_get_uint32(v);
		break;
	case 'x':
		val->type = BUXTON_TYPE_INT64;
		val->value.i64 = g_variant_get_int64(v);
		break;
	case 't':
		val->type = BUXTON_TYPE_UINT64;
		val->value.u64 = g_variant_get_uint64(v);
		break;
	case 'd':
		val->type = BUXTON_TYPE_DOUBLE;
		val->value.d = g_variant_get_double(v);
		break;
	case 'b':
		val->type = BUXTON_TYPE_BOOLEAN;
		val->value.b = g_variant_get_boolean(v);
		break;
	default:
		bxt_err("DeSerialz: Invalid variant type: %s", t);
		errno = EBADMSG;

		return -1;
	}

	return 0;
}

static int gv_to_values(GVariant *gv, char **rpriv, char **wpriv,
		struct buxton_value *val)
{
	GVariant *v;
	const char *vt;
	const char *rp;
	const char *wp;
	int r;

	assert(gv);

	if (!rpriv && !wpriv && !val)
		return 0;

	vt = g_variant_get_type_string(gv);
	if (strncmp(vt, "(ssv)", sizeof("(ssv)"))) {
		bxt_err("Deserialize: Unsupported type: %s", vt);
		errno = EBADMSG;
		return -1;
	}

	g_variant_get(gv, "(&s&sv)", &rp, &wp, &v);
	assert(rp);
	assert(wp);
	assert(v);

	if (rpriv) {
		*rpriv = strdup(rp);
		if (!*rpriv) {
			g_variant_unref(v);
			return -1;
		}
	}

	if (wpriv) {
		*wpriv = strdup(wp);
		if (!*wpriv) {
			if (rpriv)
				free(*rpriv);

			g_variant_unref(v);
			return -1;
		}
	}

	if (val) {
		memset(val, 0, sizeof(*val));
		r = gv_to_val(v, val);
		if (r == -1) {
			if (rpriv)
				free(*rpriv);

			if (wpriv)
				free(*wpriv);

			g_variant_unref(v);
			return -1;
		}
	}

	g_variant_unref(v);

	return 0;
}

int deserialz_data(uint8_t *data, int len,
		char **rpriv, char **wpriv, struct buxton_value *val)
{
	GVariant *gv;
	GVariant *v;
	char *_rpriv;
	char *_wpriv;
	struct buxton_value _val;
	int r;

	if (!data || len <= 0) {
		errno = EINVAL;
		bxt_err("Deserialize data: invalid argument:%s%s",
				data ? "" : " data", len > 0 ? "" : " len");
		return -1;
	}

	gv = g_variant_new_from_data(G_VARIANT_TYPE("v"),
			data, len, TRUE, NULL, NULL);
	assert(gv);

	g_variant_get(gv, "v", &v);
	assert(v);

	r = gv_to_values(v,
			rpriv ? &_rpriv : NULL,
			wpriv ? &_wpriv : NULL,
			val ? &_val : NULL);

	g_variant_unref(v);
	g_variant_unref(gv);

	if (r == -1)
		return -1;

	if (rpriv)
		*rpriv = _rpriv;

	if (wpriv)
		*wpriv = _wpriv;

	if (val)
		*val = _val;

	return 0;
}

void free_request(struct request *req)
{
	if (!req)
		return;

	layer_free(req->layer);
	free(req->rpriv);
	free(req->wpriv);
	free(req->key);
	value_free(req->val);
	free(req->val);
}

static int check_value(const struct buxton_value *val)
{
	if (!val) {
		bxt_err("Serialize: value is NULL");
		return -1;
	}

	switch (val->type) {
	case BUXTON_TYPE_STRING:
		if (!val->value.s) {
			bxt_err("Serialize: value has NULL string");
			return -1;
		}
		break;
	case BUXTON_TYPE_INT32:
	case BUXTON_TYPE_UINT32:
	case BUXTON_TYPE_INT64:
	case BUXTON_TYPE_UINT64:
	case BUXTON_TYPE_DOUBLE:
	case BUXTON_TYPE_BOOLEAN:
		break;
	default:
		bxt_err("Serialize: buxton_value has unknown type");
		return -1;
	}

	return 0;
}

static int check_request(enum message_type type,
		const char *key, const struct buxton_value *val)
{
	int r;

	switch (type) {
	case MSG_SET:
	case MSG_CREAT:
	case MSG_NOTI:
	case MSG_SET_WP:
	case MSG_SET_RP:
		r = check_value(val);
		if (r == -1)
			goto err;
	case MSG_GET:
	case MSG_UNSET:
	case MSG_NOTIFY:
	case MSG_UNNOTIFY:
	case MSG_GET_WP:
	case MSG_GET_RP:
		if (!key || !*key) {
			bxt_err("Serialize: key is NULL or empty string");
			goto err;
		}

		r = check_key_name(key);
		if (r == -1)
			return -1;
	case MSG_LIST:
	case MSG_CYN_ON:
	case MSG_CYN_OFF:
		break;
	default:
		bxt_err("Serialize: message type is invalid: %d", type);
		goto err;
	}

	return 0;

err:
	errno = EINVAL;

	return -1;
}

int serialz_request(const struct request *req, uint8_t **data, int *len)
{
	int r;
	GVariant *gv;
	GVariant *vv;
	GVariant *v;
	int _len;
	uint8_t *_data;

	if (!data || !len || !req || !req->layer) {
		errno = EINVAL;
		bxt_err("Serialize request: invalid argument:%s%s%s%s",
				data ? "" : " data",
				len ? "" : " len",
				req ? "" : " req",
				req && !req->layer ? " layer" : "");
		return -1;
	}

	r = check_request(req->type, req->key, req->val);
	if (r == -1)
		return -1;

	v = val_to_gv(req->val);
	if (!v) {
		errno = EINVAL;
		return -1;
	}

	vv = g_variant_new("(uuissssv)",
			req->msgid,
			req->layer->uid,
			req->layer->type,
			req->layer->name,
			req->rpriv ? req->rpriv : "",
			req->wpriv ? req->wpriv : "",
			req->key ? req->key : "",
			v);
	assert(vv);

	gv = g_variant_new("(qv)", req->type, vv);
	assert(gv);

	_data = gv_to_data(gv, &_len);

	g_variant_unref(gv);

	if (!_data)
		return -1;

	*data = _data;
	*len = _len;

	return 0;
}

static inline int _strdup(const char *src, char **dest)
{
	char *s;

	assert(dest);

	if (!src) {
		*dest = NULL;
		return 0;
	}

	s = strdup(src);
	if (!s)
		return -1;

	*dest = s;

	return 0;
}

static int set_req(struct buxton_value *val, const char *lnm, uid_t uid,
		enum buxton_layer_type type, const char *rp, const char *wp,
		const char *key, struct request *req)
{
	int r;

	assert(req);

	req->val = val;

	if (lnm && *lnm) {
		req->layer = layer_create(lnm);
		if (!req->layer)
			return -1;

		req->layer->uid = uid;
		req->layer->type = type;
	} else {
		req->layer = NULL;
	}

	r = _strdup(rp, &req->rpriv);
	if (r == -1)
		return -1;

	r = _strdup(wp, &req->wpriv);
	if (r == -1)
		return -1;

	r = _strdup(key, &req->key);
	if (r == -1)
		return -1;

	return 0;
}

static int gv_to_req(GVariant *gv, struct request *req)
{
	const char *vt;
	uint32_t uid;
	int32_t type;
	const char *lnm;
	const char *key;
	const char *rp;
	const char *wp;
	GVariant *v;
	int r;
	struct buxton_value *val;

	assert(gv);
	assert(req);

	vt = g_variant_get_type_string(gv);
	if (strncmp(vt, "(uuissssv)", sizeof("(uuissssv)"))) {
		bxt_err("DeSerialz: Unsupported type: %s", vt);
		errno = EBADMSG;
		return -1;
	}

	val = calloc(1, sizeof(*val));
	if (!val)
		return -1;

	g_variant_get(gv, "(uui&s&s&s&sv)", &req->msgid, &uid, &type,
			&lnm, &rp, &wp, &key, &v);
	assert(v);
	assert(lnm);
	assert(rp);
	assert(wp);
	assert(key);

	r = gv_to_val(v, val);

	g_variant_unref(v);

	if (r == -1) {
		free(val);
		return -1;
	}

	if (val->type == BUXTON_TYPE_UNKNOWN) {
		free(val);
		val = NULL;
	}

	r = set_req(val, lnm, uid, type, rp, wp, key, req);
	if (r == -1)
		free_request(req);

	return r;
}

int deserialz_request(uint8_t *data, int len, struct request *req)
{
	GVariant *gv;
	GVariant *v;
	int r;
	struct request _req;

	if (!data || len <= 0 || !req) {
		errno = EINVAL;
		bxt_err("Deserialize request: invalid argument:%s%s%s",
				data ? "" : " data",
				len > 0 ? "" : " len",
				req ? "" : " req");
		return -1;
	}

	gv = g_variant_new_from_data(G_VARIANT_TYPE("(qv)"),
			data, len, TRUE, NULL, NULL);
	assert(gv);

	memset(&_req, 0, sizeof(_req));

	g_variant_get(gv, "(qv)", &_req.type, &v);
	assert(v);

	r = gv_to_req(v, &_req);

	g_variant_unref(v);
	g_variant_unref(gv);

	if (r == -1)
		return -1;

	*req = _req;

	return 0;
}

void free_response(struct response *res)
{
	if (!res)
		return;

	value_free(res->val);
	free(res->val);
	buxton_free_keys(res->names);
}

static int check_response(enum message_type type, int32_t res,
		const struct buxton_value *val, char * const *names)
{
	int r;

	if (res)
		return 0;

	switch (type) {
	case MSG_LIST:
		if (!names) {
			bxt_err("Serialize: names is NULL");
			goto err;
		}
		break;
	case MSG_GET:
	case MSG_GET_WP:
	case MSG_GET_RP:
		r = check_value(val);
		if (r == -1)
			goto err;
		break;
	case MSG_SET:
	case MSG_CREAT:
	case MSG_UNSET:
	case MSG_NOTIFY:
	case MSG_UNNOTIFY:
	case MSG_SET_WP:
	case MSG_SET_RP:
	case MSG_CYN_ON:
	case MSG_CYN_OFF:
		break;
	case MSG_NOTI:
		errno = ENOTSUP;
		bxt_err("Serialize: MSG_NOTI type has no response");
		return -1;
	default:
		goto err;
	}

	return 0;

err:
	errno = EINVAL;

	return -1;
}

static int res_to_gv(enum message_type type, int32_t res,
		const struct buxton_value *val, char * const *names,
		GVariant **gv)
{
	GVariantBuilder *builder;
	GVariant *v;

	assert(gv);

	if (res) {
		*gv = g_variant_new_tuple(NULL, 0);
		return 0;
	}

	switch (type) {
	case MSG_LIST:
		builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
		assert(names);
		while (*names) {
			g_variant_builder_add(builder, "s", *names);
			names++;
		}
		v = g_variant_new("as", builder);
		assert(v);
		g_variant_builder_unref(builder);
		break;
	case MSG_GET:
	case MSG_GET_WP:
	case MSG_GET_RP:
		if (val) {
			v = val_to_gv(val);
			if (!v) {
				errno = EINVAL;
				return -1;
			}
		} else {
			v = g_variant_new_tuple(NULL, 0);
		}
		break;
	default:
		v = g_variant_new_tuple(NULL, 0);
		break;
	}

	*gv = v;

	return 0;
}

int serialz_response(enum message_type type, uint32_t msgid, int32_t res,
		const struct buxton_value *val, uint32_t nmlen,
		char * const *names, uint8_t **data, int *len)
{
	int r;
	GVariant *gv;
	GVariant *vv;
	GVariant *v;
	int _len;
	uint8_t *_data;

	if (!data || !len) {
		errno = EINVAL;
		bxt_err("Serialize response: invalid argument:%s%s",
				data ? "" : " data",
				len ? "" : " len");
		return -1;
	}

	r = check_response(type, res, val, names);
	if (r == -1)
		return -1;

	r = res_to_gv(type, res, val, names, &v);
	if (r == -1)
		return -1;

	assert(v);
	vv = g_variant_new("(uiuv)", msgid, res, nmlen, v);
	assert(vv);

	gv = g_variant_new("(qv)", type, vv);
	assert(gv);

	_data = gv_to_data(gv, &_len);

	g_variant_unref(gv);

	if (!_data)
		return -1;

	*data = _data;
	*len = _len;

	return 0;
}

static int gv_to_res_list(GVariant *gv, struct response *res)
{
	GVariantIter iter;
	gsize len;
	const char *s;
	int i;

	g_variant_iter_init(&iter, gv);
	len = g_variant_iter_n_children(&iter);

	res->names = calloc(len + 1, sizeof(void *));
	if (!res->names)
		return -1;

	i = 0;
	while (g_variant_iter_next(&iter, "&s", &s)) {
		assert(s);
		res->names[i] = strdup(s);
		if (!res->names[i])
			break;
		i++;

		assert(i <= len);
	}
	/* NULL terminated */
	res->names[i] = NULL;

	if (i < len) {
		buxton_free_keys(res->names);
		return -1;
	}

	return 0;
}

static int gv_to_res(GVariant *gv, struct response *res)
{
	const char *vt;
	GVariant *v;
	struct buxton_value *val;
	int r;

	assert(gv);
	assert(res);

	vt = g_variant_get_type_string(gv);
	if (strncmp(vt, "(uiuv)", sizeof("(uiuv)"))) {
		bxt_err("DeSerialz: Unsupported type: %s", vt);
		errno = EBADMSG;
		return -1;
	}

	g_variant_get(gv, "(uiuv)", &res->msgid, &res->res, &res->nmlen, &v);

	if (res->res)
		return 0;

	if (res->type == MSG_LIST) {
		r = gv_to_res_list(v, res);
		g_variant_unref(v);
		return r;
	}

	val = calloc(1, sizeof(*val));
	if (!val) {
		g_variant_unref(v);
		return -1;
	}

	r = gv_to_val(v, val);
	if (r == -1) {
		free(val);
		g_variant_unref(v);
		return -1;
	}

	g_variant_unref(v);

	if (val->type == BUXTON_TYPE_UNKNOWN) {
		free(val);
		val = NULL;
	}

	res->val = val;

	return 0;
}

int deserialz_response(uint8_t *data, int len, struct response *res)
{
	GVariant *gv;
	GVariant *v;
	int r;
	struct response _res;

	if (!data || len <= 0 || !res) {
		errno = EINVAL;
		bxt_err("Deserialize response: invalid argument:%s%s%s",
				data ? "" : " data",
				len > 0 ? "" : " len",
				res ? "" : " response");
		return -1;
	}

	gv = g_variant_new_from_data(G_VARIANT_TYPE("(qv)"),
			data, len, TRUE, NULL, NULL);
	assert(gv);

	memset(&_res, 0, sizeof(_res));

	g_variant_get(gv, "(qv)", &_res.type, &v);
	assert(v);

	r = gv_to_res(v, &_res);

	g_variant_unref(v);
	g_variant_unref(gv);

	if (r == -1) {
		free_response(&_res);
		return -1;
	}

	*res = _res;

	return 0;
}

