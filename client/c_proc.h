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

#ifndef UNUSED
#  define UNUSED __attribute__((unused))
#endif

#include "buxton2.h"

int c_open(void);

int c_check(UNUSED const struct buxton_layer *layer,
		UNUSED const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_get(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_str(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_int32(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_uint32(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_int64(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_uint64(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_double(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_bool(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_get_rpriv(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_get_wpriv(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_rpriv(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_set_wpriv(const struct buxton_layer *layer,
		const char *key, const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_unset(const struct buxton_layer *layer,
		const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);
int c_list(const struct buxton_layer *layer,
		UNUSED const char *key, UNUSED const char *value,
		UNUSED const char *rpriv, UNUSED const char *wpriv);

int c_create_str(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv);
int c_create_int32(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv);
int c_create_uint32(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv);
int c_create_int64(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv);
int c_create_uint64(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv);
int c_create_double(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv);
int c_create_bool(const struct buxton_layer *layer, const char *key,
		const char *value, const char *rpriv, const char *wpriv);

