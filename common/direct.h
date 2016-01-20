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

#include "buxton2.h"

int direct_init(const char *moddir, const char *confpath);
void direct_exit(void);

int direct_get(const struct buxton_layer *layer,
		const char *key, struct buxton_value *val);
int direct_set(const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val);
int direct_check(const struct buxton_layer *layer, const char *key);

int direct_create(const struct buxton_layer *layer, const char *key,
		const char *rprive, const char *wpriv,
		const struct buxton_value *val);
int direct_unset(const struct buxton_layer *layer, const char *key);

int direct_list(const struct buxton_layer *layer,
		char ***names, unsigned int *len);

int direct_get_priv(const struct buxton_layer *layer,
		const char *key, enum buxton_priv_type type, char **priv);
int direct_set_priv(const struct buxton_layer *layer,
		const char *key, enum buxton_priv_type type, const char *priv);

int direct_remove_db(const struct buxton_layer *layer);
