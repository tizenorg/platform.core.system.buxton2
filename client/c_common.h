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

#include <errno.h>
#include <string.h>

#include "buxton2.h"

#include "c_log.h"

void c_print_value(const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val);

void c_print_priv(const struct buxton_layer *layer,
		const char *key, enum buxton_priv_type type, const char *priv);

int c_set_value(enum buxton_key_type type, const char *value,
		struct buxton_value *val);

