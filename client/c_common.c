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
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>

#include "common.h"

#include "c_log.h"
#include "c_common.h"

static const char const *type_names[BUXTON_TYPE_MAX] = {
	[BUXTON_TYPE_UNKNOWN]   = "Unknown",
	[BUXTON_TYPE_STRING]    = "String",
	[BUXTON_TYPE_INT32]     = "Int32",
	[BUXTON_TYPE_UINT32]    = "UInt32",
	[BUXTON_TYPE_INT64]     = "Int64",
	[BUXTON_TYPE_UINT64]    = "UInt64",
	[BUXTON_TYPE_DOUBLE]    = "Double",
	[BUXTON_TYPE_BOOLEAN]   = "Boolean",
};

void c_print_value(const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val)
{
	const char *lnm;

	lnm = layer ? layer->name : NULL;

	printf("[%s] %s = ", lnm ? lnm : "''", key ? key : "''");

	if (!val) {
		printf("NULL\n");
		return;
	}

	switch (val->type) {
	case BUXTON_TYPE_STRING:
		printf("%s: %s\n", type_names[val->type], val->value.s);
		break;
	case BUXTON_TYPE_INT32:
		printf("%s: %d\n", type_names[val->type], val->value.i);
		break;
	case BUXTON_TYPE_UINT32:
		printf("%s: %u\n", type_names[val->type], val->value.u);
		break;
	case BUXTON_TYPE_INT64:
		printf("%s: %" PRId64 "\n", type_names[val->type],
				val->value.i64);
		break;
	case BUXTON_TYPE_UINT64:
		printf("%s: %" PRIu64 "\n", type_names[val->type],
				val->value.u64);
		break;
	case BUXTON_TYPE_DOUBLE:
		printf("%s: %lf\n", type_names[val->type], val->value.d);
		break;
	case BUXTON_TYPE_BOOLEAN:
		printf("%s: %s\n", type_names[val->type],
				val->value.b ? "True" : "False");
		break;
	default:
		printf("Unknown type\n");
		break;
	}
}

void c_print_priv(const struct buxton_layer *layer, const char *key,
		enum buxton_priv_type type, const char *priv)
{
	const char *tnm;
	const char *lnm;

	lnm = layer ? layer->name : NULL;

	switch (type) {
	case BUXTON_PRIV_READ:
		tnm = "Read";
		break;
	case BUXTON_PRIV_WRITE:
		tnm = "Write";
		break;
	default:
		tnm = "Unknown";
		break;
	}

	printf("[%s] %s - %s: '%s'\n", lnm ? lnm : "''", key ? key : "''",
			tnm, priv ? priv : "");
}

int c_set_value(enum buxton_key_type type, const char *value,
		struct buxton_value *val)
{
	char *end;
	struct buxton_value _val;

	if (!value || !val) {
		errno = EINVAL;
		return -1;
	}

	memset(&_val, 0, sizeof(_val));
	_val.type = type;

	errno = 0;
	end = NULL;
	switch (_val.type) {
	case BUXTON_TYPE_STRING:
		_val.value.s = (char *)value;
		break;
	case BUXTON_TYPE_INT32:
		_val.value.i = (int32_t)strtol(value, &end, 0);
		break;
	case BUXTON_TYPE_UINT32:
		_val.value.u = (uint32_t)strtoul(value, &end, 0);
		break;
	case BUXTON_TYPE_INT64:
		_val.value.i64 = strtoll(value, &end, 0);
		break;
	case BUXTON_TYPE_UINT64:
		_val.value.u64 = strtoull(value, &end, 0);
		break;
	case BUXTON_TYPE_DOUBLE:
		_val.value.d = strtod(value, &end);
		break;
	case BUXTON_TYPE_BOOLEAN:
		_val.value.b = !!strtol(value, &end, 0);
		break;
	default:
		bxt_err("Set: Unknown type: %d", type);
		return -1;
	}

	if (errno || ((end && *end != '\0'))) {
		bxt_err("Set: '%s': Invalid number", value);
		return -1;
	}

	*val = _val;

	return 0;
}

