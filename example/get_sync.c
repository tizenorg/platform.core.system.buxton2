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
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <glib.h>

#include <buxton2.h>

static void print_value(const char *ly, const char *key,
		struct buxton_value *val)
{
	int r;
	enum buxton_key_type type;
	const char *str;
	int32_t i;
	uint32_t u;
	int64_t i64;
	uint64_t u64;
	double d;
	int32_t b;

	r = buxton_value_get_type(val, &type);
	if (r) {
		perror("buxton_value_get_type");
		return;
	}

	switch (type) {
	case BUXTON_TYPE_STRING:
		r = buxton_value_get_string(val, &str);
		if (r)
			perror("buxton_value_get_string");
		else
			printf("Layer [%s] Key [%s]: [%s]\n", ly, key, str);
		break;
	case BUXTON_TYPE_INT32:
		r = buxton_value_get_int32(val, &i);
		if (r)
			perror("buxton_value_get_int32");
		else
			printf("Layer [%s] Key [%s]: [%d]\n", ly, key, i);
		break;

	case BUXTON_TYPE_UINT32:
		r = buxton_value_get_uint32(val, &u);
		if (r)
			perror("buxton_value_get_uint32");
		else
			printf("Layer [%s] Key [%s]: [%u]\n", ly, key, u);
		break;

	case BUXTON_TYPE_INT64:
		r = buxton_value_get_int64(val, &i64);
		if (r)
			perror("buxton_value_get_int64");
		else
			printf("Layer [%s] Key [%s]: [%" PRId64 "]\n",
					ly, key, i64);
		break;

	case BUXTON_TYPE_UINT64:
		r = buxton_value_get_uint64(val, &u64);
		if (r)
			perror("buxton_value_get_uint64");
		else
			printf("Layer [%s] Key [%s]: [%" PRIu64 "]\n",
					ly, key, u64);
		break;

	case BUXTON_TYPE_DOUBLE:
		r = buxton_value_get_double(val, &d);
		if (r)
			perror("buxton_value_get_double");
		else
			printf("Layer [%s] Key [%s]: [%lf]\n", ly, key, d);
		break;
	case BUXTON_TYPE_BOOLEAN:
		r = buxton_value_get_boolean(val, &b);
		if (r)
			perror("buxton_value_get_boolean");
		else
			printf("Layer [%s] Key [%s]: [%s]\n", ly, key,
					b ? "True" : "False");
		break;
	default:
		printf("Layer [%s] Key [%s]: unknown type %d\n", ly, key, type);
		break;
	}
}

int main(int argc, char *argv[])
{
	int r;
	struct buxton_client *cli;
	struct buxton_layer *layer;
	const char *key;
	struct buxton_value *val;

	if (argc < 3) {
		printf(" usage) %s layer key\n", argv[0]);
		printf("\n");
		printf(" ex)");
		printf("  %s system db/menu_widget/lanugage\n", argv[0]);
		printf("\n");
		return EXIT_FAILURE;
	}

	r = buxton_open(&cli, NULL, NULL);
	if (r) {
		perror("buxton_open");
		return EXIT_FAILURE;
	}

	layer = buxton_create_layer(argv[1]);
	if (!layer) {
		perror("buxton_create_layer");
		buxton_close(cli);
		return EXIT_FAILURE;
	}
	key = argv[2];

	r = buxton_get_value_sync(cli, layer, key, &val);
	if (r) {
		perror("buxton_get_value_sync");
		buxton_free_layer(layer);
		buxton_close(cli);
		return EXIT_FAILURE;
	}

	print_value(buxton_layer_get_name(layer), key, val);

	buxton_value_free(val);

	buxton_free_layer(layer);

	r = buxton_close(cli);
	if (r)
		perror("buxton_close");

	return EXIT_SUCCESS;
}

