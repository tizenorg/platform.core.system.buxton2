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
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <buxton2.h>

static const char *type_names[BUXTON_TYPE_MAX] = {
	[BUXTON_TYPE_STRING] = "string",
	[BUXTON_TYPE_INT32] = "int32",
	[BUXTON_TYPE_UINT32] = "uint32",
	[BUXTON_TYPE_INT64] = "int64",
	[BUXTON_TYPE_UINT64] = "uint64",
	[BUXTON_TYPE_DOUBLE] = "double",
	[BUXTON_TYPE_BOOLEAN] = "bool",
};

static enum buxton_key_type get_type(const char *type)
{
	int i;

	for (i = 0; i < BUXTON_TYPE_MAX; i++) {
		if (type_names[i] && !strcmp(type_names[i], type))
			return i;
	}

	return BUXTON_TYPE_UNKNOWN;
}

static struct buxton_value *arg_to_val(const char *atype, const char *arg)
{
	struct buxton_value *val;
	enum buxton_key_type type;
	int32_t i;
	uint32_t u;
	int64_t i64;
	uint64_t u64;
	double d;
	int32_t b;

	type = get_type(atype);
	switch (type) {
	case BUXTON_TYPE_STRING:
		printf("String [%s]\n", arg);
		val = buxton_value_create_string(arg);
		break;
	case BUXTON_TYPE_INT32:
		i = strtol(arg, NULL, 0);
		printf("Int32  [%d]\n", i);
		val = buxton_value_create_int32(i);
		break;
	case BUXTON_TYPE_UINT32:
		u = strtoul(arg, NULL, 0);
		printf("Uint32 [%u]\n", u);
		val = buxton_value_create_uint32(u);
		break;
	case BUXTON_TYPE_INT64:
		i64 = strtoll(arg, NULL, 0);
		printf("Int64  [%" PRId64 "]\n", i64);
		val = buxton_value_create_int64(i64);
		break;
	case BUXTON_TYPE_UINT64:
		u64 = strtoull(arg, NULL, 0);
		printf("Uint64 [%" PRIu64 "]\n", u64);
		val = buxton_value_create_uint64(u64);
		break;
	case BUXTON_TYPE_DOUBLE:
		d = strtod(arg, NULL);
		printf("Double [%lf]\n", d);
		val = buxton_value_create_double(d);
		break;
	case BUXTON_TYPE_BOOLEAN:
		if (!strcasecmp(arg, "true"))
			b = 1;
		else if (!strcasecmp(arg, "false"))
			b = 0;
		else
			b = strtol(arg, NULL, 0);

		printf("Boolean [%s]\n", b ? "True" : "False");
		val = buxton_value_create_boolean(b);
		break;
	default:
		printf("Unknown type [%s] [%s]\n", atype, arg);
		val = NULL;
		break;
	}

	return val;
}

static void set_resp(int status, const struct buxton_layer *layer,
		const char *key, const struct buxton_value *val, void *data)
{
	GMainLoop *loop = data;

	/* quit event loop */
	g_main_loop_quit(loop);

	printf("Response callback: Layer [%s] key [%s] status %d\n",
			buxton_layer_get_name(layer), key, status);
	if (status) {
		errno = status;
		perror("buxton_set_value");
		return;
	}

	/* val is set to NULL when callback is invoked by buxton_set_value */
	printf("Value set is done\n");
}

int main(int argc, char *argv[])
{
	int r;
	struct buxton_client *cli;
	struct buxton_layer *layer;
	const char *key;
	struct buxton_value *val;
	GMainLoop *loop;

	if (argc < 5) {
		printf(" usage) %s layer key type value\n", argv[0]);
		printf("  type:\n");
		printf("    {string|int32|uint32|int64|uint64|double|bool}\n");
		printf("\n");
		printf(" ex)");
		printf("  %s system db/menu_widget/lanugage string \"\"\n",
				argv[0]);
		printf("\n");
		return EXIT_FAILURE;
	}

	loop = g_main_loop_new(NULL, FALSE);

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

	printf("Layer [%s]\n", buxton_layer_get_name(layer));
	printf("Key   [%s]\n", key);

	val = arg_to_val(argv[3], argv[4]);
	if (!val) {
		buxton_free_layer(layer);
		buxton_close(cli);
		return EXIT_FAILURE;
	}

	r = buxton_set_value(cli, layer, key, val, set_resp, loop);
	if (r) {
		perror("buxton_set_value");
		buxton_free_layer(layer);
		buxton_close(cli);
		return EXIT_FAILURE;
	}
	buxton_value_free(val);
	buxton_free_layer(layer);

	g_main_loop_run(loop);
	g_main_loop_unref(loop);

	r = buxton_close(cli);
	if (r)
		perror("buxton_close");

	return EXIT_SUCCESS;
}

