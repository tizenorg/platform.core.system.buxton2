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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include "common.h"

struct buxton_layer *layer_create(const char *layer_name)
{
	struct buxton_layer *layer;

	if (!layer_name || !*layer_name) {
		errno = EINVAL;
		return NULL;
	}

	layer = calloc(1, sizeof(*layer));
	if (!layer)
		return NULL;

	layer->name = strdup(layer_name);
	if (!layer->name) {
		free(layer);
		return NULL;
	}

	layer->refcnt = 1;
	layer->uid = getuid();
	layer->type = BUXTON_LAYER_NORMAL;

	return layer;
}

/* ignore ref. count */
void layer_free(struct buxton_layer *layer)
{
	if (!layer)
		return;

	free(layer->name);
	free(layer);
}

struct buxton_layer *layer_ref(struct buxton_layer *layer)
{
	if (!layer)
		return NULL;

	layer->refcnt++;

	return layer;
}

struct buxton_layer *layer_unref(struct buxton_layer *layer)
{
	if (!layer)
		return NULL;

	layer->refcnt--;
	if (layer->refcnt == 0) {
		layer_free(layer);
		return NULL;
	}

	return layer;
}

void value_free(struct buxton_value *val)
{
	if (!val)
		return;

	switch (val->type) {
	case BUXTON_TYPE_STRING:
		free(val->value.s);
		break;
	default:
		break;
	}
}

char *get_search_key(const struct buxton_layer *layer, const char *key,
		const char *uid)
{
	char *lykey;
	int keylen;

	if (!layer || !key || !*key) {
		errno = EINVAL;
		return NULL;
	}

	keylen = strlen(layer->name) + strlen(key) + 2;

	if (uid)
		keylen += strlen(uid) + 1;

	lykey = malloc(keylen);
	if (!lykey)
		return NULL;

	snprintf(lykey, keylen, "%s\t%s%s%s", layer->name, key,
			uid ? "\t" : "", uid ? uid : "");

	return lykey;
}

