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

#include <stdint.h>

#include "buxton2.h"

#include "common.h"

int check_key_name(const char *key);

int serialz_data(const char *rpriv, const char *wpriv,
		const struct buxton_value *val,
		uint8_t **data, int *len);

int deserialz_data(uint8_t *data, int len,
		char **rpriv, char **wpriv, struct buxton_value *val);


struct request {
	enum message_type type;
	uint32_t msgid;
	struct buxton_layer *layer;
	char *rpriv;
	char *wpriv;
	char *key;
	struct buxton_value *val;
};

int serialz_request(const struct request *req, uint8_t **data, int *len);

int deserialz_request(uint8_t *data, int len, struct request *req);

void free_request(struct request *req);


int serialz_response(enum message_type type, uint32_t msgid, int32_t res,
		const struct buxton_value *val, uint32_t nmlen,
		char * const *names, uint8_t **data, int *len);

struct response {
	enum message_type type;
	uint32_t msgid;
	int32_t res;
	struct buxton_value *val;
	uint32_t nmlen;
	char **names;
};

int deserialz_response(uint8_t *data, int len, struct response *res);

void free_response(struct response *res);

