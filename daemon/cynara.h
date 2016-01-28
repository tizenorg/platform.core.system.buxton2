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

#include <sys/types.h>

int buxton_cynara_init(void);
void buxton_cynara_exit(void);

enum buxton_cynara_res {
	BUXTON_CYNARA_ERROR = -1,
	BUXTON_CYNARA_UNKNOWN,
	BUXTON_CYNARA_ALLOWED,
	BUXTON_CYNARA_DENIED,
	BUXTON_CYNARA_CANCELED,
	BUXTON_CYNARA_MAX /* sentinel value */
};

struct bxt_client;

typedef void (*buxton_cynara_callback)(struct bxt_client *client,
		enum buxton_cynara_res res, void *user_data);

enum buxton_cynara_res buxton_cynara_check(struct bxt_client *client,
		const char *client_label, const char *session,
		uid_t uid, const char *priv,
		int pid, const char *key,
		buxton_cynara_callback callback, void *user_data);

void buxton_cynara_cancel(struct bxt_client *client);

