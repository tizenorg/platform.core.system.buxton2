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

#include "common.h"

#define MSG_FIRST  0x4
#define MSG_MIDDLE 0x2
#define MSG_LAST   0x1
#define MSG_SINGLE (MSG_FIRST | MSG_MIDDLE | MSG_LAST)

#define MSG_MTU    4096

/*
 * Message header (12 bytes) :
 *
 *  +-----------+-----------+-----------+-----------+
 *  |  type (1) | mtype (1) |  Sequence number (2)  |
 *  +-----------+-----------+-----------+-----------+
 *  |               Total length (4)                |
 *  +-----------+-----------+-----------+-----------+
 *  |            Current data length (4)            |
 *  +-----------+-----------+-----------+-----------+
 *  |                  Data ... (n)                 |
 *  +-----------+-----------+-----------+-----------+
 *
 */

struct header {
	uint8_t type; /* one of MSG_XXX */
	uint8_t mtype; /* enum message_type */
	uint16_t seq; /* sequence number */
	uint32_t total; /* total length of message */
	uint32_t len; /* length of current data */
	uint8_t data[0];
} __attribute__((packed));

int proto_send(int fd, enum message_type type, uint8_t *data, int32_t len);
int proto_recv(int fd, enum message_type *type, uint8_t **data, int32_t *len);

typedef void (*recv_callback)(void *user_data,
		enum message_type type, uint8_t *data, int32_t len);
int proto_recv_async(int fd, recv_callback callback, void *user_data);
int proto_send_block(int fd, enum message_type type, uint8_t *data,
		int32_t len);

