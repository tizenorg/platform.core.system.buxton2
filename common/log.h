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

#if defined(_DLOG_H_)

#  define bxt_info(fmt, ...) LOGI(fmt, ##__VA_ARGS__)
#  define bxt_err(fmt, ...) LOGE(fmt, ##__VA_ARGS__)
#  define bxt_dbg(fmt, ...) LOGD(fmt, ##__VA_ARGS__)

#else /* _DLOG_H_ */

#  include <stdio.h>

#  if defined(NDEBUG)

#    define bxt_info(fmt, ...) printf("Buxton: " fmt "\n", ##__VA_ARGS__)
#    define bxt_err(fmt, ...) \
	fprintf(stderr, "Buxton: " fmt "\n", ##__VA_ARGS__)
#    define bxt_dbg(fmt, ...) do { } while (0)

#  else /* NDEBUG */

#    define bxt_info(fmt, ...) printf("Buxton: " fmt "\n", ##__VA_ARGS__)
#    define bxt_err(fmt, ...) \
	fprintf(stderr, "Buxton:Err: " fmt "\n", ##__VA_ARGS__)
#    define bxt_dbg(fmt, ...) \
	printf("Buxton:D:%s:%d: " fmt "\n", __func__, __LINE__, \
			##__VA_ARGS__)

#  endif

#endif /* _DLOG_H_ */
