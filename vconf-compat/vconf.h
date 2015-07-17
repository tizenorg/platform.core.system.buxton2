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

#ifndef __VCONF_H__
#define __VCONF_H__

#include <errno.h>

#include "vconf-keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VCONF_OK 0
#define VCONF_ERROR -1
#define VCONF_ERROR_FILE_NO_ENT -ENOENT
#define VCONF_ERROR_FILE_PERM -EPERM

enum vconf_t {
	VCONF_TYPE_NONE = 0, /**< Vconf none type for Error detection */
	VCONF_TYPE_STRING = 40, /**< Vconf string type */
	VCONF_TYPE_INT = 41, /**< Vconf integer type */
	VCONF_TYPE_DOUBLE = 42, /**< Vconf double type */
	VCONF_TYPE_BOOL = 43, /**< Vconf boolean type */
	VCONF_TYPE_DIR /**< Vconf directory type */
};

/**
 * keynode_t key node structure
 */
typedef struct _keynode_t keynode_t;

/**
 * Get the name of key
 *
 * @param[in] keynode Key node
 * @return the name
 * @deprecated use buxton APIs
 */
char *vconf_keynode_get_name(keynode_t *keynode);

/**
 * Get the type of key
 *
 * @param[in] keynode Key node
 * @return the type
 * @deprecated use buxton APIs
 */
int vconf_keynode_get_type(keynode_t *keynode);

/**
 * Get an integer value of key
 *
 * @param[in] keynode Key node
 * @return An integer value
 * @deprecated use buxton APIs
 */
int vconf_keynode_get_int(keynode_t *keynode);

/**
 * Get a double-precision float value of key
 *
 * @param[in] keynode Key node
 * @return A double-precision float value
 * @deprecated use buxton APIs
 */
double vconf_keynode_get_dbl(keynode_t *keynode);

/**
 * Get a boolean value of key
 *
 * @param[in] keynode Key node
 * @return a boolean value
 * @deprecated use buxton APIs
 */
int vconf_keynode_get_bool(keynode_t *keynode);

/**
 * Get a string value of key
 *
 * @param[in] keynode Key node
 * @return a string value
 * @deprecated use buxton APIs
 */
char *vconf_keynode_get_str(keynode_t *keynode);

/**
 * The type of function which is called when a key is changed
 *
 * @param[in] keynode Key node
 * @param[in] user_data data passed to callback function
 */
typedef void (*vconf_callback_fn)(keynode_t *keynode, void *user_data);

/**
 * Add a callback function which is called when a key is changed
 *
 * @param[in] key the name of key
 * @param[in] cb callback function
 * @param[in] user_data data passed to callback function
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_notify_key_changed(const char *key, vconf_callback_fn cb,
		void *user_data);

/**
 * Remove a change callback function
 *
 * @param[in] key the name of key
 * @param[in] cb callback function
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_ignore_key_changed(const char *key, vconf_callback_fn cb);

/**
 * Set an integer value
 *
 * @param[in] key the name of key
 * @param[in] intval an integer value
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_set_int(const char *key, int intval);

/**
 * Set a boolean value
 *
 * @param[in] key the name of key
 * @param[in] boolval a boolean value
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_set_bool(const char *key, int boolval);

/**
 * Set a string value
 *
 * @param[in] key the name of key
 * @param[in] strval a string value
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_set_str(const char *key, const char *strval);

/**
 * Set a double-precision float value
 *
 * @param[in] key the name of key
 * @param[in] dblval a double value
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_set_dbl(const char *key, double dblval);

/**
 * Get an integer value
 *
 * @param[in] key the name of key
 * @param[out] intval a pointer to an integer value to be set
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_get_int(const char *key, int *intval);

/**
 * Get a boolean value
 *
 * @param[in] key the name of key
 * @param[out] boolval a pointer to a boolean value to be set
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_get_bool(const char *key, int *boolval);

/**
 * Get a string value
 *
 * @param[in] key the name of key
 * @return a string on success (should be freed by free()), NULL on error
 * @deprecated use buxton APIs
 */
char *vconf_get_str(const char *key);

/**
 * Get a double-precision float value
 *
 * @param[in] key the name of key
 * @param[out] dblval a pointer to a double value to be set
 * @return 0 on success, -1 on error
 * @deprecated use buxton APIs
 */
int vconf_get_dbl(const char *key, double *dblval);

/**
 * Get an error code of the last API call
 *
 * @return error code
 * @deprecated use buxton APIs
 */
int vconf_get_ext_errno(void);


/**
 * keylist_t
 */
typedef struct _keylist_t keylist_t;

keylist_t *vconf_keylist_new(void);
int vconf_keylist_free(keylist_t *keylist);

int vconf_keylist_add_int(keylist_t *keylist, const char *keyname, int value);
int vconf_keylist_add_bool(keylist_t *keylist, const char *keyname, int value);
int vconf_keylist_add_dbl(keylist_t *keylist,
		const char *keyname, double value);
int vconf_keylist_add_str(keylist_t *keylist,
		const char *keyname, const char *value);
int vconf_keylist_del(keylist_t *keylist, const char *keyname);

enum get_option_t {
	VCONF_GET_KEY = 0,
	VCONF_GET_ALL,
	VCONF_GET_DIR,
};
typedef enum get_option_t get_option_t;

int vconf_get(keylist_t *keylist,
		const char *in_parentDIR, get_option_t option);
int vconf_set(keylist_t *keylist);

int vconf_keylist_lookup(keylist_t *keylist, const char *keyname,
		keynode_t **return_node);

#ifdef __cplusplus
}
#endif

#endif /* __VCONF_H__ */