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

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <glib.h>
#include <gdbm.h>

#include "backend.h"
#include "log.h"

static GHashTable *dbs;

static void free_db(GDBM_FILE db)
{
	if (!db)
		return;

	gdbm_close(db);
}

static GDBM_FILE open_gdbm(const char *dbpath)
{
	GDBM_FILE db;
	char *nm;

	assert(dbpath);

	if (!dbs) {
		errno = ENODEV;
		return NULL;
	}

	db = g_hash_table_lookup(dbs, dbpath);
	if (db)
		return db;

	nm = strdup(dbpath);
	if (!nm) {
		errno = ENOMEM;
		return NULL;
	}

	db = gdbm_open(nm, 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, NULL);
	if (!db) {
		bxt_err("Open '%s' failed: %s", dbpath,
				gdbm_strerror(gdbm_errno));
		errno = EIO;
		return NULL;
	}

	g_hash_table_insert(dbs, nm, db);

	bxt_dbg("Open '%s'", dbpath);

	return db;
}

static int open_db(const char *dbpath)
{
	GDBM_FILE db;

	if (!dbpath || !*dbpath) {
		errno = EINVAL;
		return -1;
	}

	db = open_gdbm(dbpath);
	if (!db)
		return -1;

	return 0;
}

static int remove_db(const char *dbpath)
{
	GDBM_FILE db;
	int r;

	if (!dbpath || !*dbpath) {
		errno = EINVAL;
		return -1;
	}

	if (!dbs) {
		errno = ENODEV;
		return -1;
	}

	db = g_hash_table_lookup(dbs, dbpath);
	if (db)
		g_hash_table_remove(dbs, dbpath);

	r = unlink(dbpath);
	if (r == -1) {
		bxt_err("Remove '%s' failed: %d", dbpath, errno);
		return -1;
	}

	bxt_dbg("Remove '%s'", dbpath);

	return 0;
}

static int set_value(const char *dbpath, const char *key, const void *data,
		int dlen)
{
	GDBM_FILE db;
	int r;
	datum d_key;
	datum d_data;

	if (!dbpath || !*dbpath || !key || !*key || !data || dlen <= 0) {
		errno = EINVAL;
		return -1;
	}

	db = open_gdbm(dbpath);
	if (!db)
		return -1;

	d_key.dptr = (char *)key;
	d_key.dsize = strlen(key) + 1;

	d_data.dptr = (char *)data;
	d_data.dsize = dlen;

	r = gdbm_store(db, d_key, d_data, GDBM_REPLACE);
	if (r) {
		if (gdbm_errno == GDBM_READER_CANT_STORE)
			errno = EROFS;

		bxt_err("Set '%s' failed: %s", key,
				gdbm_strerror(gdbm_errno));

		return -1;
	}

	bxt_dbg("Set '%s' Key '%s'", dbpath, key);

	return 0;
}

static int get_value(const char *dbpath, const char *key, void **data,
		int *dlen)
{
	GDBM_FILE db;
	datum d_key;
	datum d_data;

	if (!dbpath || !*dbpath || !key || !*key || !data || !dlen) {
		errno = EINVAL;
		return -1;
	}

	db = open_gdbm(dbpath);
	if (!db)
		return -1;

	d_key.dptr = (char *)key;
	d_key.dsize = strlen(key) + 1;

	d_data = gdbm_fetch(db, d_key);
	if (d_data.dptr == NULL) {
		errno = ENOENT;
		return -1;
	}

	*data = d_data.dptr;
	*dlen = d_data.dsize;

	bxt_dbg("Get '%s' Key '%s'", dbpath, key);

	return 0;
}

static int unset_value(const char *dbpath, const char *key)
{
	GDBM_FILE db;
	int r;
	datum d_key;

	if (!dbpath || !*dbpath || !key || !*key) {
		errno = EINVAL;
		return -1;
	}

	db = open_gdbm(dbpath);
	if (!db)
		return -1;

	d_key.dptr = (char *)key;
	d_key.dsize = strlen(key) + 1;

	r = gdbm_delete(db, d_key);
	if (r) {
		switch (gdbm_errno) {
		case GDBM_READER_CANT_DELETE:
			errno = EROFS;
			break;
		case GDBM_ITEM_NOT_FOUND:
			errno = ENOENT;
			break;
		default:
			errno = EIO;
			break;
		}

		return -1;
	}

	bxt_dbg("Unset '%s' Key '%s'", dbpath, key);

	return 0;
}

static int list_keys(const char *dbpath, char ***keys, unsigned int *klen)
{
	GDBM_FILE db;
	GList *list;
	GList *l;
	datum d_key;
	int i;
	unsigned int _klen;
	char **_keys;

	if (!dbpath || !*dbpath || !keys) {
		errno = EINVAL;
		return -1;
	}

	db = open_gdbm(dbpath);
	if (!db)
		return -1;

	_klen = 0;
	list = NULL;
	d_key = gdbm_firstkey(db);
	while (d_key.dptr) {
		list = g_list_append(list, d_key.dptr);
		_klen++;
		d_key = gdbm_nextkey(db, d_key);
	}

	/* +1 for NULL terminated */
	_keys = malloc(sizeof(void *) * (_klen + 1));
	if (!_keys) {
		g_list_free_full(list, (GDestroyNotify)free);
		errno = ENOMEM;
		return -1;
	}

	for (i = 0, l = list; l && i < _klen; l = g_list_next(l), i++)
		_keys[i] = l->data;

	/* NULL terminated */
	_keys[i] = NULL;

	g_list_free(list);

	*keys = _keys;

	if (klen)
		*klen = _klen;

	bxt_dbg("List '%s'", dbpath);

	return 0;
}

static void module_exit(void)
{
	g_hash_table_destroy(dbs);
	dbs = NULL;
}

static int module_init(void)
{
	dbs = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)free, (GDestroyNotify)free_db);
	if (!dbs) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

DEFINE_BUXTON_BACKEND = {
	.name = "gdbm",

	.module_init = module_init,
	.module_exit = module_exit,

	.open_db = open_db,
	.remove_db = remove_db,
	.set_value = set_value,
	.get_value = get_value,
	.unset_value = unset_value,
	.list_keys = list_keys,
};

