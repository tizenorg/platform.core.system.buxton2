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
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include <glib.h>

#include "buxton2.h"

#include "c_log.h"
#include "c_proc.h"
#include "c_direct.h"

struct options {
	char *confpath;
	gboolean direct;
	gboolean install;
	gint uid;
	gboolean help;
};

typedef int (*comm_func)(const struct buxton_layer *layer,
		const char *key, const char *value,
		const char *rpriv, const char *wpriv);

struct command {
	const char *name;
	const char *summary;
	int nargs;
	const char *usage;
	comm_func func;
	comm_func dfunc;
};

static const struct command const commands[] = {
	{
		.name    = "check",
		.summary = "Check the availability of Buxton",
		.nargs   = 0,
		.usage   = "",
		.func    = c_check,
		.dfunc   = c_check,
	},
	{
		.name    = "get",
		.summary = "Get a value by key",
		.nargs   = 2,
		.usage   = "LAYER KEY",
		.func    = c_get,
		.dfunc   = c_direct_get,
	},
	{
		.name    = "create-string",
		.summary = "Create a key with a string value",
		.nargs   = 5,
		.usage   = "LAYER KEY VALUE READ_PRIV WRITE_PRIV",
		.func    = c_create_str,
		.dfunc   = c_direct_create_str,
	},
	{
		.name    = "create-int32",
		.summary = "Create a key with an int32_t value",
		.nargs   = 5,
		.usage   = "LAYER KEY VALUE READ_PRIV WRITE_PRIV",
		.func    = c_create_int32,
		.dfunc   = c_direct_create_int32,
	},
	{
		.name    = "create-uint32",
		.summary = "Create a key with an uint32_t value",
		.nargs   = 5,
		.usage   = "LAYER KEY VALUE READ_PRIV WRITE_PRIV",
		.func    = c_create_uint32,
		.dfunc   = c_direct_create_uint32,
	},
	{
		.name    = "create-int64",
		.summary = "Create a key with an int64_t value",
		.nargs   = 5,
		.usage   = "LAYER KEY VALUE READ_PRIV WRITE_PRIV",
		.func    = c_create_int64,
		.dfunc   = c_direct_create_int64,
	},
	{
		.name    = "create-uint64",
		.summary = "Create a key with an uint64_t value",
		.nargs   = 5,
		.usage   = "LAYER KEY VALUE READ_PRIV WRITE_PRIV",
		.func    = c_create_uint64,
		.dfunc   = c_direct_create_uint64,
	},
	{
		.name    = "create-double",
		.summary = "Create a key with a double precision value",
		.nargs   = 5,
		.usage   = "LAYER KEY VALUE READ_PRIV WRITE_PRIV",
		.func    = c_create_double,
		.dfunc   = c_direct_create_double,
	},
	{
		.name    = "create-bool",
		.summary = "Create a key with a boolean value",
		.nargs   = 5,
		.usage   = "LAYER KEY VALUE READ_PRIV WRITE_PRIV",
		.func    = c_create_bool,
		.dfunc   = c_direct_create_bool,
	},
	{
		.name    = "set-string",
		.summary = "Set a key with a string value",
		.nargs   = 3,
		.usage   = "LAYER KEY VALUE",
		.func    = c_set_str,
		.dfunc   = c_direct_set_str,
	},
	{
		.name    = "set-int32",
		.summary = "Set a key with an int32_t value",
		.nargs   = 3,
		.usage   = "LAYER KEY VALUE",
		.func    = c_set_int32,
		.dfunc   = c_direct_set_int32,
	},
	{
		.name    = "set-uint32",
		.summary = "Set a key with an uint32_t value",
		.nargs   = 3,
		.usage   = "LAYER KEY VALUE",
		.func    = c_set_uint32,
		.dfunc   = c_direct_set_uint32,
	},
	{
		.name    = "set-int64",
		.summary = "Set a key with an int64_t value",
		.nargs   = 3,
		.usage   = "LAYER KEY VALUE",
		.func    = c_set_int64,
		.dfunc   = c_direct_set_int64,
	},
	{
		.name    = "set-uint64",
		.summary = "Set a key with an uint64_t value",
		.nargs   = 3,
		.usage   = "LAYER KEY VALUE",
		.func    = c_set_uint64,
		.dfunc   = c_direct_set_uint64,
	},
	{
		.name    = "set-double",
		.summary = "Set a key with a double precision value",
		.nargs   = 3,
		.usage   = "LAYER KEY VALUE",
		.func    = c_set_double,
		.dfunc   = c_direct_set_double,
	},
	{
		.name    = "set-bool",
		.summary = "Set a key with a boolean value",
		.nargs   = 3,
		.usage   = "LAYER KEY VALUE",
		.func    = c_set_bool,
		.dfunc   = c_direct_set_bool,
	},
	{
		.name    = "get-read-priv",
		.summary = "Get a value's read privilege",
		.nargs   = 2,
		.usage   = "LAYER KEY",
		.func    = c_get_rpriv,
		.dfunc   = c_direct_get_rpriv,
	},
	{
		.name    = "set-read-priv",
		.summary = "Set a value's read privilege",
		.nargs   = 3,
		.usage   = "LAYER KEY PRIVILEGE",
		.func    = c_set_rpriv,
		.dfunc   = c_direct_set_rpriv,
	},
	{
		.name    = "get-write-priv",
		.summary = "Get a value's write privilege",
		.nargs   = 2,
		.usage   = "LAYER KEY",
		.func    = c_get_wpriv,
		.dfunc   = c_direct_get_wpriv,
	},
	{
		.name    = "set-write-priv",
		.summary = "Set a value's write privilege",
		.nargs   = 3,
		.usage   = "LAYER KEY PRIVILEGE",
		.func    = c_set_wpriv,
		.dfunc   = c_direct_set_wpriv,
	},
	{
		.name    = "unset",
		.summary = "Unset a value by key",
		.nargs   = 2,
		.usage   = "LAYER KEY",
		.func    = c_unset,
		.dfunc   = c_direct_unset,
	},
	{
		.name    = "list-keys",
		.summary = "List the keys for a layer",
		.nargs   = 1,
		.usage   = "LAYER",
		.func    = c_list,
		.dfunc   = c_direct_list,
	},
	{
		.name    = "security-enable",
		.summary = "Enable security check",
		.nargs   = 0,
		.usage   = "",
		.func    = c_cyn_enable,
		.dfunc   = c_cyn_enable,
	},
	{
		.name    = "security-disable",
		.summary = "Disable security check",
		.nargs   = 0,
		.usage   = "",
		.func    = c_cyn_disable,
		.dfunc   = c_cyn_disable,
	},
};

static const struct command *find_comm(const char *name)
{
	int i;

	if (!name)
		return NULL;

	for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
		if (commands[i].name && !strcmp(name, commands[i].name))
			return &commands[i];
	}

	return NULL;
}

static int get_layer(const char *lnm, uid_t uid, enum buxton_layer_type type,
		struct buxton_layer **layer)
{
	struct buxton_layer *_layer;

	if (lnm) {
		_layer = buxton_create_layer(lnm);
		if (!_layer) {
			bxt_err("create layer '%s' error", lnm);
			return -1;
		}
	} else {
		_layer = NULL;
	}

	if (!_layer) {
		*layer = NULL;
		return 0;
	}

	if (uid == 0)
		uid = getuid();

	buxton_layer_set_uid(_layer, uid);
	buxton_layer_set_type(_layer, type);

	*layer = _layer;

	return 0;
}

static void print_usage(const char *name, const struct command *comm)
{
	assert(name);
	assert(comm);
	printf(" Usage: %s [option] %s %s\n\n", name, comm->name, comm->usage);
}

static void usage(const char *name)
{
	int i;

	printf(" Usage: %s [option] [command] ...\n\n", name);
	printf("  Option:\n");
	printf("   -c, --config-file=[FILE]  Path to configuration file\n");
	printf("                             (direct access only)\n");
	printf("   -d, --direct              Directly access the database\n");
	printf("   -i, --install             Execute on BASE db used for\n");
	printf("                             the default value\n");
	printf("   -u, --uid=[UID]           Specify the UID\n");
	printf("   -h, --help                Display help and exit\n\n");
	printf("  Command:\n");

	for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
		printf("%16s - %s\n", commands[i].name, commands[i].summary);

	printf("\n");
	printf("  Example:\n");
	printf("   - Get value\n");
	printf("    $ %s get system bluetooth/status\n", name);
	printf("   - Set an empty string\n");
	printf("    $ %s set-string system home/language \"\"\n", name);
	printf("   - Set a negative value\n");
	printf("    $ %s set-int32 system wifi/status -1\n", name);
	printf("\n");

	exit(EXIT_FAILURE);
}

static int parse_args(gint *argc, gchar ***argv, struct options *opt)
{
	GError *err;
	gboolean b;
	GOptionContext *optctx;
	GOptionEntry entries[] = {
		{ "config-file", 'c', 0,
			G_OPTION_ARG_STRING, &opt->confpath, NULL, NULL },
		{ "direct", 'd', 0,
			G_OPTION_ARG_NONE, &opt->direct, NULL, NULL },
		{ "install", 'i', 0,
			G_OPTION_ARG_NONE, &opt->install, NULL, NULL },
		{ "uid", 'u', 0,
			G_OPTION_ARG_INT, &opt->uid, NULL, NULL },
		{ "help", 'h', 0,
			G_OPTION_ARG_NONE, &opt->help, NULL, NULL },
		{ NULL }
	};

	assert(argc);
	assert(argv);
	assert(*argv);
	assert(**argv);

	optctx = g_option_context_new(NULL);
	if (!optctx) {
		bxt_err("option new error");
		return -1;
	}

	g_option_context_add_main_entries(optctx, entries, NULL);
	g_option_context_set_help_enabled(optctx, FALSE);
	g_option_context_set_ignore_unknown_options(optctx, TRUE);

	err = NULL;
	b = g_option_context_parse(optctx, argc, argv, &err);
	g_option_context_free(optctx);

	if (!b) {
		bxt_err("option parse error: %s", err->message);
		usage(**argv);
		g_clear_error(&err);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int r;
	const struct command *comm;
	comm_func func;
	struct buxton_layer *layer;
	struct options opt = {
		.confpath = NULL,
		.direct = FALSE,
		.install = FALSE,
		.uid = 0,
		.help = FALSE,
	};

	r = parse_args(&argc, &argv, &opt);
	if (r == -1)
		return EXIT_FAILURE;

	if (opt.help || argc < 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	comm = find_comm(argv[1]);
	if (!comm) {
		bxt_err("Unknown command '%s'", argv[1]);
		return EXIT_FAILURE;
	}

	func = opt.direct ? comm->dfunc : comm->func;
	if (!func) {
		bxt_err("Command '%s' not supported", comm->name);
		return EXIT_FAILURE;
	}

	if (argc - 2 < comm->nargs) {
		print_usage(argv[0], comm);
		return EXIT_FAILURE;
	}

	if (opt.direct && opt.confpath)
		c_direct_set_conf(opt.confpath);

	r = get_layer(argc > 2 ? argv[2] : NULL, (uid_t)opt.uid,
			opt.install ? BUXTON_LAYER_BASE : BUXTON_LAYER_NORMAL,
			&layer);
	if (r == -1)
		return EXIT_FAILURE;

	assert(func);
	r = func(layer, argc > 3 ? argv[3] : NULL,
			argc > 4 ? argv[4] : NULL,
			argc > 5 ? argv[5] : NULL,
			argc > 6 ? argv[6] : NULL);

	buxton_free_layer(layer);

	if (r == -1)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

