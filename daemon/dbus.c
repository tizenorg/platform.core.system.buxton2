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
#include <limits.h>

#include <glib.h>
#include <gio/gio.h>

#include "dbus.h"
#include "common.h"
#include "log.h"
#include "direct.h"

#define LOGIND_INTERFACE "org.freedesktop.login1.Manager"
#define LOGIND_PATH "/org/freedesktop/login1"
#define LOGIND_SIGNAL_USER_REMOVED "UserRemoved"

static GDBusConnection *conn;
static guint s_id;

static void __signal_handler(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	struct buxton_layer *layer;
	guint uid;

	if (g_strcmp0(signal_name, LOGIND_SIGNAL_USER_REMOVED))
		return;

	g_variant_get(parameters, "(uo)", &uid, NULL);
	layer = layer_create("user-memory");
	if (layer) {
		layer->uid = uid;
		direct_remove_db(layer);
		layer_free(layer);
	}
}

static void __bus_get(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	GError *err = NULL;

	conn = g_bus_get_finish(res, &err);
	if (!conn) {
		bxt_err("g_bus_get_sync() is failed. %s", err->message);
		g_error_free(err);
		return;
	}

	s_id = g_dbus_connection_signal_subscribe(conn,
					NULL,
					LOGIND_INTERFACE,
					LOGIND_SIGNAL_USER_REMOVED,
					LOGIND_PATH,
					NULL,
					G_DBUS_SIGNAL_FLAGS_NONE,
					__signal_handler,
					NULL,
					NULL);

	if (s_id == 0) {
		bxt_err("g_dbus_connection_signal_subscribe() is failed.");
		g_object_unref(conn);
	}
}

void buxton_dbus_init(void)
{
	if (!conn)
		g_bus_get(G_BUS_TYPE_SYSTEM, NULL, __bus_get, NULL);
}

void buxton_dbus_exit(void)
{
	if (s_id) {
		g_dbus_connection_signal_unsubscribe(conn, s_id);
		s_id = 0;
	}

	if (conn) {
		g_object_unref(conn);
		conn = NULL;
	}
}

