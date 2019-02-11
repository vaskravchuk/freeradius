/*
 * mainconf.c	Handle the server's configuration.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002,2006-2007  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/portnox_config.h>

struct portnox_conf_t portnox_config;

static const CONF_PARSER portnox_redis_keys_config_nodest[] = {
	{ "cache_ttl", PW_TYPE_INTEGER, 0, &portnox_config.redis.keys.cache_ttl, Stringify(3600) },
	{ "shared_secret_key_format", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.keys.redis_srv_pwd, NULL},
	{ "org_id_key_format", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.keys.redis_srv_pwd, NULL}.

	{ NULL, -1, 0, NULL, NULL }
};
static const CONF_PARSER portnox_redis_config_nodest[] = {
	{ "srv_addr", PW_TYPE_BOOLEAN, 0, &portnox_config.redis.srv_addr, NULL },
	{ "srv_port", PW_TYPE_INTEGER, 0, &portnox_config.redis.srv_port, Stringify(6379) },
	{ "srv_timeout", PW_TYPE_INTEGER, 0, &portnox_config.redis.srv_timeout, Stringify(500) },
	{ "srv_pwd", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.srv_pwd, NULL},
	{ "srv_db", PW_TYPE_INTEGER, 0, &portnox_config.redis.srv_db, Stringify(0)},
	{ "keys", PW_TYPE_STRING_PTR, 0, &portnox_redis_keys_config_nodest, NULL},

	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER portnox_be_config_nodest[] = {
	{ "cluster_id", PW_TYPE_STRING_PTR, 0, &portnox_config.be.cluster_id, NULL },
	{ "req_crt", PW_TYPE_STRING_PTR, 0, &portnox_config.be.req_crt, NULL },
	{ "req_crt_pwd", PW_TYPE_STRING_PTR, 0, &portnox_config.be.req_crt_pwd, NULL },
	{ "caller_info_url", PW_TYPE_STRING_PTR, 0, &portnox_config.be.caller_info_url, NULL},
	{ "auth_url", PW_TYPE_STRING_PTR, 0, &portnox_config.be.auth_url, NULL},
	{ "event_url", PW_TYPE_STRING_PTR, 0, &portnox_config.be.event_url, NULL},

	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER portnox_log_config_nodest[] = {
	{ "allow_auth_flow_log", PW_TYPE_BOOLEAN, 0, &portnox_config.log.allow_auth_flow_log, "yes" },
	{ "log_script", PW_TYPE_STRING_PTR, 0, &portnox_config.log.log_script, NULL},

	{ NULL, -1, 0, NULL, NULL }
};

const CONF_PARSER portnox_config_nodest[] = {
	{ "redis", PW_TYPE_SUBSECTION, 0, NULL, (const void *) portnox_redis_config_nodest },
	{ "be", PW_TYPE_SUBSECTION, 0, NULL, (const void *) portnox_be_config_nodest },
	{ "log", PW_TYPE_SUBSECTION, 0, NULL, (const void *) portnox_log_config_nodest }

	{ NULL, -1, 0, NULL, NULL }
};