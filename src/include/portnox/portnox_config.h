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

extern struct portnox_conf_t portnox_config;

typedef struct portnox_redis_keys_config_t {
	int							cache_ttl;
	char						*shared_secret_key_format;
	char						*org_id_key_format;
} PORTNOX_REDIS_KEYS_CONFIG_T;

typedef struct portnox_redis_config_t {
	char						*srv_addr;
	int							srv_port;
	int							srv_timeout;
	char						*srv_pwd;
	int							srv_db;
	PORTNOX_REDIS_KEYS_CONFIG_T	keys;
} PORTNOX_REDIS_CONFIG_T;

typedef struct portnox_be_config_t {
	char						*cluster_id;
	char						*req_crt;
	char						*req_crt_pwd;
	char						*caller_info_url;
	char						*auth_url;
	char						*event_url;
} PORTNOX_BE_CONFIG_T;

typedef struct portnox_log_config_t {
	int							allow_auth_flow_log;
	char						*log_script;
} PORTNOX_LOG_CONFIG_T;


typedef struct portnox_config_t {
	PORTNOX_REDIS_CONFIG_T		redis;
	PORTNOX_BE_CONFIG_T			be;
	PORTNOX_LOG_CONFIG_T		log;
} PORTNOX_CONFIG_T;