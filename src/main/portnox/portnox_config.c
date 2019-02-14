/*
 * portnox_config.c	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/portnox_config.h>

struct portnox_config_t portnox_config;

static const CONF_PARSER portnox_redis_keys_config_nodest[] = {
	{ "cache_ttl", PW_TYPE_INTEGER, 0, &portnox_config.redis.keys.cache_ttl, Stringify(3600) },
	{ "shared_secret_key_format", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.keys.shared_secret_key_format, "ss_%s"},
	{ "org_id_key_format", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.keys.org_id_key_format, "oid_%s"}
	{ "response_key_format", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.keys.response_key_format, "r_%s"},

	{ NULL, -1, 0, NULL, NULL }
};
static const CONF_PARSER portnox_redis_config_nodest[] = {
	{ "srv_addr", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.srv_addr, NULL },
	{ "srv_port", PW_TYPE_INTEGER, 0, &portnox_config.redis.srv_port, Stringify(6379) },
	{ "srv_timeout", PW_TYPE_INTEGER, 0, &portnox_config.redis.srv_timeout, Stringify(500) },
	{ "srv_pwd", PW_TYPE_STRING_PTR, 0, &portnox_config.redis.srv_pwd, NULL},
	{ "srv_db", PW_TYPE_INTEGER, 0, &portnox_config.redis.srv_db, Stringify(0)},
	{ "keys", PW_TYPE_SUBSECTION, 0, NULL, (const void *) portnox_redis_keys_config_nodest },

	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER portnox_be_config_nodest[] = {
	{ "cluster_id", PW_TYPE_STRING_PTR, 0, &portnox_config.be.cluster_id, NULL },
	{ "req_crt", PW_TYPE_STRING_PTR, 0, &portnox_config.be.req_crt, NULL },
	{ "req_crt_pwd", PW_TYPE_STRING_PTR, 0, &portnox_config.be.req_crt_pwd, NULL },
	{ "caller_info_url", PW_TYPE_STRING_PTR, 0, &portnox_config.be.caller_info_url, NULL},
	{ "auth_url", PW_TYPE_STRING_PTR, 0, &portnox_config.be.auth_url, NULL},
	{ "event_url", PW_TYPE_STRING_PTR, 0, &portnox_config.be.event_url, NULL},
	{ "timeout", PW_TYPE_INTEGER, 0, &portnox_config.be.timeout, Stringify(30)},
	{ "need_auth_cache_for_error", PW_TYPE_BOOLEAN, 0, &portnox_config.be.need_auth_cache_for_error, "no"},

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
	{ "log", PW_TYPE_SUBSECTION, 0, NULL, (const void *) portnox_log_config_nodest },

	{ NULL, -1, 0, NULL, NULL }
};