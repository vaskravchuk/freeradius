/*
 * portnox_config.h	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSIDH(portnox_config_h, "$Id$")

#include <freeradius-devel/radiusd.h>

extern struct portnox_config_t portnox_config;

typedef struct portnox_redis_keys_config_t {
	int							cache_ttl;
	char						*shared_secret_key_format;
	char						*org_id_key_format;
	char						*response_key_format;
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
	int							timeout;
	int							need_auth_cache_for_error;
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