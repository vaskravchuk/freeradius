/*
 * redis_dal.c	main redis dal operations.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/portnox/redis_client.h>
#include <freeradius-devel/portnox/redis_dal.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/string_helper.h>

#include <stdio.h>
#include <string.h>

#define PORTNOX_INNER_PORT "18122"

static int do_set_for_key_format(const char *key_part, const char *val, int need_ttl, char* format);
static int do_get_for_key_format(const char *client, const char **val, char* format);
static int do_set_for_port(const int port, const char *val, int need_ttl, int (*setter)(const char*, const char*));
static int do_get_for_port(const int port, char **val, int (*getter)(const char*, const char*));
static dstr get_response_key_part(const char* username, const char* mac, const char* port, const char* nas_type);

/* shared secret redis dal */
int get_shared_secret_for_client(const char *client, char **val) {
    return do_get_for_key_format(client, val, portnox_config.redis.keys.shared_secret_key_format);
}
int set_shared_secret_for_client(const char *client, const char *val) {
    return do_set_for_key_format(client, val, 1, portnox_config.redis.keys.shared_secret_key_format);
}
int get_shared_secret_for_port(const int port, char **val) {
    return do_get_for_port(port, val, &get_shared_secret_for_client);
}
int set_shared_secret_for_port(const int port, const char *val) {
    return do_set_for_port(port, val, 1, &set_shared_secret_for_client);
}

/* organization id redis dal */
int get_org_id_for_client(const char *client, char **val) {
    return do_get_for_key_format(client, val, portnox_config.redis.keys.org_id_key_format);
}
int set_org_id_for_client(const char *client, const char *val) {
    return do_set_for_key_format(client, val, 0, portnox_config.redis.keys.org_id_key_format);
}
int get_org_id_for_port(const int port, char **val) {
    return do_get_for_port(port, val, &get_org_id_for_client);
}
int set_org_id_for_port(const int port, const char *val) {
    return do_set_for_port(port, val, 0, &set_org_id_for_client);
}

/* response cache redis dal */
int get_response_for_data(const char* username, const char* mac, const char* port, const char* nas_type, char **val) {
    dstr key_part = {0};
    int result = 0;

    key_part = get_response_key_part(username, mac, port, nas_type);
    result = do_get_for_key_format(dstr_to_cstr(&key_part), val, portnox_config.redis.keys.response_key_format);

    dstr_destroy(&key_part);
    return result;
}
int set_response_for_data(const char* username, const char* mac, const char* port, const char* nas_type, const char *val) {
    dstr key_part = {0};
    int result = 0;

    key_part = get_response_key_part(username, mac, port, nas_type);
    result = do_set_for_key_format(dstr_to_cstr(&key_part), val, 1, portnox_config.redis.keys.response_key_format);

    dstr_destroy(&key_part);
    return result;
}


//${uname}-${MAC}-${PORT}-${nas_type}
static dstr get_response_key_part(const char* username, const char* mac, const char* port, const char* nas_type) {
    char* uname = NULL;
    dstr key = {0};

    if (username) {
        if(!nas_type || !strstr(nas_type, "Ethernet") || !strstr(nas_type, "Wireless")) {
            uname = trim_to_string(username, "#");
        } else {
            uname = strdup(username);
        }
    }

    key = dstr_from_fmt("%s-%s-%s-%s", n_str(uname), n_str(mac), n_str(port), n_str(nas_type));

    if (uname) free(uname);
    return key;
}

static int do_set_for_key_format(const char *key_part, const char *val, int need_ttl, char* format) {
    int result;
    dstr key;

    key = dstr_from_fmt(format, n_str(key_part));
    if (need_ttl) {
        result = redis_setex(dstr_to_cstr(&key), val, portnox_config.redis.keys.cache_ttl);
    } else {
        result = redis_set(dstr_to_cstr(&key), val);
    }

    dstr_destroy(&key);

    return result;
}
static int do_get_for_key_format(const char *key_part, const char **val, char* format) {
    int result = 0;
    dstr key = {0};

    /*
     * in case of PORTNOX_INNER_PORT we use static client
     * so we don't have SHARED_SECRET and CENTRALE_ORGID
     * use CLUSTER_ID as stub value
     */
    if (strcmp(key_part, PORTNOX_INNER_PORT) == 0) {
        *val = strdup(portnox_config.be.cluster_id);
    }
    else {
        key = dstr_from_fmt(format, n_str(key_part));
        result = redis_get(dstr_to_cstr(&key), val);
    }

    dstr_destroy(&key);

    return result;
}
static int do_set_for_port(const int port, const char *val, int need_ttl, int (*setter)(const char*, const char*)) {
    int result;
    dstr client;

    client = dstr_from_fmt("%d", port);
    result = setter(dstr_to_cstr(&client), val);

    dstr_destroy(&client);

    return result;
}
static int do_get_for_port(const int port, char **val, int (*getter)(const char*, const char*)) {
    int result;
    dstr client;

    client = dstr_from_fmt("%d", port);
    result = getter(dstr_to_cstr(&client), val);

    dstr_destroy(&client);

    return result;
}


/* Return string which describes redis Error */
const char* redis_error_descr(int error) {
    switch (error) {
        case CREDIS_OK:
            return "OK";
        case CREDIS_KEY_NOT_FOUND:
            return "Key not found";
        case CLIENT_CR_ERROR:
            return "Failed to create client";
        case CREDIS_ERR:
            return "Redis common error";
        case CREDIS_ERR_NOMEM:
            return "Not enough memory";
        case CREDIS_ERR_RESOLVE:
            return "Host resolve error";
        case CREDIS_ERR_CONNECT:
            return "Connection error";
        case CREDIS_ERR_SEND:
            return "Failed to send data";
        case CREDIS_ERR_RECV:
            return "Failed to receive data";
        case CREDIS_ERR_TIMEOUT:
            return "Timeout";
        case CREDIS_ERR_PROTOCOL:
            return "Protocol error";
        default:
            return "Unknown";
    }
}