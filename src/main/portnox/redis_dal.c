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

#include <stdio.h>
#include <string.h>

#define PORTNOX_INNER_PORT "18122"

static int do_set_for_key_format(const char *key_part, const char *val, int need_ttl, char* format);
static int do_get_for_key_format(const char *client, const char **val, char* format);
static int do_set_for_port(const int port, const char *val, int need_ttl, int (*setter)(const char*, const char*));
static int do_get_for_port(const int port, char **val, int (*getter)(const char*, const char*));

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
int get_response_for_request(REQUEST *request, char **val) {
    *val = "";
}
int set_response_for_request(REQUEST *request, const char *val) {
}

static int do_set_for_key_format(const char *key_part, const char *val, int need_ttl, char* format) {
    int result;
    dstr key;

    key = dstr_from_fmt(format, key_part);
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
    if (strcmp(client, PORTNOX_INNER_PORT) == 0) {
        *val = strdup(portnox_config.be.cluster_id);
    }
    else {
        key = dstr_from_fmt(format, key_part);
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