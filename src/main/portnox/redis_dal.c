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

/* shared secret redis dal */
int get_shared_secret_for_client(const char *client, char **val) {
    return do_get_for_client(client, val, portnox_config.redis.keys.shared_secret_key_format);
}
int set_shared_secret_for_client(const char *client, const char *val) {
    return do_set_for_client(client, val, 1, portnox_config.redis.keys.shared_secret_key_format);
}
int get_shared_secret_for_port(const int port, char **val) {
    return do_get_for_port(port, val, &get_shared_secret_for_client);
}
int set_shared_secret_for_port(const int port, const char *val) {
    return do_set_for_port(port, val, 1, &set_shared_secret_for_client);
}

/* organization id redis dal */
int get_org_id_for_client(const char *client, char **val) {
    return do_get_for_client(client, val, portnox_config.redis.keys.org_id_key_format);
}
int set_org_id_for_client(const char *client, const char *val) {
    return do_set_for_client(client, val, 0, portnox_config.redis.keys.org_id_key_format);
}
int get_org_id_for_port(const int port, char **val) {
    return do_get_for_port(port, val, &get_org_id_for_client);
}
int set_org_id_for_port(const int port, const char *val) {
    return do_set_for_port(port, val, 0, &set_org_id_for_client);
}

int do_set_for_client(const char *client, const char *val, int need_ttl, char* format) {
    int result;
    dstr key;

    key = dstr_from_fmt(format, client);
    if (need_ttl) {
        result = redis_setex(dstr_to_cstr(&key), val, portnox_config.redis.keys.cache_ttl);
    } else {
        result = redis_set(dstr_to_cstr(&key), val);
    }

    dstr_destroy(&key);

    return result;
}
int do_get_for_client(const char *client, const char **val, char* format) {
    int result;
    dstr key;

    key = dstr_from_fmt(format, client);
    result = redis_get(dstr_to_cstr(&key), val);

    dstr_destroy(&key);

    return result;
}
int do_set_for_port(const int port, const char *val, int need_ttl, int (*setter)(const char*, const char*)) {
    int result;
    dstr client;

    client = dstr_from_fmt("%d", port);
    result = setter(dstr_to_cstr(&client), val);

    dstr_destroy(&client);

    return result;
}
int do_get_for_port(const int port, char **val, int (*getter)(const char*, const char*)) {
    int result;
    dstr client;

    client = dstr_from_fmt("%d", port);
    result = getter(dstr_to_cstr(&client), val);

    dstr_destroy(&client);

    return result;
}