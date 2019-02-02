/*
 * redis_p.c	Execute redis commands.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/portnox/redis_p.h>
#include <freeradius-devel/portnox/dep/credis.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/autoconf.h>

#include <stdio.h>
#include <string.h>

/*
 * Describe redis operation.
 * For closure implementation on C
 */
typedef struct redis_op_info redis_op_info;
struct redis_op_info {
    /* SET redis command */
    int (* processor)(REDIS, redis_op_info*);

    /* redis key */
    const char *key;
    /* redis value (to set or get)*/
    const char *val;
    /* SET redis command */
    int ttl;
};

/* ERROR with creating Redis client */
#define CLIENT_CR_ERROR -10

#include <freeradius-devel/threads.h>

#ifdef HAVE_PTHREAD_H
    #include <pthread.h>
    pthread_mutex_t	client_mutex;
    #define REDIS_CLIENT_LOCK pthread_mutex_lock(&client_mutex)
    #define REDIS_CLIENT_UNLOCK pthread_mutex_unlock(&client_mutex)
#else
    #define REDIS_CLIENT_LOCK
    #define REDIS_CLIENT_UNLOCK
#endif

extern char* redis_srv_addr;
extern int redis_srv_port;
extern int redis_srv_timeout;
extern char* redis_srv_pwd;
extern int redis_srv_db;

static REDIS get_redis_client();
static void invalidate_redis_client();
static int perform_redis_operation(redis_op_info* op);

/*
 * Redis client will be on for all requests,
 * because reconnection takes a lot of time.
 */
REDIS redis_client = NULL;

/* Return redis client. Create new one if invalidated. */
static REDIS get_redis_client() {
    if (redis_client == NULL) {
        /* Create redis client */
        redis_client = credis_connect(redis_srv_addr, redis_srv_port, redis_srv_pwd, redis_srv_timeout);

        /* Select redis DB */
        if (redis_client) credis_select(redis_client, redis_srv_db);
    }
    return redis_client;
}

/* Invalidate our singelton redis client to be recreated. */
static void invalidate_redis_client() {
    if (redis_client) credis_close(redis_client);
    redis_client = NULL;
}

/* redis operation executor */
static int perform_redis_operation(redis_op_info* op) {
    REDIS client = NULL;
    int result = 0;

    /*
     * Redis client is not thread safety.
     * Redis is single thread system
     * so should be OK. But in the future can be make client pool
     * but fo now it's micro optimizations.
     */
    REDIS_CLIENT_LOCK;

    client = get_redis_client();
    if (!client) {
        return CLIENT_CR_ERROR;
    }

    /*
     * Execute operation.
     * I don't want do retrying. To not stuck and block other requests.
     * Better rely on NAS retrying.
     * In case of CREDIS_ERR_NOMEM we should repeat again
     * because of 'credis' already increased buffer for this request
     */
    do {
        result = op->processor(client, op);
    } while (result == CREDIS_ERR_NOMEM);

    /* If error case -> invalidate client, maybe something with connection. */
    if (result <= CREDIS_ERR) {
        invalidate_redis_client();
    }

    REDIS_CLIENT_UNLOCK;

    return result;
}


/* operation wrapper for SET command */
int redis_set_aux(REDIS client, redis_op_info* op_info) {
    return credis_set(client, op_info->key, op_info->val);
}
int redis_set(const char *key, const char *val) {
    int result = 0;
    redis_op_info op_info;
    dstr dkey;
    dstr dval;

    /* Escape key and val strings */
    dkey = dstr_escaped(key);
    dval = dstr_escaped(val);

    op_info = (redis_op_info){redis_set_aux, dstr_to_cstr(&dkey), dstr_to_cstr(&dval), 0, };
    result = perform_redis_operation(&op_info);

    dstr_destroy(&dkey);
    dstr_destroy(&dval);

    return result;
}

/* operation wrapper for SETEX command */
int redis_setex_aux(REDIS client, redis_op_info* op_info) {
    return credis_setex(client, op_info->key, op_info->val, op_info->ttl);
}
int redis_setex(const char *key, const char *val, int ttl) {
    int result = 0;
    redis_op_info op_info;
    dstr dkey;
    dstr dval;

    /* Escape key and val strings */
    dkey = dstr_escaped(key);
    dval = dstr_escaped(val);

    op_info = (redis_op_info){redis_setex_aux, dstr_to_cstr(&dkey), dstr_to_cstr(&dval), ttl};
    result = perform_redis_operation(&op_info);

    dstr_destroy(&dkey);
    dstr_destroy(&dval);

    return result;
}

/* operation wrapper for GET command */
int redis_get_aux(REDIS client, redis_op_info* op_info) {
    return credis_get(client, op_info->key, &op_info->val);
}
int redis_get(const char *key, char **val) {
    int result = 0;
    redis_op_info op_info;
    dstr dkey;

    /* Escape key string */
    dkey = dstr_escaped(key);

    op_info = (redis_op_info){redis_get_aux, dstr_to_cstr(&dkey), NULL, 0};
    result = perform_redis_operation(&op_info);

    /* Escape key string */
    if (result == CREDIS_OK) *val = op_info.val;

    dstr_destroy(&dkey);

    return result;
}

/* operation wrapper for DEL command */
int redis_del_aux(REDIS client, redis_op_info* op_info) {
    return credis_del(client, op_info->key);
}
int redis_del(const char *key) {
    int result = 0;
    redis_op_info op_info;
    dstr dkey;

    /* Escape key string */
    dkey = dstr_escaped(key);

    op_info = (redis_op_info){redis_del_aux, dstr_to_cstr(&dkey), NULL, 0, };
    result = perform_redis_operation(&op_info);

    dstr_destroy(&dkey);

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