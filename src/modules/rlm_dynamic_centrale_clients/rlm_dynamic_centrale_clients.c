#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <sys/file.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

#define CALLER_ORG_ID "CallerOrgId"
#define CALLER_SECRET "CallerSecret"

extern char* centrale_baseurl;

char *format_client_output(char *ip, char *port, char *caller_secret);
char *get_shared_secret_key(char* key_buf, char* port);
char *get_centrale_orgid_key(char* key_buf, char* port);

/*
 *      Define a structure for our module configuration.
 */
typedef struct rlm_dynamic_centrale_clients_t {
    char    *program;
    int     *use_script;
} rlm_dynamic_centrale_clients_t;

static const CONF_PARSER module_config[] = {
    { "program",  PW_TYPE_STRING_PTR, offsetof(rlm_dynamic_centrale_clients_t, program), NULL, NULL },
    { "use_script",  PW_TYPE_BOOLEAN, offsetof(rlm_dynamic_centrale_clients_t, use_script), NULL, "no" },
    { NULL, -1, 0, NULL, NULL }
};

static int dynamic_centrale_clients_detach(void *instance)
{
    rlm_dynamic_centrale_clients_t      *inst = instance;
    free(inst);
    return 0;
}

static int dynamic_centrale_clients_instantiate(CONF_SECTION *conf, void **instance)
{
    rlm_dynamic_centrale_clients_t    *inst;
    inst = rad_malloc(sizeof(rlm_dynamic_centrale_clients_t));
    if (!inst) {
        return -1;
    }
    memset(inst, 0, sizeof(rlm_dynamic_centrale_clients_t));
    if (cf_section_parse(conf, inst, module_config) < 0) {
        radlog(L_ERR, "rlm_dynamic_centrale_clients: Failed parsing the configuration");
        dynamic_centrale_clients_detach(inst);
        return -1;
    }
    *instance = inst;
    return 0;
}

static int dynamic_centrale_client_authorize(UNUSED void *instance, REQUEST *request)
{
    CONF_PAIR *cp;
    const char *value;
    RADCLIENT *c;
    char buffer[1024];
    char hostname[256];
    char cmdline[1024];
    rlm_dynamic_centrale_clients_t *inst = instance;
    int result;

    if ((request->packet->vps != NULL) || (request->parent != NULL)) {
        radius_exec_logger_centrale(request, "60015", "rlm_dynamic_centrale_clients: Improper configuration");
        return RLM_MODULE_NOOP;
    }

    if (!request->client || !request->client->cs) {
        radius_exec_logger_centrale(request, "60016", "rlm_dynamic_centrale_clients: Unknown client definition");
        return RLM_MODULE_NOOP;
    }

    cp = cf_pair_find(request->client->cs, "directory");
    if (!cp) {
        radius_exec_logger_centrale(request, "60017", "rlm_dynamic_centrale_clients: No directory configuration in the client");
        return RLM_MODULE_NOOP;
    }

    value = cf_pair_value(cp);
    if (!value) {
        radius_exec_logger_centrale(request, "60018", "rlm_dynamic_centrale_clients: No value given for the directory entry in the client.");
        return RLM_MODULE_NOOP;
    }

    ip_ntoh(&request->packet->src_ipaddr, hostname, sizeof(hostname));

    if ((strlen(hostname) + strlen(value)) >= sizeof(buffer)) {
        radius_exec_logger_centrale(request, "60019", "rlm_dynamic_centrale_clients: Directory name too long");
        return RLM_MODULE_NOOP;
    }

    if (!snprintf(buffer, sizeof(buffer), "%s/%s", value, hostname)) {
        radius_exec_logger_centrale(request, "60020", "rlm_dynamic_centrale_clients: Unable to make cmd line");
        return RLM_MODULE_FAIL;
    }

    if (inst->use_script == 0) {
        if (!snprintf(cmdline, sizeof(cmdline), "%s %d %s %s",  hostname, request->packet->dst_port, buffer, request->context_id)) {
            radius_exec_logger_centrale(request, "60021", "rlm_dynamic_centrale_clients: Unable to make arguments");
            return RLM_MODULE_FAIL;
        }

        result = radius_exec_dynamic_centrale(cmdline, request)

        if (result != 0) {
            return RLM_MODULE_FAIL;
        }

        c = client_read(buffer, (request->client->server != NULL), TRUE);

        if (!c) {
            radius_exec_logger_centrale(request, "60023", "rlm_dynamic_centrale_clients: Internal script failed");
            return RLM_MODULE_FAIL;
        }
    }
    else {
        if (!snprintf(cmdline, sizeof(cmdline), "%s %s %d %s %s", inst->program, hostname, request->packet->dst_port, buffer, request->context_id)) {
            radius_exec_logger_centrale(request, "60021", "rlm_dynamic_centrale_clients: Unable to make cmd line");
            return RLM_MODULE_FAIL;
        }

        result = radius_exec_program_centrale(cmdline, request, TRUE, NULL, 0, EXEC_TIMEOUT, NULL, NULL, FALSE, 60026);

        if (result != 0) {
            radlog(L_DBG, "rlm_dynamic_centrale_clients: External script '%s' failed", cmdline);
            return RLM_MODULE_FAIL;
        }

        c = client_read(buffer, (request->client->server != NULL), TRUE);

        if (!c) {
            radius_exec_logger_centrale(request, "60023", "rlm_dynamic_centrale_clients: External script '%s' failed", cmdline);
            return RLM_MODULE_FAIL;
        }
    }
    request_set_client(request, c);
    return RLM_MODULE_OK;
}


int radius_exec_dynamic_centrale(const char *cmd, REQUEST *request) {
    char *shared_secret;
    char *caller_orgid;
    char *caller_secret;
    char *resp_data;
    char *req_json;
    srv_req client_call_req;
    srv_resp client_call_resp;
    char *shared_secret_key;
    char *centrale_orgid_key;
    int from_cache = 0;
    int result;

    char *args = strtok(cmd, " ");

    get_shared_secret_key(&shared_secret_key, &args[1]);

    result = redis_get(shared_secret_key, &shared_secret);

    if (result == 0) {
        from_cache = 1;
    }

    if (from_cache == 0) {
        radlog(L_INFO, "Dynamic central clients for ip %s port %s from url", args[0], args[1]);

        req_json = (char *) calloc(300, sizeof(char));
        snprintf(req_json, 300 * sizeof(char), "{\"CallerIp\":\"%s\",\"CallerPort\":%s,\"ClusterId\":\"%s\"}",
                 &args[0], &args[1], portnox_config.be.cluster_id);

        client_call_req = req_create(portnox_config.be.caller_info_url, dstr_cstr(req_json), 0, 1);

        client_call_resp = exec_http_request(&client_call_req);

        if (client_call_resp.return_code != 0) {
            radlog(L_ERR, "Failed curl request with error code %d", client_call_resp.return_code);
            return 1;
        }

        resp_data = dstr_to_cstr(&clients_call_resp.data);

        caller_orgid = get_val_by_attr_from_json(resp_data, CALLER_ORG_ID);

        if (!caller_orgid) {
            radius_exec_logger_centrale(request, "60007",
                                        "rlm_dynamic_centrale_clients: Unable to get CallerOrgId for client %s on port %s",
                                        args[0], args[1]);
        }

        caller_secret = get_val_by_attr_from_json(resp_data, CALLER_SECRET);

        if (!caller_secret) {
            radius_exec_logger_centrale(request, "60007",
                                        "rlm_dynamic_centrale_clients: Unable to get CallerSecret for client %s on port %s",
                                        args[0], args[1]);
        }

        req_destroy(&client_call_req);
        resp_destroy(&client_call_resp);
        free(req_json);
    } else {
        caller_secret = shared_secret;
    }

    if (shared_secret) {
        char *client_buffer;

        FILE *output_file = fopen(&args[3], "w");

        client_buffer = format_client_output(&args[0], &args[1], caller_secret);

        fputs(client_buffer, output_file);
        fclose(output_file);
        free(client_buffer);
    }

    if (from_cache == 0) {
        get_centrale_orgid_key(&centrale_orgid_key, &args[1]);
        redis_set(centrale_orgid_key, caller_orgid);
        redis_setex(shared_secret_key, caller_secret, portnox_config.redis.keys.cache_ttl);
    }

    free(centrale_orgid_key);
    free(shared_secret_key);
    free(caller_secret);
    free(caller_orgid);
    return 0;
}

void format_client_output(char* buffer, char*ip, char* port, char* caller_secret) {
    char *client = "client %s {\n"
                   "\tsecret = %s\n"
                   "\tshortname = %s\n"
                   "}";
    snprintf(buffer, sizeof(buffer), client, ip, caller_secret, port);
}

void get_shared_secret_key(char* key_buf, char* port) {
    snprintf(key_buf, sizeof(key_buf), "secret:%s:SHARED_SECRET", port);
}

void get_centrale_orgid_key(char* key_buf, char* port) {
    snprintf(key_buf, sizeof(key_buf), "secret:%s:CENTRALE_ORGID", port);
}


module_t rlm_dynamic_centrale_clients = {
    RLM_MODULE_INIT,
    "dynamic_centrale_clients",
    RLM_TYPE_CHECK_CONFIG_SAFE,                     /* type */
    dynamic_centrale_clients_instantiate,           /* instantiation */
    dynamic_centrale_clients_detach,                /* detach */
    {
        NULL,                                       /* authentication */
        dynamic_centrale_client_authorize,          /* authorization */
        NULL,                                       /* preaccounting */
        NULL,                                       /* accounting */
        NULL,                                       /* checksimul */
        NULL,                                       /* pre-proxy */
        NULL,                                       /* post-proxy */
        NULL                                        /* post-auth */
    },
};
