#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <sys/file.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

extern char* centrale_baseurl;
extern char* cluster_id;
extern char* portnox_crt_path;
extern char* portnox_crt_pwd;

/*
 *      Define a structure for our module configuration.
 */
typedef struct rlm_dynamic_centrale_clients_t {
    char    *program;
    int    *use_internal_script;
} rlm_dynamic_centrale_clients_t;

static const CONF_PARSER module_config[] = {
    { "program",  PW_TYPE_STRING_PTR, offsetof(rlm_dynamic_centrale_clients_t, program), NULL, NULL },
    { "use_internal_script",  PW_TYPE_BOOLEAN, offsetof(rlm_dynamic_centrale_clients_t, use_internal_script), NULL, NULL },
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

    if (inst->use_internal_script == 1) {
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
    char *resp_data;
    dstr req_json;
    srv_req client_call_req;
    srv_resp client_call_resp;
    int from_cache;
    int result;

    char *args = strtok(cmd, " ");

    char shared_secret_key_buf[40];
    char centrale_orgid_key_buf[40];
    char url_buf[150];

    snprintf(url_buf, sizeof(url_buf), "%s/%s", centrale_baseurl, "cloudradius/callers");
    snprintf(shared_secret_key_buf, sizeof(shared_secret_key_buf), "secret:%s:SHARED_SECRET", args[1]);

    result = redis_get(shared_secret_key_buf, &shared_secret);

    if (result == 0) {
        from_cache = 1;
    }
    else {
        radlog(L_ERR, "Problem getting shared secret from redis");
        return 1;
    }

    if (from_cache == 0) {
        radlog(L_INFO, "Dynamic central clients for ip %s port %s from url", args[0], args[1]);

        portnox_auth_request req = {
            .cluster_id = cluster_id,
            .caller_ip = &args[0],
            .caller_port = &args[1]
        };

        req_json = dstr_cstr(create_request_data_json(&req, NULL, 0));

        client_call_req = (srv_req) {
            .url = url_buf,
            .data = req_json,
            .is_debug = 1,
            .need_crt_auth = 1,
            .req_auth_crt_path = portnox_crt_path,
            .req_auth_crt_pwd = portnox_crt_pwd
        };

        client_call_resp = exec_http_request(&client_call_req);

        if (client_call_resp.return_code == 0) {
            resp_data = dstr_to_cstr(&clients_call_resp.data);

            caller_orgid = get_val_by_attr_from_json(data_from_file, "CallerOrgId");

            if (!caller_orgid) {
                radlog(L_ERR, "60007: Unable to get CallerOrgId for client %s on port %s", args[0], args[1]);
            }

            caller_secret = get_val_by_attr_from_json(data_from_file, "CallerSecret");

            if (!caller_secret) {
                radlog(L_ERR, "60007: Unable to get CallerSecret for client %s on port %s", args[0], args[1]);
            }

            req_destroy(&client_call_req);
            resp_destroy(&client_call_resp);
        }
        else {
            radlog(L_ERR, "Failed curl request with error code %d", client_call_resp.return_code);
            return 1;
        }
    } else {
        caller_secret = shared_secret;
    }

    if (shared_secret) {
        FILE *output_file = fopen(&args[3], "w");

        char *client = "client %s {\n"
                       "\tsecret = %s\n"
                       "\tshortname = %s\n"
                       "}";

        char *client_buffer[350];

        snprintf(client_buffer, sizeof(client_buffer), client, args[0], caller_secret, args[1]);
        fputs(client_buffer, output_file);
        fclose(output_file);
        free(client_buffer);
    }

    if (from_cache == 0) {
        snprintf(centrale_orgid_key_buf, sizeof(centrale_orgid_key_buf), "secret:%s:CENTRALE_ORGID", &args[1]);
        redis_set(centrale_orgid_key_buf, caller_orgid);
        redis_setex(shared_secret_key_buf, caller_secret, 3600);
    }

    return 0;
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
