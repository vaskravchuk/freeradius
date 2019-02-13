#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/curl_client.h>
#include <freeradius-devel/portnox/redis_dal.h>
#include <freeradius-devel/portnox/json_helper.h>
#include <sys/file.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

/* request fields */
#define CALLER_IP "CallerIp"
#define CALLER_PORT "CallerPort"
#define CLUSTER_ID "ClusterId"
/* response fields */
#define CALLER_ORG_ID "CallerOrgId"
#define CALLER_SECRET "CallerSecret"

static int get_caller_info(REQUEST *request, char* hostname, int port, char* file, char* context_id);
static void write_data_to_file(char *hostname, int port, char *shared_secret, char *file);
static char* get_request_json(char *hostname, int port, char *cluster_id);

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

    if (!inst->use_script) {
        result = get_caller_info(request, hostname, request->packet->dst_port, buffer, request->context_id);

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


static int get_caller_info(REQUEST *request, char* hostname, int port, char* file, char* context_id) {
    char *shared_secret = NULL;
    char *org_id = NULL;
    char *req_json = NULL;
    srv_req call_req = {0};
    srv_resp call_resp = {0};
    int from_cache = 0;
    int result = 0;

    /* try get shared secret and org id from redis */
    if (!get_shared_secret_for_port(port, &shared_secret) &&
        !get_org_id_for_port(port, &org_id)) {
        from_cache = 1;
    }
    else {
        /* clean if we have something */
        if (shared_secret) {
            free(shared_secret);
            shared_secret = NULL;
        }
        if (org_id) {
            free(org_id);
            org_id = NULL;
        }
    }

    /* did not found in redis -> try by REST from BE */
    if (from_cache == 0) {
        radlog(L_INFO, "Dynamic central clients for ip %s port %d from url", hostname, port);

        /* compose request json */
        req_json = get_request_json(hostname, port, portnox_config.be.cluster_id);

        if (!req_json || !(*req_json)) {
            radlog(L_ERR, "Failed create curl request");
            goto fail;
        }

        /* move req_json scope to req_create */
        call_req = req_create(portnox_config.be.caller_info_url, req_json, 0, 1);
        /* call REST to get shared secret and org from BE */
        call_resp = exec_http_request(&call_req);

        if (call_resp.return_code != 0 || !call_resp.data || !(*call_resp.data)) {
            radlog(L_ERR, "Failed curl request with error code '%d', data '%s'", call_resp.return_code, call_resp.data ? call_resp.data : "(null)");
            result = 1; 
            goto fail;
        }

        org_id = get_val_by_attr_from_json(call_resp.data, CALLER_ORG_ID);

        if (!org_id || !(*org_id)) {
            radius_exec_logger_centrale(request, "60007",
                                        "rlm_dynamic_centrale_clients: Unable to get CallerOrgId for client %s on port %d",
                                        hostname, port);
        }

        shared_secret = get_val_by_attr_from_json(call_resp.data, CALLER_SECRET);

        if (!shared_secret || !(*shared_secret)) {
            radius_exec_logger_centrale(request, "60007",
                                        "rlm_dynamic_centrale_clients: Unable to get CallerSecret for client %s on port %d",
                                        hostname, port);
        }
    }

    /* save to file and parse by client */
    if (shared_secret && *shared_secret && 
        org_id && *org_id) {
        write_data_to_file(hostname, port, shared_secret, file);
    }
    else {
        radlog(L_ERR, "Failed to get caller_info");
        result = 1;
        goto fail;
    }

    /* save in redis if data come from BE */
    if (from_cache == 0) {
        set_org_id_for_port(port, org_id);
        set_shared_secret_for_port(port, shared_secret);
    }

    fail:
    req_destroy(&call_req);
    resp_destroy(&call_resp);
    if (shared_secret) free(shared_secret);
    if (org_id) free(org_id);
    return result;
}

static void write_data_to_file(char *hostname, int port, char *shared_secret, char *file) {
    static char *format = "client %s {\n"
                   "\tsecret = %s\n"
                   "\tshortname = %d\n"
                   "}";
    dstr formated_output;
    FILE *output_file;

    output_file = fopen(file, "w");

    formated_output = dstr_from_fmt(format, hostname, shared_secret, port);

    if (!is_nas(&formated_output)) {
        fputs(dstr_to_cstr(&formated_output), output_file);
    }

    fclose(output_file);
    dstr_destroy(&formated_output);
}

static char* get_request_json(char *hostname, int port, char *cluster_id) {
    char *json = NULL;
    cJSON *request_data = NULL;

    request_data = cJSON_CreateObject();

    if (hostname) cJSON_AddStringToObject(request_data, CALLER_IP, hostname);
    if (port > 0) cJSON_AddNumberToObject(request_data, CALLER_PORT, port);
    if (cluster_id) cJSON_AddStringToObject(request_data, CLUSTER_ID, cluster_id);

    json = cJSON_Print(request_data);
    cJSON_Delete(request_data);

    return json;
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
