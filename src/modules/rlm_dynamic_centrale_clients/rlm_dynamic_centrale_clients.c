#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <sys/file.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

/*
 *      Define a structure for our module configuration.
 */
typedef struct rlm_dynamic_centrale_clients_t {
    char    *program;
} rlm_dynamic_centrale_clients_t;

static const CONF_PARSER module_config[] = {
    { "program",  PW_TYPE_STRING_PTR, offsetof(rlm_dynamic_centrale_clients_t, program), NULL, NULL },
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

    if (!snprintf(cmdline, sizeof(cmdline), "%s %s %d %s", inst->program, hostname, request->packet->dst_port, buffer)) {
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

    request->client = c;
    return RLM_MODULE_OK;
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
