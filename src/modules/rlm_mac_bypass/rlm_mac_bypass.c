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
typedef struct rlm_mac_bypass_t {
    char    *program;
} rlm_mac_bypass_t;

static const CONF_PARSER module_config[] = {
    { "program",  PW_TYPE_STRING_PTR, offsetof(rlm_mac_bypass_t, program), NULL, NULL },
    { NULL, -1, 0, NULL, NULL }
};

static int mac_bypass_detach(void *instance)
{
    rlm_mac_bypass_t      *inst = instance;
    free(inst);
    return 0;
}

static int mac_bypass_instantiate(CONF_SECTION *conf, void **instance)
{
    rlm_mac_bypass_t    *inst;
    inst = rad_malloc(sizeof(rlm_mac_bypass_t));
    if (!inst) {
        return -1;
    }
    memset(inst, 0, sizeof(rlm_mac_bypass_t));
    if (cf_section_parse(conf, inst, module_config) < 0) {
        radlog(L_ERR, "60024 rlm_mac_bypass: Failed parsing the configuration");
        mac_bypass_detach(inst);
        return -1;
    }
    *instance = inst;
    return 0;
}

static int mac_bypass_authorize(UNUSED void *instance, REQUEST *request)
{
    CONF_PAIR *cp;
    const char *value;
    char buffer[1024];
    char cmdline[1024];
    VALUE_PAIR      *vp;
    rlm_mac_bypass_t *inst = instance;
    int result;

    if (!request->client || !request->client->cs) {
        radlog(L_ERR, "60025 rlm_mac_bypass: Unknown client definition");
        return RLM_MODULE_NOOP;
    }

    if ((vp = pairfind(request->packet->vps, PW_USER_NAME)) != NULL) {
	if (!snprintf(buffer, sizeof(buffer), "%s", vp->vp_strvalue)) {
    	    radlog(L_ERR, "60026 rlm_mac_bypass: Unable to process username");
    	    return RLM_MODULE_FAIL; 
	}
    } else {
        radlog(L_ERR, "60027 rlm_mac_bypass: Unable to get username");
        return RLM_MODULE_FAIL; 
    }

    if (!snprintf(cmdline, sizeof(cmdline), "%s %d %s", inst->program, request->packet->dst_port, buffer)) {
        radlog(L_ERR, "60028 rlm_mac_bypass: Unable to make cmd line");
        return RLM_MODULE_FAIL; 
    }

    result = radius_exec_program(cmdline, request, TRUE, NULL, 0, 10000, request->packet->vps, NULL, 1);

    if (result != 0) {
        radlog(L_ERR, "60029 rlm_mac_bypass: External script '%s' failed", cmdline);
        return RLM_MODULE_REJECT;
    } else {
	return RLM_MODULE_OK;
    }
}

module_t rlm_mac_bypass = {
    RLM_MODULE_INIT,
    "mac_bypass",
    RLM_TYPE_CHECK_CONFIG_SAFE,                     /* type */
    mac_bypass_instantiate,                         /* instantiation */
    mac_bypass_detach,                              /* detach */
    {
        NULL,                                       /* authentication */
        mac_bypass_authorize,                       /* authorization */
        NULL,                                       /* preaccounting */
        NULL,                                       /* accounting */
        NULL,                                       /* checksimul */
        NULL,                                       /* pre-proxy */
        NULL,                                       /* post-proxy */
        NULL                                        /* post-auth */
    },
};
