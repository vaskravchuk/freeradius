/*
 * rlm_exec.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002,2006  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/redis_dal.h>

static dstr get_vps_attr(REQUEST *request, char *attr);
static dstr get_username(REQUEST *request);
static dstr get_client(REQUEST *request);
static dstr get_context_id(REQUEST *request);
static dstr get_mac(REQUEST *request);
static dstr get_plain_password(REQUEST *request);
static cJSON* get_attrs_json(REQUEST *request);

/*
 *  do pap authentication
 */
static int portnox_pap_auth(void *instance, REQUEST *request)
{
	int result;
	VALUE_PAIR **output_pairs;
	VALUE_PAIR *answer = NULL;

	result = radius_exec_program(inst->program, request,
				     inst->wait, NULL, 0,
				     inst->timeout,
				     NULL, &answer, inst->shell_escape);

	if (result < 0) {
		radlog(L_ERR, "portnox_pap_auth failed");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Move the answer over to the output pairs.
	 *
	 *	If we're not waiting, then there are no output pairs.
	 */
	if (output_pairs) pairmove(output_pairs, &answer);

	pairfree(&answer);

	if (result == 0) {
		return RLM_MODULE_OK;
	}
	if (result > RLM_MODULE_NUMCODES) {
		return RLM_MODULE_FAIL;
	}
	return result-1;
}

#define AUTH_METHOD_PR				"AuthNMethod"
#define MAC_ADDRESS_PR				"MacAddress"
#define PLAIN_PWD_PR				"PlainPwd"
#define USERNAME_PR					"UserName"
#define CLIENT_CERT_PR				"ClientCertificate"
#define NT_CHALLENGE_PR				"NtChallenge"
#define NT_CHALLENGE_RESPONSE_PR	"NtClientResponse"
#define RADIUS_CUSTOM_PR			"RadiusCustom"
#define CONTEXT_ID_ATTR				"CONTEXT_ID"
#define PORT_ATTR					"PORT"
#define REQ_CUSTOM_ATTR_VAL_KEY		"Key"
#define REQ_CUSTOM_ATTR_VAL_VALUE	"Value"

static char* get_request_json(REQUEST *request, char* client, char* context_id, int auth_method, int) {
    char *json = NULL;
    cJSON *request_data = NULL;
    dstr username = {0};
    dstr mac = {0};
    dstr pwd = {0};
    char *org_id = NULL;

    request_data = cJSON_CreateObject();

    username = get_username(request);

    if (hostname) {
        cJSON_AddStringToObject(request_data, CALLER_IP, hostname);
    }
    if (port > 0) {
        cJSON_AddNumberToObject(request_data, CALLER_PORT, port);
    }
    if (cluster_id) {
        cJSON_AddStringToObject(request_data, CLUSTER_ID, cluster_id);
    }

    json = cJSON_Print(request_data);

    cJSON_Delete(request_data);
    dstr_destroy(&username);
    dstr_destroy(&mac);
    dstr_destroy(&pwd);
    if (org_id) free(org_id);

    return json;
}



static dstr get_username(REQUEST *request) {
	static char *attr = "User-Name";
	int len = 0;
	dstr str = {0};

	str = get_vps_attr_or_empty(request, attr);

	return str;
}

static dstr get_client(REQUEST *request) {
	return dstr_cstr(request->client_shortname);
}

static dstr get_context_id(REQUEST *request) {
	return dstr_cstr(request->context_id);
}

static dstr get_mac(REQUEST *request) {
	static char *attr = "Calling-Station-Id";
	int len = 0;
	dstr str = {0};

	str = get_vps_attr_or_empty(request, attr);

	if (dstr_size(&str) > 0) {
		dstr_replace_chars(&str, '-', ':');
		lower(&str);
	} else {
		dstr_cat_cstr(&str, "00:00:00:00:00:00")
	}

	return str;
}

static dstr get_plain_password(REQUEST *request) {
	static char *attr = "User-Password";
	int len = 0;
	dstr str = {0};

	str = get_vps_attr_or_empty(request, attr);

	return str;
}
#define ATTR_VALUE_BUF_SIZE 256

static dstr get_vps_attr_or_empty(REQUEST *request, char *attr) {
	int len = 0;
    char val[ATTR_VALUE_BUF_SIZE];
	dstr str = {0};

	for (VALUE_PAIR *vp = vps; vp; vp = vp->next) {
		if (!vp->name || !(*vp->name)) continue;
		if (strcmp(attr, vp->name) == 0) {
			len = vp_prints_value(val, ATTR_VALUE_BUF_SIZE, vp, 0);
			break;	
		}
	}
	val[len] = 0;

	str = dstr_cstr_n(val, len);

	return str;
}

static cJSON* get_attrs_json(REQUEST *request, char* client, char* context_id) {
	cJSON *rad_custom = NULL;
    cJSON *item = NULL;
    int i = 0;
    char val[ATTR_VALUE_BUF_SIZE];
	int len = 0;
    
    rad_custom = cJSON_CreateArray();

	for (VALUE_PAIR *vp = vps; vp; vp = vp->next) {
		if (!vp->name || !(*vp->name)) continue;
		/* get value */
		len = vp_prints_value(val, ATTR_VALUE_BUF_SIZE, vp, 0);
		val[len] = 0;

		/* to json */
        item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_KEY, vp->name);
        cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_VALUE, val);
        cJSON_AddItemToArray(rad_custom, item);
    }

    /* context id */
    item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, CONTEXT_ID_ATTR, context_id);
    cJSON_AddItemToArray(rad_custom, item);

    /* port */
    item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, PORT_ATTR, client);
    cJSON_AddItemToArray(rad_custom, item);

    return rad_custom;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_portnox_pap = {
	RLM_MODULE_INIT,
	"portnox_pap",					/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	NULL,							/* instantiation */
	NULL,							/* detach */
	{
		portnox_pap_auth,			/* authentication */
		NULL,	        			/* authorization */
		NULL,						/* pre-accounting */
		NULL,						/* accounting */
		NULL,						/* check simul */
		NULL,						/* pre-proxy */
		NULL,						/* post-proxy */
		NULL						/* post-auth */
#ifdef WITH_COA
		, NULL,
		NULL
#endif
	},
};
