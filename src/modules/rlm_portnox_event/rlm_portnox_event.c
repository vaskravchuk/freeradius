/*
 * rlm_portnox_event.c
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
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/attrs_helper.h>
#include <freeradius-devel/portnox/string_helper.h>
#include <freeradius-devel/portnox/curl_client.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/portnox_common.h>

#define ACCEPT_TYPE		0
#define REJECT_TYPE		1
#define ACCT_TYPE		2
#define TYPES_SIZE		3
static char *type_map[TYPES_SIZE] = { "ACCEPT", "REJECT", "ACCT"};

#define TYPE_ACCESS		0
#define TYPE_ACCOUNTING	1
#define SUBTYPE_ACCEPT	0
#define SUBTYPE_REJECT	1
#define SUBTYPE_START	2
#define SUBTYPE_STOP	3


#define START_ACCT_SUBTYPE		"Start"
#define STOP_ACCT_SUBTYPE		"Stop"

#define TIME_BUFFER_SIZE	32

/* Define a structure for our module configuration. */
typedef struct rlm_portnox_event_t {
	int				type;
	char			*packet_type;
	unsigned int	packet_code;
} rlm_portnox_event_t;

static void sent_event_to_portnox(rlm_portnox_event_t *inst, REQUEST *request, int subtype);
static srv_req get_event_request(rlm_portnox_event_t *inst, REQUEST *request, char *org_id, int subtype);

/* A mapping of configuration file names to internal variables. */
static const CONF_PARSER module_config[] = {
	{ "type",  PW_TYPE_INTEGER,
	  offsetof(rlm_portnox_event_t,type), NULL, Stringify(0) },
	{ "packet_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_portnox_event_t,packet_type), NULL, NULL },
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/* Detach an instance and free it's data. */
static int portnox_event_detach(void *instance)
{
	rlm_portnox_event_t	*inst = NULL;

	inst = instance;

	free(inst);
	return 0;
}

/* Do any per-module initialization */
static int portnox_event_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_portnox_event_t	*inst;

	/* Set up a storage area for instance data */

	inst = rad_malloc(sizeof(rlm_portnox_event_t));
	if (!inst)
		return -1;
	memset(inst, 0, sizeof(rlm_portnox_event_t));

	/* If the configuration parameters can't be parsed, then fail. */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		radlog(L_ERR, "rlm_portnox_event: Failed parsing the configuration");
		exec_detach(inst);
		return -1;
	}

	/* Get the packet type on which to execute */
	if (!inst->packet_type) {
		inst->packet_code = 0;
	} else {
		DICT_VALUE	*dval;

		dval = dict_valbyname(PW_PACKET_TYPE, inst->packet_type);
		if (!dval) {
			radlog(L_ERR, "rlm_portnox_event: Unknown packet type %s: See list of VALUEs for Packet-Type in share/dictionary", inst->packet_type);
			exec_detach(inst);
			return -1;
		}
		inst->packet_code = dval->value;
	}

	*instance = inst;

	return 0;
}

/* do event processing */
static int event_processing(void *instance, REQUEST *request){
	rlm_portnox_event_t	*inst = NULL;
	int subtype = 0;
	
	inst = instance;

	radlog(L_ERR, "rlm_portnox_event: Start event processing packet type '%s', Event type '%d', on port %s", 
		n_str(inst->packet_type), inst->type, n_str(request->client_shortname));

	/* See if we're supposed to execute it now. */
	if (!((inst->packet_code == 0) ||
	      (request->packet->code == inst->packet_code) ||
	      (request->reply->code == inst->packet_code) ||
	      (request->proxy &&
	       (request->proxy->code == inst->packet_code)) ||
	      (request->proxy_reply &&
	       (request->proxy_reply->code == inst->packet_code)))) {
		RDEBUG2("Packet type %s is wrong. Not executing, on port %s", n_str(inst->packet_type), n_str(request->client_shortname));
		return RLM_MODULE_NOOP;
	}

	/* check valid type */
	if (inst->type >= TYPES_SIZE) {
		RDEBUG2("Event type %d is wrong. Not executing, on port %s", inst->type, n_str(request->client_shortname));
		return RLM_MODULE_NOOP;
	}


	if (inst->type == ACCT_TYPE) {
		/* accounting subtype should be only start or stop */
		dstr subtype_val = get_acct_subtype(request);
		char *subtype_val_str = dstr_to_cstr(&subtype_val);
		int subtype_result = 0;

		if (dstr_size(&subtype_val) == 0) {
			RDEBUG2("Event type %s should contains 'Acct-Status-Type' attribute, on port %s", type_map[inst->type], n_str(request->client_shortname));
			subtype_result = -1;
		} else if (strcmp(subtype_val_str, START_ACCT_SUBTYPE) == 0) {
			subtype = SUBTYPE_START;
			
		} else if (strcmp(subtype_val_str, STOP_ACCT_SUBTYPE) == 0) {
			subtype = SUBTYPE_STOP;
		} else {
			RDEBUG2("Event type %s contains wrong 'Acct-Status-Type' attribute '%s', should be 'Start' or 'Stop', on port %s", 
						type_map[inst->type], subtype_val_str, n_str(request->client_shortname));
			subtype_result = -1;
		}

		dstr_destroy(&subtype_val);
		if (subtype_result != 0) return RLM_MODULE_NOOP;
	}
	else {
		subtype = inst->type == REJECT_TYPE ? SUBTYPE_REJECT : SUBTYPE_ACCEPT;
	}

	sent_event_to_portnox(inst, request, subtype);

	return RLM_MODULE_OK;
}

/* sent event to portnox be */
static void sent_event_to_portnox(rlm_portnox_event_t *inst, REQUEST *request, int subtype) {
    char *org_id = NULL;
    srv_req call_req = {0};
    srv_resp call_resp = {0};

    /* get org id */
    if (get_org_id_for_client(request->client_shortname, &org_id)) {
        radius_exec_logger_centrale(request, 60013, "Unable to find centrale orgid in REDIS for port %s", n_str(request->client_shortname));
        goto fail;
    } 

    call_req = get_event_request(inst, request, org_id, subtype);
    if (!call_req.data || !(*call_req.data)) {
		radlog(L_ERR, "rlm_portnox_event: Start event processing packet type '%s', Event type '%s', on port %s", 
				n_str(inst->packet_type), type_map[inst->type], n_str(request->client_shortname));
    	goto fail;
    }

	radlog(L_INFO, call_req.data);
    call_resp = exec_http_request(&call_req);
    if (call_resp.return_code != 0) {
		radlog(L_ERR, "rlm_portnox_event: Failed to send event with curl code %ld, http code %d, packet type '%s', Event type '%s', on port %s", 
			call_resp.return_code, call_resp.http_code, n_str(inst->packet_type), type_map[inst->type], n_str(request->client_shortname));
    	goto fail;
    }

    fail:
    if (org_id) free(org_id);
    req_destroy(&call_req);
    resp_destroy(&call_resp);
}

/* sent event to portnox be */
static srv_req get_event_request(rlm_portnox_event_t *inst, REQUEST *request, char *org_id, int subtype) {
    char event_time[TIME_BUFFER_SIZE] = {0};
    char event_date[TIME_BUFFER_SIZE] = {0};
    dstr identity = {0};
    dstr mac = {0};
    dstr ip = {0};
    time_t timer;
    struct tm* tm_info;
    int len = 0;
    cJSON *json_obj = NULL; 
    /* Do not destroy next vars. will be moved out of scope */
    cJSON* attrs = NULL;
    char* json = NULL;
    dstr url = {0};

    /* get portnox url */
    url = dstr_from_fmt(portnox_config.be.event_url, n_str(org_id));
    /* get main data */
    identity = get_username(request);
    mac = get_mac(request);
    ip = get_device_ip(request);
    /* date/time */
    time(&timer);
    tm_info = localtime(&timer);
    len = strftime(event_date, TIME_BUFFER_SIZE, "%d/%m/%Y", tm_info);
    event_date[len] = 0;
    len = strftime(event_time, TIME_BUFFER_SIZE, "%H:%M:%S", tm_info);
    event_time[len] = 0;
    /* custom attributes */
    attrs = get_attrs_json(request);

    /* create json */
    json_obj = cJSON_CreateObject();

    if (dstr_size(&ip) > 0) cJSON_AddStringToObject(json_obj, DEVICE_IP_PR, dstr_to_cstr(&ip));
    if (dstr_size(&mac) > 0) cJSON_AddStringToObject(json_obj, DEVICE_MAC_PR, dstr_to_cstr(&mac));
    if (dstr_size(&identity) > 0) cJSON_AddStringToObject(json_obj, USERNAME_PR, dstr_to_cstr(&identity));
    if (event_date && *event_date) cJSON_AddStringToObject(json_obj, EVENT_DATE_PR, event_date);
    if (event_time && *event_time) cJSON_AddStringToObject(json_obj, EVENT_TIME_PR, event_time);
    if (attrs) cJSON_AddItemToObject(json_obj, RADIUS_CUSTOM_PR, attrs);
    switch (inst->type) {
    	case ACCEPT_TYPE:
    	case REJECT_TYPE:
    		cJSON_AddNumberToObject(json_obj, EVENT_TYPE_PR, TYPE_ACCESS);
    		cJSON_AddNumberToObject(json_obj, EVENT_SUBTYPE_PR, subtype);
    		break;
    	case ACCT_TYPE: {
    		cJSON_AddNumberToObject(json_obj, EVENT_TYPE_PR, TYPE_ACCOUNTING);
    		cJSON_AddNumberToObject(json_obj, EVENT_SUBTYPE_PR, subtype);

    		if (subtype == SUBTYPE_STOP) {
    			dstr data_in = get_acct_data_in(request);
    			dstr data_out = get_acct_data_out(request);
    			dstr disc_reason = get_acct_disconnection_reason(request);

    			if (dstr_size(&data_in) > 0) cJSON_AddStringToObject(json_obj, DATA_IN_PR, dstr_to_cstr(&data_in));
    			if (dstr_size(&data_in) > 0) cJSON_AddStringToObject(json_obj, DATA_OUT_PR, dstr_to_cstr(&data_out));
    			if (dstr_size(&data_in) > 0) cJSON_AddStringToObject(json_obj, DISCONNECTION_REASON_PR, dstr_to_cstr(&disc_reason));


    			dstr_destroy(&data_in);
    			dstr_destroy(&data_out);
    			dstr_destroy(&disc_reason);
    		}
    		break;
    	}
    }

    json = cJSON_Print(json_obj);
    cJSON_Minify(json);


    cJSON_Delete(json_obj);
    dstr_destroy(&identity);
    dstr_destroy(&mac);
    dstr_destroy(&ip);
    return req_create(dstr_to_cstr(&url), json, 0, 1);
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
module_t rlm_portnox_event = {
	RLM_MODULE_INIT,
	"portnox_event",				/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	portnox_event_instantiate,		/* instantiation */
	portnox_event_detach,			/* detach */
	{
		event_processing,			/* authentication */
		event_processing,	        /* authorization */
		event_processing,			/* pre-accounting */
		event_processing,			/* accounting */
		NULL,						/* check simul */
		event_processing,			/* pre-proxy */
		event_processing,			/* post-proxy */
		event_processing			/* post-auth */
#ifdef WITH_COA
		, event_processing,
		NULL
#endif
	},
};
