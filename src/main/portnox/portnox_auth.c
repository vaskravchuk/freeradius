/*
 * portnox_config.c	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/portnox_auth.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/redis_dal.h>
#include <freeradius-devel/portnox/json_helper.h>

#define NTKEY_ATTR_STRING_FORMAT    "NT_KEY: %s"

static dstr get_vps_attr_or_empty(REQUEST *request, char *attr);
static char* get_username(REQUEST *request);
static dstr get_mac(REQUEST *request);
static cJSON* get_attrs_json(REQUEST *request, char* client, char* context_id);
static char* get_request_json(REQUEST *request, 
                              int auth_method, 
                              char* identity, 
                              char* mac, 
                              auth_attr_proc_list_t *attr_proc_list);
static int create_auth_req(REQUEST *request, 
                           int auth_method, 
                           auth_attr_proc_list_t *attr_proc_list, 
                           srv_req* req);


int portnox_auth(REQUEST *request, 
                int auth_method, 
                auth_attr_proc_list_t *attr_proc_list, 
                VALUE_PAIR **output_pairs) {

    int result = OPERATION_SUCCESS;
    srv_req call_req = {0};
    srv_resp call_resp = {0};

    /* create request struct */
    result = create_auth_req(request, auth_method, attr_proc_list, &call_req);
    if (result != OPERATION_SUCCESS) {
        goto fail;
    }

    /* call REST to portnox auth service */
    call_resp = exec_http_request(&call_req);

    if (call_resp.return_code != 0) {
        result = AUTH_REJECT_ERROR;
        goto fail;
    }

    /* process response */
    process_response(&call_resp, output_pairs);

    fail:
    req_destroy(&call_req);
    resp_destroy(&call_resp);
    return result;
}

static void process_response(srv_resp* call_resp, VALUE_PAIR **output_pairs) {
    VALUE_PAIR *vp = NULL;
    cJSON *json = NULL;
    /* will be destroyed with json object */
    cJSON *item = NULL;

    if (!call_resp->data || !(*call_resp->data)) return;

    json = cJSON_Parse(call_resp->data);
    if (!json) return;

    /* move nt key to output pairs */
    item = cJSON_GetObjectItem(json, NTKEY_PR);
    if (item && item->valuestring && *item->valuestring) {
        /* temp value, don't destroy, we will move string in other scope */
        dstr ntkey_attr_val = {0};

        ntkey_attr_val = dstr_from_fmt(NTKEY_ATTR_STRING_FORMAT, item->valuestring);
        vp = pairmake(NTKEY_ATTR, dstr_to_cstr(&ntkey_attr_val), T_OP_ADD);
        pairadd(output_pairs, vp);

        dstr_destroy(&ntkey_attr_val);
    }

    /* parse radius custom attributes */
    item = cJSON_GetObjectItem(json, RADIUS_CUSTOM_PR);
    /* null safe */
    parse_custom_attr(item, output_pairs);

    if (json) cJSON_Delete(json);
}

static int create_auth_req(REQUEST *request, 
                           int auth_method, 
                           auth_attr_proc_list_t *attr_proc_list, 
                           srv_req* req) {
    int result = OPERATION_SUCCESS;
    char *org_id = NULL;
    dstr identity = {0};
    dstr mac = {0};
    int org_id_res = 0;
    dstr url = {0};
    char* json = NULL;

    /* get org id */
    org_id_res = get_org_id_for_client(request->client_shortname, &org_id);
    if (org_id_res == -1) {
        result = ORG_ID_NOT_FOUND_ERROR;
        goto fail;
    } else (org_id_res != 0) {
        result = ORG_ID_NOT_FAILED_GET_ERROR;
        goto fail;
    }

    /* get identity */
    identity = get_username(request);
    if (!dstr_size(&identity)) {
        result = IDENTITY_NOT_FOUND_ERROR;
        goto fail;
    }

    /* get org id */
    url = dstr_from_fmt(portnox_config.be.auth_info_url, org_id);

    /* get mac */
    mac = get_mac(request);

    /* get request json string */
    json = get_request_json(request, 
                            auth_method, 
                            dstr_to_cstr(&identity), 
                            dstr_to_cstr(&mac),
                            attr_proc_list);

    /* create request struct & move json scope to req_create */
    *req = req_create(dstr_to_cstr(&url), json, 0, 1);


    fail:
    if (org_id) free(org_id);
    dstr_destroy(&identity);
    dstr_destroy(&url);
    dstr_destroy(&mac);
    return result;
}


static dstr get_username(REQUEST *request) {
	return get_vps_attr_or_empty(request, USERNAME_ATTR);
}

static dstr get_mac(REQUEST *request) {
	dstr str;

	str = get_vps_attr_or_empty(request, CALLING_STATION_ID_ATTR);

	if (dstr_size(&str) > 0) {
		dstr_replace_chars(&str, '-', ':');
		lower(&str);
	} else {
		dstr_cat_cstr(&str, "00:00:00:00:00:00");
	}

	return str;
}

static char* get_request_json(REQUEST *request, 
                              int auth_method, 
                              char* identity, 
                              char* mac, 
                              auth_attr_proc_list_t *attr_proc_list) {
    char *json = NULL;
    cJSON *json_obj = NULL; 
    cJSON* attrs = NULL;

    json_obj = cJSON_CreateObject();

    /* get custom attrs */
    attrs = get_attrs_json(request);

    /* compose json */
    cJSON_AddNumberToObject(json_obj, AUTH_METHOD_PR, auth_method);
    if (identity && *identity) cJSON_AddStringToObject(json_obj, USERNAME_PR, identity);
    if (mac && *mac) cJSON_AddStringToObject(json_obj, MAC_ADDRESS_PR, mac);
    if (attrs) cJSON_AddObjectToObject(json_obj, RADIUS_CUSTOM_PR, attrs);
    /* process custom params */
    if (attr_proc_list) {
        for (int i = 0; i < attr_proc_list->count; i++) {
        	auth_attr_proc_t proc = attr_proc_list->items[i];
        	dstr val = get_vps_attr_or_empty(request, proc.attr_name);
            if (proc.processor) proc.processor(&val);
            if (!is_nas(&val)) cJSON_AddStringToObject(json_obj, proc.json_attr, dstr_to_cstr(&val));
            dstr_destroy(&val);
        }
    }

    /* create json string */
    json = cJSON_Print(json_obj);

    cJSON_Delete(json_obj);

    return json;
}

static dstr get_vps_attr_or_empty(REQUEST *request, char *attr) {
	int len = 0;
    char val[ATTR_VALUE_BUF_SIZE];
	dstr str = {0};

    if (request->packet) {
    	for (VALUE_PAIR *vp = request->packet->vps; vp; vp = vp->next) {
    		if (!vp->name || !(*vp->name)) continue;
    		if (strcmp(attr, vp->name) == 0) {
    			len = vp_prints_value(val, ATTR_VALUE_BUF_SIZE, vp, 0);
    			break;	
    		}
    	}
    }
	val[len] = 0;

	str = dstr_cstr_n(val, len);

	return str;
}

