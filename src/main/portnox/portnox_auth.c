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
#include <freeradius-devel/portnox/curl_client.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/portnox_auth.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/redis_dal.h>
#include <freeradius-devel/portnox/json_helper.h>
#include <freeradius-devel/portnox/string_helper.h>

#define NTKEY_ATTR_STRING_FORMAT    "NT_KEY: %s"

static dstr get_vps_attr_or_empty(REQUEST *request, char *attr);
static dstr get_nas_port(REQUEST *request);
static char* get_request_json(REQUEST *request, int auth_method, char* identity, char* mac, 
                              AUTH_SP_ATTR_LIST *attr_proc_list);
static srv_req create_auth_req(REQUEST *request, int auth_method, char *org_id, char* identity, char* mac, 
                               AUTH_SP_ATTR_LIST *attr_proc_list);
static void process_response(srv_resp* call_resp, VALUE_PAIR **output_pairs);
static const char* auth_method_str(int auth_method);

int portnox_auth(REQUEST *request, 
                int auth_method, 
                AUTH_INFO *auth_info, 
                VALUE_PAIR **output_pairs) {
    int result = OPERATION_SUCCESS;
    srv_req call_req = {0};
    srv_resp call_resp = {0};
    dstr identity = {0};
    dstr mac = {0};
    char *org_id = NULL;
    int resp_from_cache = 0;

    radlog(L_INFO, 
           "ContextId: %s; portnox_auth for auth_method: %s", 
           request->context_id, auth_method_str(auth_method));

    /* get identity */
    identity = get_username(request);
    if (!dstr_size(&identity)) {
        radius_exec_logger_centrale(request, 
                                    auth_info->missed_username_error_code, 
                                    "Please use: username");
        result = IDENTITY_NOT_FOUND_ERROR;
        goto fail;
    }

    /* get mac */
    mac = get_mac(request);

    /* get org id */
    if (get_org_id_for_client(request->client_shortname, &org_id)) {
        radius_exec_logger_centrale(request, 
                                    auth_info->missed_orgid_error_code, 
                                    "Unable to find centrale orgid in REDIS for port %s", 
                                    request->client_shortname);
        result = ORG_ID_FAILED_GET_ERROR;
        goto fail;
    } 
    
    radlog(L_ERR, 
           "ContextId: %s; Central auth for %s on port %s with mac %s", 
           request->context_id, dstr_to_cstr(&identity),  request->client_shortname, dstr_to_cstr(&mac));

    /* create request struct */
    call_req = create_auth_req(request, 
                             auth_method, 
                             org_id,
                             dstr_to_cstr(&identity), 
                             dstr_to_cstr(&mac), 
                             auth_info->auth_attr_list);

    if (result != OPERATION_SUCCESS) {
        goto fail;
    }

    /* call REST to portnox auth service */
    call_resp = exec_http_request(&call_req);

    radlog(L_INFO, "portnox_auth_call: AUTH_CALL_ERR=%d result=%ld", call_resp.return_code, call_resp.http_code);

    /* try use reponse cache from redis (optional) */
    if (portnox_config.be.need_auth_cache_for_error && 
        call_resp.return_code != 0 &&
        (call_resp.return_code  != 22 || call_resp.http_code == 404 || 
         call_resp.http_code == 405 || call_resp.http_code == 500)) {
        char* cached_data = NULL;
        dstr nas_port = {0};
        int resp_cache_result = 0;

        radlog(L_INFO, 
           "ContextId: %s; portnox_auth try get response from redis auth_method: %s", 
           request->context_id, auth_method_str(auth_method));

        nas_port = get_nas_port(request);
        resp_cache_result = get_response_for_data(dstr_to_cstr(&identity), 
                                                     dstr_to_cstr(&mac), 
                                                     request->client_shortname, 
                                                     dstr_to_cstr(&nas_port), 
                                                     &cached_data);
        if (resp_cache_result == 0 && cached_data) {
            radlog(L_INFO, 
               "ContextId: %s; portnox_auth use response from redis auth_method: %s", 
               request->context_id, auth_method_str(auth_method));

            resp_destroy(&call_resp);
            call_resp.return_code = 0;
            call_resp.http_code = 200;
            call_resp.data = cached_data;
            resp_from_cache = 1;
        }

        dstr_destroy(&nas_port);
    }

    /* we get fail -> log and goto fail */
    if (call_resp.return_code != 0) {
        radius_exec_logger_centrale(request, 
                                    auth_info->failed_auth_error_code, 
                                    "CURL_ERR: %d %ld",
                                    call_resp.return_code, call_resp.http_code);
        result = AUTH_REJECT_ERROR;
        goto fail;
    }

    /* auth is OK, cache response if need */
    if (!resp_from_cache && portnox_config.be.need_auth_cache_for_error) {
        dstr nas_port = {0};

        radlog(L_INFO, "ContextId: %s; portnox_auth save response to redis auth_method: %s", 
                        request->context_id, auth_method_str(auth_method));

        nas_port = get_nas_port(request);
        set_response_for_data(dstr_to_cstr(&identity), 
                                 dstr_to_cstr(&mac), 
                                 request->client_shortname, 
                                 dstr_to_cstr(&nas_port), call_resp.data);

        dstr_destroy(&nas_port);
    }

    /* process response */
    process_response(&call_resp, output_pairs);

    fail:
    if (org_id) free(org_id);
    req_destroy(&call_req);
    resp_destroy(&call_resp);
    dstr_destroy(&identity);
    dstr_destroy(&mac);
    return result;
}

static srv_req create_auth_req(REQUEST *request, int auth_method, char *org_id, char* identity, char* mac, 
                               AUTH_SP_ATTR_LIST *attr_proc_list) {
    dstr url = {0};
    char* json = NULL;

    /* get org id */
    url = dstr_from_fmt(portnox_config.be.auth_url, org_id);

    /* get request json string */
    json = get_request_json(request, 
                            auth_method, 
                            identity, 
                            mac,
                            attr_proc_list);

    /* create request struct & move json scope to req_create */
    return req_create(dstr_to_cstr(&url), json, 0, 1);
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

dstr get_username(REQUEST *request) {
    return get_vps_attr_or_empty(request, USERNAME_ATTR);
}

dstr get_mac(REQUEST *request) {
	dstr str = {0};

	str = get_vps_attr_or_empty(request, CALLING_STATION_ID_ATTR);

	if (!is_nas(&str)) {
		dstr_replace_chars(&str, '-', ':');
		dstr_to_lower(&str);
	} else {
		str = dstr_cstr("00:00:00:00:00:00");
	}

	return str;
}

static dstr get_nas_port(REQUEST *request) {
    return get_vps_attr_or_empty(request, NAS_PORT_ATTR);
}

static char* get_request_json(REQUEST *request, int auth_method, char* identity, char* mac, 
                              AUTH_SP_ATTR_LIST *attr_proc_list) {
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
    if (attrs) cJSON_AddItemToObject(json_obj, RADIUS_CUSTOM_PR, attrs);
    /* process custom params */
    if (attr_proc_list) {
        for (int i = 0; i < attr_proc_list->count; i++) {
        	AUTH_SP_ATTR proc = attr_proc_list->items[i];
        	dstr val = get_vps_attr_or_empty(request, proc.attr_name);
            if (!is_nas(&val) && proc.processor) proc.processor(&val, proc.user_data);
            if (!is_nas(&val)) cJSON_AddStringToObject(json_obj, proc.json_attr, dstr_to_cstr(&val));
            dstr_destroy(&val);
        }
    }

    /* create json string */
    json = cJSON_Print(json_obj);
    cJSON_Minify(json);

    cJSON_Delete(json_obj);

    return json;
}

static dstr get_vps_attr_or_empty(REQUEST *request, char *attr) {
	int len = 0;
    char val[ATTR_VALUE_BUF_SIZE];
    char *val_escaped = NULL;
	dstr str = {0};

    if (request->packet) {
    	for (VALUE_PAIR *vp = request->packet->vps; vp; vp = vp->next) {
    		if (!vp->name || !(*vp->name)) continue;
    		if (strcmp(attr, vp->name) == 0) {
    			len = vp_prints_value(val, ATTR_VALUE_BUF_SIZE, vp, 0);

                val[len] = 0;

                val_escaped = str_replace(val, "\\\\", "\\");
                str = dstr_cstr(val_escaped);

                if (val_escaped) free(val_escaped);
    			break;	
    		}
    	}
    }

	return str;
}

static const char* auth_method_str(int auth_method) {
    switch (auth_method) {
        case PAP_AUTH_METHOD:
            return "PAP";
        case MSCHAP_AUTH_METHOD:
            return "MSCHAP";
        case CHAP_AUTH_METHOD:
            return "CHAP";
        case EAPTLS_AUTH_METHOD:
            return "EAP_TLS";
        case MD5_AUTH_METHOD:
            return "MD5";
        default:
            return "UNKNOWN";
    }
}