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
#include <freeradius-devel/portnox/attrs_helper.h>

#define NTKEY_ATTR_STRING_FORMAT    "NT_KEY: %s"

static char* get_request_json(REQUEST *request, int auth_method, char* identity, char* mac, 
                              AUTH_SP_ATTR_LIST *attr_proc_list);
static srv_req create_auth_req(REQUEST *request, int auth_method, char *org_id, char* identity, char* mac, 
                               AUTH_SP_ATTR_LIST *attr_proc_list);
static void process_response(srv_resp* call_resp, VALUE_PAIR **output_pairs);
static const char* auth_method_str(int auth_method);
static void process_result(int res, char *user_msg, int msg_len);

int portnox_auth(REQUEST *request, 
                int auth_method, 
                AUTH_INFO *auth_info, 
                VALUE_PAIR **output_pairs,
                char *user_msg, int msg_len) {
    int result = OPERATION_SUCCESS;
    srv_req call_req = {0};
    srv_resp call_resp = {0};
    dstr identity = {0};
    dstr mac = {0};
    char *org_id = NULL;
    int resp_from_cache = 0;
    int redis_result = 0;

    radlog(L_INFO, 
           "ContextId: %s; portnox_auth for auth_method: %s", 
           n_str(request->context_id), auth_method_str(auth_method));
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
    redis_result = get_org_id_for_client(request->client_shortname, &org_id);
    if (redis_result) {
        radlog(L_ERR, "ContextId: %s; portnox_auth for auth_method: %s failed to get org id from redis for %s on port %s with mac %s with error '%s'", 
                                    n_str(request->context_id), 
                                    auth_method_str(auth_method), 
                                    n_str(dstr_to_cstr(&identity)),  
                                    n_str(request->client_shortname), 
                                    n_str(dstr_to_cstr(&mac)), 
                                    redis_dal_error_descr(redis_result));
        radius_exec_logger_centrale(request, 
                                    auth_info->missed_orgid_error_code, 
                                    "Unable to find centrale orgid in REDIS for port %s", 
                                    n_str(request->client_shortname));
        result = ORG_ID_FAILED_GET_ERROR;
        goto fail;
    } 
    
    radlog(L_ERR, 
           "ContextId: %s; Central auth for %s on port %s with mac %s", 
           n_str(request->context_id), n_str(dstr_to_cstr(&identity)),  n_str(request->client_shortname), n_str(dstr_to_cstr(&mac)));

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

        radlog(L_INFO, 
           "ContextId: %s; portnox_auth try get response from redis auth_method: %s", 
           n_str(request->context_id), auth_method_str(auth_method));

        nas_port = get_nas_port(request);
        redis_result = get_response_for_data(dstr_to_cstr(&identity), 
                                                     dstr_to_cstr(&mac), 
                                                     request->client_shortname, 
                                                     dstr_to_cstr(&nas_port), 
                                                     &cached_data);
        if (redis_result) {
            radlog(L_ERR, "ContextId: %s; portnox_auth for auth_method: %s failed to get response cache from redis for %s on port %s with mac %s with error '%s'", 
                                        n_str(request->context_id), 
                                        auth_method_str(auth_method), 
                                        n_str(dstr_to_cstr(&identity)),  
                                        n_str(request->client_shortname), 
                                        n_str(dstr_to_cstr(&mac)), 
                                        redis_dal_error_descr(redis_result));
        }
        else if (cached_data) {
            radlog(L_INFO, 
               "ContextId: %s; portnox_auth use response from redis auth_method: %s", 
               n_str(request->context_id), auth_method_str(auth_method));

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
    if (!resp_from_cache && portnox_config.be.need_auth_cache_for_error && call_resp.data) {
        dstr nas_port = {0};

        radlog(L_INFO, "ContextId: %s; portnox_auth save response to redis auth_method: %s", 
                        n_str(request->context_id), auth_method_str(auth_method));

        nas_port = get_nas_port(request);
        redis_result = set_response_for_data(dstr_to_cstr(&identity), 
                                 dstr_to_cstr(&mac), 
                                 request->client_shortname, 
                                 dstr_to_cstr(&nas_port), call_resp.data);
        if (redis_result) {
            radlog(L_ERR, "ContextId: %s; portnox_auth for auth_method: %s failed to save response cache to redis for %s on port %s with mac %s with error '%s'", 
                                        n_str(request->context_id), 
                                        auth_method_str(auth_method), 
                                        n_str(dstr_to_cstr(&identity)),  
                                        n_str(request->client_shortname), 
                                        n_str(dstr_to_cstr(&mac)), 
                                        redis_dal_error_descr(redis_result));
        }

        dstr_destroy(&nas_port);
    }

    /* process response */
    process_response(&call_resp, output_pairs);

    fail:
    process_result(result, user_msg, msg_len);
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
    srv_req req = {0};

    /* get portnox url */
    url = dstr_from_fmt(portnox_config.be.auth_url, n_str(org_id));

    /* get request json string */
    json = get_request_json(request, 
                            auth_method, 
                            identity, 
                            mac,
                            attr_proc_list);

    /* create request struct & move json scope to req_create */
    req = req_create(dstr_to_cstr(&url), json, 0, 1);

    dstr_destroy(&url);
    return req;
}

static void process_response(srv_resp* call_resp, VALUE_PAIR **output_pairs) {
    VALUE_PAIR *vp = NULL;
    cJSON *json = NULL;
    /* will be destroyed with json object */
    cJSON *item = NULL;

    if (!call_resp->data || !(*call_resp->data)) return;

    json = cJSON_Parse(call_resp->data);
    if (!json) return;

    radlog(L_DBG, "portnox_auth process response");
    /* move nt key to output pairs */
    item = cJSON_GetObjectItem(json, NTKEY_PR);
    if (item && item->valuestring && *item->valuestring) {
        radlog(L_DBG, "portnox_auth process NT-KEY");
        /* temp value, don't destroy, we will move string in other scope */
        dstr ntkey_attr_val = {0};

        ntkey_attr_val = dstr_from_fmt(NTKEY_ATTR_STRING_FORMAT, item->valuestring);
        vp = pairmake(NTKEY_ATTR, dstr_to_cstr(&ntkey_attr_val), T_OP_ADD);
        pairadd(output_pairs, vp);

        dstr_destroy(&ntkey_attr_val);
    }
    radlog(L_DBG, "portnox_auth process custom attrs");

    /* parse radius custom attributes */
    item = cJSON_GetObjectItem(json, RADIUS_CUSTOM_PR);
    /* null safe */
    parse_custom_attr(item, output_pairs);

    if (json) cJSON_Delete(json);
}

static char* get_request_json(REQUEST *request, int auth_method, char* identity, char* mac, 
                              AUTH_SP_ATTR_LIST *attr_proc_list) {
    char *json = NULL;
    char *src_ip = NULL;
    cJSON *json_obj = NULL; 
    cJSON* attrs = NULL;

    json_obj = cJSON_CreateObject();

    /* get custom attrs */
    attrs = get_attrs_json(request);
    /* get source ip */
    src_ip = get_client_ip(request);

    /* compose json */
    cJSON_AddNumberToObject(json_obj, AUTH_METHOD_PR, auth_method);
    if (identity && *identity) cJSON_AddStringToObject(json_obj, USERNAME_PR, identity);
    if (mac && *mac) cJSON_AddStringToObject(json_obj, MAC_ADDRESS_PR, mac);
    if (attrs) cJSON_AddItemToObject(json_obj, RADIUS_CUSTOM_PR, attrs);
    if (src_ip && *src_ip) cJSON_AddStringToObject(json_obj, SRC_IP_ADDRESS_PR, src_ip);
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
    if (src_ip) free(src_ip);

    return json;
}


static char* get_client_ip(REQUEST *request) {
    char *ip = NULL;
    RADIUS_PACKET *packet = NULL;
    int buf_size = 0;

    buf_size = INET_ADDRSTRLEN;
    ip = malloc(buf_size);
    packet = request->packet;

    if (*((uint32_t*)&packet->src_ipaddr.ipaddr) != INADDR_ANY) {
        inet_ntop(packet->src_ipaddr.af,
                 &packet->src_ipaddr.ipaddr,
                 &ip, buf_size);
    } else if (*((uint32_t*)&packet->dst_ipaddr.ipaddr) != INADDR_ANY) {
        inet_ntop(packet->dst_ipaddr.af,
                 &packet->dst_ipaddr.ipaddr,
                 &ip, buf_size);
    }

    return ip;
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

static void process_result(int res, char *user_msg, int msg_len) {
    if (!user_msg || !msg_len) return;

    int n = 0;
    const char* msg = NULL;

    msg = get_operation_result_desc(res);
    n = str_format(user_msg, msg_len, msg);
    user_msg[n] = '\0';
}

const char *get_operation_result_desc(int res) {
    switch (res) {
        case OPERATION_SUCCESS:
            return "Success";
        case ORG_ID_FAILED_GET_ERROR:
            return "Failed to get org id";
        case IDENTITY_NOT_FOUND_ERROR:
            return "Identity not found";
        case AUTH_REJECT_ERROR:
            return "Fails external verification";
        default:
            return "UNKNOWN";
    }
}