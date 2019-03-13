#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/curl_client.h>
#include <freeradius-devel/portnox/json_helper.h>
#include <freeradius-devel/portnox/attrs_helper.h>
#include <freeradius-devel/portnox/string_helper.h>
#include <freeradius-devel/portnox/log_helper.h>
#include <freeradius-devel/portnox/redis_dal.h>
#include <syslog.h>

#define DEBUG_PRIORITY  0
#define INFO_PRIORITY   1
#define ERROR_PRIORITY  2

static void to_syslog(int priority, dstr* message);
static void log_to_portnox(dstr* message);

static void to_syslog(int priority, dstr *message) {
    int syslog_priority = 0;

    switch (priority) {
        case DEBUG_PRIORITY: 
            syslog_priority = LOG_DEBUG;
            break;
        case INFO_PRIORITY: 
            syslog_priority = LOG_INFO;
            break;
        case ERROR_PRIORITY: 
            syslog_priority = LOG_ERR;
            break;
        default:
            syslog_priority = LOG_INFO;
            break;
    }

    syslog(LOG_MAKEPRI(LOG_LOCAL1, syslog_priority), "%s", n_str(dstr_to_cstr(message)));
    closelog();
}

static void log_to_portnox(dstr *message) {
    srv_req req = {0};
    srv_resp resp = {0};
    char* msg_cpy = NULL;

    if (!is_nas(message)) msg_cpy = strdup(dstr_to_cstr(message));

    req = req_create(portnox_config.log.logging_url, msg_cpy, 0, 0);
    resp = exec_http_request(&req);

    req_destroy(&req);
    resp_destroy(&resp);
}

void log_portnox(const char* code, dstr *message, int priority, REQUEST* req) {
    dstr full_message = {0};

    full_message = dstr_from_fmt("%s ContextId: %s; %s", n_str(code), n_str(req->context_id), n_str(dstr_to_cstr(message)));

    // to syslog
    to_syslog(priority, &full_message);

    // to portnox
    log_to_portnox(&full_message);

    dstr_destroy(&full_message);
}

void log_portnox_info(dstr *message,  REQUEST* req) {
    log_portnox("0", message, INFO_PRIORITY, req);
}

void log_portnox_error(const char* code, dstr *message, REQUEST* req) {
    log_portnox(code, message, ERROR_PRIORITY, req);
}

int radius_internal_logger_centrale(char *error_code, char *message, REQUEST *request) {
    dstr full_message = {0};
    dstr username = {0};
    dstr mac = {0};
    dstr client_ip = {0};
    char *custom_json = NULL;
    char *port = NULL;
    char *context_id = NULL;
    int redis_result = 0;

    custom_json = get_attrs_json_str(request);
    username = get_username(request);
    mac = get_mac(request);
    client_ip = get_device_ip(request); 
    port = request->client_shortname;
    context_id = request->context_id;

    if (strcmp(error_code, "60029") == 0) {
        full_message = dstr_from_fmt("Radius request timeout error for %s on port %s with mac %s and attributes ,\"RadiusCustom\":%s", 
            n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
    } else if (strcmp(error_code, "60030") == 0) {
        full_message = dstr_from_fmt("Radius eap-tls handshake error for %s on port %s with mac %s and attributes ,\"RadiusCustom\":%s",
                 n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
    } else if (strcmp(error_code, "60031") == 0) {
        full_message = dstr_from_fmt("Radius request wrong eap auth type error for %s on port %s with mac %s and attributes ,\"RadiusCustom\":%s",
                 n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
    } else if (strcmp(error_code, "60002") == 0 || strcmp(error_code, "60035") == 0 || strcmp(error_code, "60039") == 0 || strcmp(error_code, "60051") == 0) {
        char *org_id = NULL;

        redis_result = get_org_id_for_client(request->client_shortname, &org_id);
        if (redis_result) 
        {
            radlog(L_ERR, "radius_internal_logger_centrale failed to get org_id from redis on port %s with mac %s with error '%s' ,\"RadiusCustom\":%s", 
                            n_str(port), n_str(dstr_to_cstr(&mac)), redis_dal_error_descr(redis_result), n_str(custom_json));
        }

        full_message = dstr_from_fmt("%s while connecting to BASEURL/organizations/%s/authndot1x for %s on port %s with mac %s ,\"RadiusCustom\":%s",
                 n_str(message), n_str(org_id), n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);

        if (org_id) free(org_id);
    } else if (strcmp(error_code, "1") == 0) {
        char *auth_method = NULL;
        VALUE_PAIR *auth_type = pairfind(request->config_items, PW_AUTH_TYPE);

        if (auth_type) {
            auth_method = dict_valnamebyattr(PW_AUTH_TYPE, auth_type->vp_integer);
        }

        full_message = dstr_from_fmt( "%s for %s on port %s with mac %s, client ip %s, auth method %s and attributes ,\"RadiusCustom\":%s",
                n_str(message), n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(dstr_to_cstr(&client_ip)), 
                n_str(auth_method), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
    } else {
        dstr d_message = {0};

        d_message = dstr_cstr(message);
        log_portnox_error(error_code, &d_message, request);

        dstr_destroy(&d_message);
    }

    if (custom_json) free(custom_json);
    dstr_destroy(&full_message);
    dstr_destroy(&username);
    dstr_destroy(&mac);
    dstr_destroy(&client_ip);
    return 0;
}
