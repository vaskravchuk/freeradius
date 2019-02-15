#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/curl_client.h>
#include <freeradius-devel/portnox/portnox_auth.h>
#include <freeradius-devel/portnox/json_helper.h>
#include <freeradius-devel/portnox/log_helper.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <syslog.h>

#define TAG "radiusd"

void to_syslog(char* priority, dstr* message);
void log_to_portnox(dstr* message);

void log(char* code, dstr *message, char* priority, REQUEST* req) {
    dstr full_message = {0};

    full_message = dstr_from_fmt("%s ContextId: %s; %s", code, req->context_id, dstr_to_cstr(message));

    // to syslog
    to_syslog(priority, message);

    // to portnox
    log_to_portnox(&full_message);
}

void to_syslog(char* priority, dstr *message) {
    int syslog_priority = 0;

    if(strcmp(priority, "info") == 0){
        syslog_priority = LOG_INFO;
    }
    else if(strcmp(priority, "error") == 0){
        syslog_priority = LOG_ERR;
    }
    else if(strcmp(priority, "debug") == 0){
        syslog_priority = LOG_DEBUG;
    }
    else{
        syslog_priority = LOG_INFO;
    }

    openlog(TAG, LOG_PID, LOG_LOCAL1);
    syslog(LOG_MAKEPRI(LOG_LOCAL1, syslog_priority), "%s", dstr_to_cstr(message));
}

void log_to_portnox(dstr *message) {
    srv_req req = req_create(portnox_config.daemon.logging_url, dstr_to_cstr(message), 0, 0);

    srv_resp resp = exec_http_request(&req);

    req_destroy(&req);
    resp_destroy(&resp);
}

void log_info(dstr *message,  REQUEST* req) {
    log("0", message, "info", req);
}

void log_error(char* code, dstr *message, REQUEST* req) {
    log(code, message, "error", req);
}

int radius_internal_logger_centrale(char *error_code, char *message, REQUEST *request) {
    dstr full_message = {0};

    char *custom_json = get_attrs_json_str(request);

    dstr username = get_username(request);
    dstr mac = get_mac(request);
    char *port = request->client_shortname;
    char *context_id = request->context_id;

    if (strcmp(error_code, "60029") == 0) {
        full_message = dstr_from_fmt("Radius request timeout error for %s on port %s with mac %s and attributes %s", 
            dstr_to_cstr(&username), port, dstr_to_cstr(&mac), custom_json);
        log_error(error_code, &full_message, request);
    } else if (strcmp(error_code, "60030") == 0) {
        full_message = dstr_from_fmt("Radius eap-tls handshake error for %s on port %s with mac %s and attributes %s",
                 dstr_to_cstr(&username), port, dstr_to_cstr(&mac), custom_json);
        log_error(error_code, &full_message, request);
    } else if (strcmp(error_code, "60031") == 0) {
        full_message = dstr_from_fmt("Radius request wrong eap auth type error for %s on port %s with mac %s and attributes %s",
                 dstr_to_cstr(&username), port, dstr_to_cstr(&mac), custom_json);
        log_error(error_code, &full_message, request);
    } else if (strcmp(error_code, "1") == 0) {
        full_message = dstr_from_fmt( "%s %s for %s on port %s with mac %s and attributes %s",
                error_code, message, dstr_to_cstr(&username), port, dstr_to_cstr(&mac), custom_json);
        log_error(error_code, &full_message, request);
    } else {
        dstr mess = dstr_cstr(message);
        log_error(error_code, &mess, request);
    }

    dstr_destroy(&full_message);
    dstr_destroy(&username);
    dstr_destroy(&mac);
    return 0;
}
