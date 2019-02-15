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

#define TAG "radiusd.script"

void to_syslog(char* priority, char* message);
void log_to_portnox(char* message);

void log(char* code, char* message, char* priority, REQUEST* req) {
    char * full_message = calloc(1024, sizeof(char *));

    snprintf(full_message, 1024 * sizeof(char *), "%s ContextId: %s; %s", code, req->context_id, message);

    // to syslog
    to_syslog(priority, message);

    // to portnox if not inner port
    log_to_portnox(full_message);

    //free(full_message);
}

void to_syslog(char* priority, char* message) {
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

    openlog(TAG, LOG_PID, LOG_LOCAL2);
    syslog(LOG_MAKEPRI(LOG_LOCAL2, syslog_priority), "%s", message);
}

void log_to_portnox(char* message) {
    srv_req req = req_create(portnox_config.daemon.logging_url, message, 0, 0);

    srv_resp resp = exec_http_request(&req);

    req_destroy(&req);
}

void log_info(char* message,  REQUEST* req) {
    log("0", message, "info", req);
}

void log_error(char* code, char* message, REQUEST* req) {
    log(code, message, "error", req);
}

int radius_internal_logger_centrale(char *error_code, char *message, REQUEST *request) {
    char *full_message = calloc(5000, sizeof(char *));

    char *custom_json = get_attrs_json_str(request);

    char *username = get_val_by_attr_from_json(custom_json, USERNAME_PR);
    char *mac = get_val_by_attr_from_json(custom_json, MAC_ADDRESS_PR);
    char *port = request->client_shortname;
    char *context_id = request->context_id;
    message = get_attrs_json_str(request, "P-Error-Msg");
    
    if (strcmp(error_code, "60029") == 0) {
        snprintf(full_message, 5000 * sizeof(char *),
                 "Radius request timeout error for %s on port %s with mac %s and attributes %s",
                 username, port, mac, custom_json);

        log_error(error_code, full_message, request);
    } else if (strcmp(error_code, "60030") == 0) {
        snprintf(full_message, 5000 * sizeof(char *),
                 "Radius eap-tls handshake error for %s on port %s with mac %s and attributes %s",
                 username, port, mac, custom_json);

        log_error(error_code, full_message, request);
    } else if (strcmp(error_code, "60031") == 0) {
        snprintf(full_message, 5000 * sizeof(char *),
                 "Radius request wrong eap auth type error for %s on port %s with mac %s and attributes %s",
                 username, port, mac, custom_json);

        log_error(error_code, 5000 * sizeof(char *), request);
    } else if (strcmp(error_code, "1") == 0) {
        snprintf(full_message, 5000 * sizeof(char *),
                "%s for %s on port %s with mac %s and attributes %s",
                message, username, port, mac, custom_json);

        log_error(error_code, full_message, request);
    } else {
        log_error(error_code, message, request);
    }

    free(full_message);
    return 0;
}
