#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/curl_client.h>
#include <freeradius-devel/portnox/json_p.h>
#include <freeradius-devel/portnox/log_p.h>
#include <stdio.h>
#include <mem.h>
#include <malloc.h>
#include <syslog.h>

#define TAG "radiusd.script"

void to_syslog(char* priority, char* message);
void to_portnox_logger(char* message);

void log_p(char* code, char* message, char* priority, REQUEST* req) {
    char * full_message = calloc(1024, sizeof(char *));

    snprintf(full_message, sizeof(full_message), "%s ContextId: %s; %s", code, req->context_id, message);

    // to syslog
    to_syslog(priority, message);

    // to portnox if not inner port
    if (req->packet->dst_port != portnox_config.portnox_inner_port) {
        to_portnox_logger(full_message);
    }

    free(full_message);
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

    openlog(TAG, LOG_PID, LOG_LOCAL1);
    syslog(LOG_MAKEPRI(LOG_LOCAL1, syslog_priority), "%s", message);
}

void to_portnox_logger(char* message) {
    srv_req log_req = req_create(portnox_config.rad_daemon.log_url, message, 0, 0);

    exec_http_request(log_req);

    req_destroy(log_req);
}

void log_info_p(char* message,  REQUEST* req) {
    log_p("0", message, "info", req);
}

void log_error_p(char* code, char* message, REQUEST* req) {
    log_p(code, message, "error", req);
}

int radius_internal_logger_centrale(char *error_code, char *message, REQUEST *request) {
    char *full_message = calloc(1024, sizeof(char *));

    char *username = request->username->data;
    int port = request->packet->dst_port;
    char *mac = ;
    char *context_id = request->context_id;

    cJSON *custom_json = get_attrs_json(request, port, context_id);

    if (strcmp(error_code, "60029") == 0) {

        snprintf(full_message, 1024 * sizeof(char *),
                 "Radius request timeout error for %s on port %d with mac %s and attributes %s",
                 username, port, mac, cJSON_Print(custom_json));

        log_error_p(error_code, full_message, request)
    } else if (strcmp(error_code, "60030") == 0) {
        snprintf(full_message, 1024 * sizeof(char *),
                 "Radius eap-tls handshake error for %s on port %d with mac %s and attributes %s",
                 username, port, mac, cJSON_Print(custom_json));

        log_error_p(error_code, full_message, request)
    } else if (estrcmp(error_code, "60031") == 0) {
        snprintf(full_message, 1024 * sizeof(char *),
                 "Radius request wrong eap auth type error for %s on port %d with mac %s and attributes %s",
                 username, port, mac, cJSON_Print(custom_json));

        log_error_p(error_code, 1024 * sizeof(char *), request)
    } else if (strcmp(error_code, "1") == 0) {
        snprintf(full_message, 1024 * sizeof(char *),
                "%s for %s on port %d with mac %s and attributes %s",
                message, username, port, mac, cJSON_Print(custom_json));

        log_error_p(error_code, full_message, request)
    } else {
        log_error_p(error_code, message, request)
    }

    cJSON_Delete(custom_json);
    free(full_message);
    return 0;
}