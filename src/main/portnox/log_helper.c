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
static dstr get_client_ip_port(REQUEST *request);

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

void log_portnox(int code, dstr *message, int priority, REQUEST* req) {
    dstr full_message = {0};

    full_message = dstr_from_fmt("%d ContextId: %s; %s", code, n_str(req->context_id), n_str(dstr_to_cstr(message)));

    // to syslog
    to_syslog(priority, &full_message);

    // to portnox
    log_to_portnox(&full_message);

    dstr_destroy(&full_message);
}

void log_portnox_info(dstr *message,  REQUEST* req) {
    log_portnox(0, message, INFO_PRIORITY, req);
}

void log_portnox_error(int code, dstr *message, REQUEST* req) {
    log_portnox(code, message, ERROR_PRIORITY, req);
}

int radius_internal_logger_centrale(int error_code, char *message, REQUEST *request) {
    dstr full_message = {0};
    dstr username = {0};
    dstr mac = {0};
    dstr client_ip = {0};
    char *custom_json = NULL;
    char *port = NULL;
    char *auth_method = NULL;
    int redis_result = 0;

    custom_json = get_attrs_json_str(request);
    username = get_username(request);
    mac = get_mac(request);
    port = request->client_shortname;
    auth_method = request->auth_subtype;

    switch (error_code) {
    case 60029:
        full_message = dstr_from_fmt("Radius request timeout error for %s on port %s with mac %s and attributes \"RadiusCustom\":%s",
                                     n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
        break;
    case 60030:
        full_message = dstr_from_fmt("Radius EAP-TLS handshake error for %s on port %s with mac %s and attributes \"RadiusCustom\":%s",
                                     n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
        break;
    case 60031:
        full_message = dstr_from_fmt("Radius request wrong eap auth type error for %s on port %s with mac %s and attributes \"RadiusCustom\":%s",
                                     n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
        break;
    case 60060 ... 60084:
        full_message = dstr_from_fmt("Radius EAP-TLS error %s for %s on port %s with mac %s and attributes \"RadiusCustom\":%s",
                                     n_str(message), n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
        break;
    case 60002:
    case 60035:
    case 60039:
    case 60051: {
        char *org_id = NULL;

        redis_result = get_org_id_for_client(request->client_shortname, &org_id);
        if (redis_result)
        {
            radlog(L_ERR, "radius_internal_logger_centrale failed to get org_id from redis on port %s with mac %s with error '%s' \"RadiusCustom\":%s",
                   n_str(port), n_str(dstr_to_cstr(&mac)), redis_dal_error_descr(redis_result), n_str(custom_json));
        }

        full_message = dstr_from_fmt("%s while connecting to BASEURL/organizations/%s/authndot1x for %s on port %s with mac %s \"RadiusCustom\":%s",
                                     n_str(message), n_str(org_id), n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);

        if (org_id) free(org_id);
        break;
    }
    case 1:
        client_ip = get_client_ip_port(request);
        full_message = dstr_from_fmt( "%s for %s on port %s with mac %s, client ip %s, auth method %s and attributes \"RadiusCustom\":%s",
                                      n_str(message), n_str(dstr_to_cstr(&username)), n_str(port), n_str(dstr_to_cstr(&mac)), n_str(dstr_to_cstr(&client_ip)),
                                      n_str(auth_method), n_str(custom_json));
        log_portnox_error(error_code, &full_message, request);
        break;
    default: {
        dstr d_message = {0};

        d_message = dstr_cstr(message);
        log_portnox_error(error_code, &d_message, request);

        dstr_destroy(&d_message);
        break;
    }
    };

    if (custom_json) free(custom_json);
    dstr_destroy(&full_message);
    dstr_destroy(&username);
    dstr_destroy(&mac);
    dstr_destroy(&client_ip);
    return 0;
}

int ssl_error_to_error_id(char *ssl_error) {
    int error_id = 60060;

    if (strcmp(ssl_error, "UM") == 0) {
        return error_id;
    } else if (strcmp(ssl_error, "PU") == 0) {
        return error_id + 1;
    } else if (strcmp(ssl_error, "HF") == 0) {
        return error_id + 2:
    } else if (strcmp(ssl_error, "BC") == 0) {
        return error_id + 3;
    } else if (strcmp(ssl_error, "CU") == 0) {
        return error_id 4;
    } else if (strcmp(ssl_error, "IP") == 0) {
        return error_id + 5;
    } else if (strcmp(ssl_error, "CA") == 0) {
        return error_id + 6;
    } else if (strcmp(ssl_error, "CY") == 0) {
        return error_id + 7;
    } else if (strcmp(ssl_error, "IE") == 0) {
        return error_id + 8;
    } else if (strcmp(ssl_error, "AD") == 0) {
        return error_id + 9;
    } else if (strcmp(ssl_error, "BM") == 0) {
        return error_id + 10;
    } else if (strcmp(ssl_error, "DF") == 0) {
        return error_id + 11;
    } else if (strcmp(ssl_error, "NC") == 0) {
        return error_id + 12;
    } else if (strcmp(ssl_error, "UC") == 0) {
        return error_id + 13;
    } else if (strcmp(ssl_error, "CR") == 0) {
        return error_id + 14;
    } else if (strcmp(ssl_error, "CE") == 0) {
        return error_id + 15;
    } else if (strcmp(ssl_error, "DC") == 0) {
        return error_id + 16;
    } else if (strcmp(ssl_error, "RO") == 0) {
        return error_id + 17;
    } else if (strcmp(ssl_error, "DE") == 0) {
        return error_id + 18;
    } else if (strcmp(ssl_error, "CY") == 0) {
        return error_id + 19;
    } else if (strcmp(ssl_error, "ER") == 0) {
        return error_id + 20;
    } else if (strcmp(ssl_error, "IS") == 0) {
        return error_id + 21;
    } else if (strcmp(ssl_error, "US") == 0) {
        return error_id + 22;
    } else if (strcmp(ssl_error, "NR") == 0) {
        return error_id + 23;
    } else if (strcmp(ssl_error, "UP") == 0) {
        return error_id + 24;
    }
    return 60030;
}

static dstr get_client_ip_port(REQUEST *request) {
    dstr str = {0};
    RADIUS_PACKET *packet = NULL;
    char ip[INET_ADDRSTRLEN] = {0};

    packet = request->packet;

    if (*((uint32_t*)&packet->src_ipaddr.ipaddr) != INADDR_ANY) {
        inet_ntop(packet->src_ipaddr.af,
                  &packet->src_ipaddr.ipaddr,
                  ip, sizeof(ip));
        str = dstr_from_fmt("%s:%d", ip, packet->src_port);
    } else if (*((uint32_t*)&packet->dst_ipaddr.ipaddr) != INADDR_ANY) {
        inet_ntop(packet->dst_ipaddr.af,
                  &packet->dst_ipaddr.ipaddr,
                  ip, sizeof(ip));
        str = dstr_from_fmt("%s:%d", ip, packet->dst_port);
    }

    return str;
}