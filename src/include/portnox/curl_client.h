/*
 * curl_client.h	Execute curl.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#ifndef CURL_CLIENT_H
#define CURL_CLIENT_H

#include <freeradius-devel/portnox/dstr.h>

/* request structure */
typedef struct srv_req {
    /* endpoint url */
    char* url = NULL;
    /* data to send. if empty -> GET request */
    char* data = NULL;
    /* if 'true' -> print curl logs */
    int is_debug = 0;
    /* if 'true' -> use certificate */
    int need_crt_auth = 0;
} srv_req;

/* response from server */
typedef struct srv_resp {
    /* curl return code */
    int return_code = 0;
    /* http code */
    long http_code = 0;
    /* plain data from be */
    char* data = NULL;
} srv_resp;

/* Create/destroy structs */
srv_req req_create(char* url, char* data, int is_debug, int need_crt_auth);
srv_resp resp_create(int return_code, int http_code, char* data);
req_destroy(srv_req* req);
resp_destroy(srv_resp* resp);

/* Do curl http call */
srv_resp exec_http_request(srv_req* req);

#endif //CURL_CLIENT_H
