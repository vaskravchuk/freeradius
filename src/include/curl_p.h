/*
 *  curl_p.c	Execute curl.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#ifndef CURL_P_H
#define CURL_P_H

#include "dstr.h"

/* Id response or request is destroyed*/
#define is_destroyed(S) (!((S).data)->s)

typedef struct srv_req srv_req;
struct srv_req {
    char* url;
    dstr data;
    int is_debug;
    char* req_auth_crt_path;
    char* req_auth_key_path;
};

typedef struct srv_resp srv_resp;
struct srv_resp {
    int return_code;
    long http_code;
    dstr data;
};

srv_req req_create(char* url, dstr data, int is_debug, int need_crt_auth);
srv_resp resp_create(int return_code, int http_code, dstr data);
req_destroy(srv_req* req);
resp_destroy(srv_resp* resp);

/* Do curl http call */
srv_resp exec_http_request(srv_req* req);

#endif //CURL_P_H
