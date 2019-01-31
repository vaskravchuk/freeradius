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
/* request structure */
struct srv_req {
    /* endpoint url */
    char* url;
    /* data to send. if empty -> GET request */
    dstr data;
    /* if 'true' -> print curl logs */
    int is_debug;

    /* cert (pfx) path to authenticate request on be */
    char* req_auth_crt_path;
    /* pwd to auth certificate */
    char* req_auth_crt_pwd;
};

typedef struct srv_resp srv_resp;
/* response from server */
struct srv_resp {
    /* curl return code */
    int return_code;
    /* http code */
    long http_code;
    /* plain data from be */
    dstr data;
};

/* Create/destroy structs */
srv_req req_create(char* url, dstr data, int is_debug, int need_crt_auth);
srv_resp resp_create(int return_code, int http_code, dstr data);
req_destroy(srv_req* req);
resp_destroy(srv_resp* resp);

/* Do curl http call */
srv_resp exec_http_request(srv_req* req);

#endif //CURL_P_H
