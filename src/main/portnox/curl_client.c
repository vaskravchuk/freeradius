/*
 * curl_client.c	Execute curl.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/portnox/curl_client.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/dstr.h>
#include <stdio.h>
#include <curl/curl.h>

#define START_BUF_SIZE 1024

static size_t curl_write_callback_string(void *contents, size_t size, size_t nmemb, void *usr_data);

srv_req req_create(char* url, char* data, int is_debug, int need_crt_auth) {
    return (srv_req) {strdup(url), data, is_debug, need_crt_auth};
}

srv_resp resp_create(int return_code, int http_code, char* data) {
    return (srv_resp) {return_code, http_code, data};
}

void req_destroy(srv_req* req) {
    if (req->data) {
        free(req->data);
        req->data = NULL;
    }
    if (req->url) {
        free(req->url);
        req->url = NULL;
    }
}

void resp_destroy(srv_resp* resp) {
    if (resp->data) {
        free(resp->data);
        resp->data = NULL;
    }
}

/* callback to save incoming data */
static size_t curl_write_callback_string(void *contents, size_t size, size_t nmemb, void *usr_data) {
    dstr* buf = (dstr*)usr_data;
    size_t data_size = size * nmemb;
    dstr_cat_cstr_n(buf, data_size, contents);
    return data_size;
}

srv_resp exec_http_request(srv_req* req) {
    srv_resp resp = {0};
    dstr data;
    CURL *curl;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, req->url);

        /* header for json content type */
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");

        /* disable the Expect header (remove 1 sec delay) */ 
        headers = curl_slist_append(headers, "Expect:");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


#ifdef SKIP_PEER_VERIFICATION
        /*
         * If you want to connect to a site who isn't using a certificate that is
         * signed by one of the certs in the CA bundle you have, you can skip the
         * verification of the server's certificate. This makes the connection
         * A LOT LESS SECURE.
         *
         * If you have a CA cert for the server stored someplace else than in the
         * default bundle, then the CURLOPT_CAPATH option might come handy for
         * you.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
        /*
         * If the site you're connecting to uses a different host name that what
         * they have mentioned in their server certificate's commonName (or
         * subjectAltName) fields, libcurl will refuse to connect. You can skip
         * this check, but this will make the connection less secure.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
        /* do not destroy, we will move string to outside scope */
        data = dstr_create(START_BUF_SIZE);
        /* curl_easy_perform will return "22" if http_code will be >= 400 */
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
        /* setup timeout */
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, portnox_config.be.timeout);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, req->is_debug ? 1L : 0L);
        /* Perform the request, res will get the return code */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_string);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        if (req->data && *req->data) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->data);
        }

        /* Set the cert for client authentication if needed*/
        if (req->need_crt_auth) {
            curl_easy_setopt(curl, CURLOPT_SSLCERT,  portnox_config.be.req_crt);
            curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
            curl_easy_setopt(curl, CURLOPT_SSLCERTPASSWD, portnox_config.be.req_crt_pwd);
        }

        /* do all work */
        resp.return_code = curl_easy_perform(curl);
        curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &resp.http_code);

        /* moving string to request scope */
        resp.data = dstr_to_cstr(&data);

        /* always cleanup */
        curl_easy_cleanup(curl);

        curl_slist_free_all(headers);
    }

    return resp;
}