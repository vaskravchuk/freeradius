//
// Created by darya.nekryach on 1/31/2019.
//

#ifndef JSON_H
#define JSON_H

#include <freeradius-devel/portnox/dep/cJSON.h>

typedef struct portnox_auth_request portnox_auth_request;

//request info structure 
struct portnox_auth_request {
    int authn_method;
    char *mac_addr;
    char *plain_pwd;
    char *nt_challenge;
    char *nt_response;
    char *username;
};

// radius custom attributes structure
struct radius_custom {
    char *attr;
    char *value;
};
// destroy structures
void request_data_destroy(struct portnox_auth_request *data);
void radius_custom_destroy(struct radius_custom* rad_custom);
void radius_custom_array_destroy(struct radius_custom *rad_custom, int *size);

// create json string request with request data and custom radius attributes 
char *create_request_data_json(struct portnox_auth_request *req, struct radius_custom rad_attr[], int attr_len);

cJSON *make_custom_attributes(struct radius_custom rad_attr[], int attr_len);
char *get_val_by_attr_from_json(char *json, char *attr);

// parse response json radius custom attributes into radius_custom struct array
struct radius_custom *parse_response_data(char *json, int *size);

#endif //JSON_H
