//
// Created by darya.nekryach on 1/31/2019.
//

#ifndef JSON_H
#define JSON_H

#include <freeradius-devel/portnox/cJSON.h>

//request info structure 
struct request_data {
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

// create json string request with request data and custom radius attributes 
char *create_request_data_json(struct request_data *req, struct radius_custom rad_attr[], int attr_len);

cJSON *make_custom_attributes(struct radius_custom rad_attr[], int attr_len);

//parse response json radius custom attributes into radius_custom struct array
struct radius_custom *parse_response_data(char *toparse);

#endif //JSON_H
