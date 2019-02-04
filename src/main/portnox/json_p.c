//
// Created by darya.nekryach on 1/31/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <freeradius-devel/portnox/json_p.h>
#include <freeradius-devel/portnox/cJSON.h>
#include <freeradius-devel/portnox/dsrt.h>

char *create_request_data_json(struct request_data *req, struct radius_custom rad_attr[], int attr_len) {
    cJSON *request_data = cJSON_CreateObject();

    if (req->authn_method) {
        cJSON_AddNumberToObject(request_data, "AuthNMethod", req->authn_method);
    }
    if (req->mac_addr) {
        cJSON_AddStringToObject(request_data, "MacAddress", req->mac_addr);
    }
    if (req->plain_pwd) {
        cJSON_AddStringToObject(request_data, "PlainPwd", req->plain_pwd);
    }
    if (req->nt_challenge) {
        cJSON_AddStringToObject(request_data, "NtChallenge", req->nt_challenge);
    }
    if (req->nt_response) {
        cJSON_AddStringToObject(request_data, "NtClientResponse", req->nt_response);
    }
    if (req->username) {
        cJSON_AddStringToObject(request_data, "UserName", req->username);
    }

    cJSON *rad_custom = make_custom_attributes(rad_attr, attr_len);
    cJSON_AddItemToObject(request_data, "RadiusCustom", rad_custom);

    char *json = cJSON_Print(request_data);
    cJSON_Delete(request_data);
    return json;
}

cJSON *make_custom_attributes(struct radius_custom rad_attr[], int attr_len) {
    cJSON *rad_custom = cJSON_CreateArray();
    cJSON *item;
    for (int i = 0; i < attr_len; i++) {
        item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "Key", rad_attr[i].attr);
        cJSON_AddStringToObject(item, "Value", rad_attr[i].value);
        cJSON_AddItemToArray(rad_custom, item);
    }
    return rad_custom;
}

struct radius_custom *parse_response_data(char *toparse) {
    cJSON *array = NULL;
    cJSON *parsed = cJSON_Parse(toparse);
    cJSON *rad_custom_arr = cJSON_GetObjectItem(parsed, "RadiusCustom");

    int attrs_size = cJSON_GetArraySize(rad_custom_arr);
    struct radius_custom *rad_attr = malloc(attrs_size * sizeof(struct radius_custom));
    int i = 0;

    cJSON_ArrayForEach(array, rad_custom_arr) {
        rad_attr[i].attr = (cJSON_GetObjectItem(array, "key")->valuestring);
        rad_attr[i].value = cJSON_GetObjectItem(array, "value")->valuestring;
        i++;
    }

    return rad_attr;
}