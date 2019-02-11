//
// Created by darya.nekryach on 1/31/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <freeradius-devel/portnox/json_p.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/dsrt.h>

char *create_request_data_json(struct portnox_auth_request *req, struct radius_custom rad_attr[], int attr_len) {
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
    if (rad_attr != NULL & attr_len > 0) {
        cJSON *rad_custom = make_custom_attributes(rad_attr, attr_len);
        cJSON_AddItemToObject(request_data, "RadiusCustom", rad_custom);
    }
    char *json = cJSON_Print(request_data);
    cJSON_Delete(request_data);
    return json;
}

char *get_val_by_attr_from_json(char *json, char *attr) {
    cJSON *parsed = cJSON_Parse(json);
    char *val =  strdup(cJSON_GetObjectItem(parsed, attr)->valuestring);
    cJSON_Delete(parsed);
    return val;
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

struct radius_custom *parse_response_data(char *json, int *size) {
    cJSON *array = NULL;
    cJSON *parsed = cJSON_Parse(json);
    cJSON *rad_custom_arr = cJSON_GetObjectItem(parsed, "RadiusCustom");

    int attrs_size = cJSON_GetArraySize(rad_custom_arr);
    *size = attrs_size;
    struct radius_custom *rad_attr = malloc(attrs_size * sizeof(struct radius_custom));
    int i = 0;

    cJSON_ArrayForEach(array, rad_custom_arr) {
        rad_attr[i].attr = strdup(cJSON_GetObjectItem(array, "key")->valuestring);
        rad_attr[i].value = strdup(cJSON_GetObjectItem(array, "value")->valuestring);
        i++;
    }
    cJSON_Delete(parsed);
    return rad_attr;
}

void request_data_destroy(struct portnox_auth_request *data) {
    free(data->plain_pwd);
    free(data->nt_response);
    free(data->nt_challenge);
    free(data->username);
    free(data->mac_addr);
    free(data->caller_ip);
    free(data->caller_port);
    free(data->cluster_id);
}

void radius_custom_destroy(struct radius_custom *rad_custom) {
    free(rad_custom->value);
    free(rad_custom->attr);
}

void radius_custom_array_destroy(struct radius_custom *rad_custom, int *size) {
    int i;
    for (i = 0; i < *size; i++) {
        radius_custom_destroy(&rad_custom[i]);
    }
}
