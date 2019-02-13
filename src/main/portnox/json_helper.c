//
// Created by darya.nekryach on 1/31/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <freeradius-devel/portnox/json_helper.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/portnox/portnox_auth.h>

char *get_val_by_attr_from_json(char *json, char *attr) {
    cJSON *parsed = NULL;
    cJSON *found_item = NULL;
    char *val = NULL;

    parsed = cJSON_Parse(json);
    if (!parsed) goto fail;

    found_item = cJSON_GetObjectItem(parsed, attr);
    if (!found_item || !found_item->valuestring) goto fail;

    /* should be copied */
    val =  strdup(found_item->valuestring);

    fail:
    if (parsed) cJSON_Delete(parsed);
    return val;
}

void parse_custom_attr(cJSON *attrs, VALUE_PAIR **output_pairs) {
    cJSON *item = NULL;
    cJSON *key = NULL;
    cJSON *val = NULL;
    VALUE_PAIR *vp;

    if (!attrs) return;

    cJSON_ArrayForEach(item, attrs) {
        key = cJSON_GetObjectItem(item, RESP_CUSTOM_ATTR_VAL_KEY);
        val = cJSON_GetObjectItem(item, RESP_CUSTOM_ATTR_VAL_VALUE);
        if (key && val) {
            vp = pairmake(key->valuestring, val->valuestring, T_OP_ADD);
            pairadd(output_pairs, vp);
        }
    }
}

cJSON *get_attrs_json(REQUEST *request) {
    cJSON *array = NULL;
    cJSON *item = NULL;
    char val[ATTR_VALUE_BUF_SIZE];
    int len = 0;
    
    array = cJSON_CreateArray();
    
    if (request->packet) {
        for (VALUE_PAIR *vp = request->packet->vps; vp; vp = vp->next) {
            if (!vp->name || !(*vp->name)) continue;
            /* get value */
            len = vp_prints_value(val, ATTR_VALUE_BUF_SIZE, vp, 0);
            val[len] = 0;

            /* to json */
            item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_KEY, vp->name);
            cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_VALUE, val);
            cJSON_AddItemToArray(array, item);
        }
    }

    /* context id */
    item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, CONTEXT_ID_ATTR, request->context_id);
    cJSON_AddItemToArray(array, item);

    /* port */
    item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, PORT_ATTR, request->client_shortname);
    cJSON_AddItemToArray(array, item);

    return array;
}

char *get_attrs_json_str(REQUEST *request) {
    cJSON *attrs = NULL;
    char* json = NULL;

    /* default */
    json = "";

    attrs = get_attrs_json(request);
    if (attrs) {
        json = cJSON_Print(attrs);
        cJSON_Delete(attrs);
    }

    return json;
}