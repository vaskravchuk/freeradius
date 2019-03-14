//
// Created by darya.nekryach on 1/31/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <freeradius-devel/portnox/json_helper.h>
#include <freeradius-devel/portnox/dep/cJSON.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/portnox/string_helper.h>
#include <freeradius-devel/portnox/portnox_common.h>


#define REQ_CUSTOM_ATTR_VAL_KEY     "Key"
#define REQ_CUSTOM_ATTR_VAL_VALUE   "Value"

#define RESP_CUSTOM_ATTR_VAL_KEY    "key"
#define RESP_CUSTOM_ATTR_VAL_VALUE  "value"

char *get_val_by_attr_from_json(char *json, char *attr) {
    cJSON *parsed = NULL;
    cJSON *found_item = NULL;
    char *val = NULL;

    parsed = cJSON_Parse(json);
    if (!parsed) goto fail;

    found_item = cJSON_GetObjectItem(parsed, attr);
    if (!found_item || !found_item->valuestring) goto fail;

    /* should be copied */
    val = strdup(found_item->valuestring);

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
            dstr dval = {0};

            dval = dstr_cstr(val->valuestring);
            dstr_extract_quoted_str(&dval);
            vp = pairmake(key->valuestring, dstr_to_cstr(&dval), T_OP_ADD);
            pairadd(output_pairs, vp);

            dstr_destroy(&dval);
        }
    }
}

cJSON *get_attrs_json(REQUEST *request) {
    /*
     * EMMET MARVIN & MARTIN had problem with parsing
     * request json bacause of 'Chargeable-User-Identity' attr 
     * So lets skip it
     */
    static char *except_attrs[] = { "TLS-Client-Cert-Filename", "EAP-Message", "Message-Authenticator", "Chargeable-User-Identity" };
    static char *except_attrs_size = sizeof(except_attrs) / sizeof(except_attrs[0]);
    char val[ATTR_VALUE_BUF_SIZE];
    int len = 0;
    cJSON *array = NULL;
    cJSON *item = NULL;
    
    array = cJSON_CreateArray();
    
    if (request->packet) {
        for (VALUE_PAIR *vp = request->packet->vps; vp; vp = vp->next) {
            if (!vp->name || !(*vp->name)) continue;
            if (is_contains(except_attrs, except_attrs_size, vp->name)) continue;
            char *val_escaped = NULL;
            
            /* get value */
            len = vp_prints_value(val, ATTR_VALUE_BUF_SIZE, vp, 0);
            val[len] = 0;
            val_escaped = str_replace(val, "\\\\", "\\");

            /* to json */
            item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_KEY, vp->name);
            cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_VALUE, val_escaped);
            cJSON_AddItemToArray(array, item);

            if (val_escaped) free(val_escaped);
        }
    }

    /* context id */
    item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_KEY, CONTEXT_ID_ATTR);
    cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_VALUE, request->context_id);
    cJSON_AddItemToArray(array, item);

    /* port */
    item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_KEY, PORT_ATTR);
    cJSON_AddStringToObject(item, REQ_CUSTOM_ATTR_VAL_VALUE, request->client_shortname);
    cJSON_AddItemToArray(array, item);

    return array;
}

char *get_attrs_json_str(REQUEST *request) {
    cJSON *attrs = NULL;
    char* json = NULL;

    /* default */
    json = "";

    attrs = get_attrs_json(request);
    json = cJSON_Print(attrs);
    cJSON_Minify(json);
    cJSON_Delete(attrs);

    return json;
}