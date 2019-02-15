//
// Created by darya.nekryach on 1/31/2019.
//

#ifndef JSON_HELPER_H
#define JSON_H

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dep/cJSON.h>

char *get_val_by_attr_from_json(char *json, char *attr);
void parse_custom_attr(cJSON *json, VALUE_PAIR **output_pairs);
cJSON *get_attrs_json(REQUEST *request);
char *get_attrs_json_str(REQUEST *request);

#endif //JSON_H
