/*
 * portnox_config.h	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */
#ifndef PORTNOX_AUTH_H
#define PORTNOX_AUTH_H

#include <freeradius-devel/ident.h>
RCSIDH(portnox_auth_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/portnox/attrs_helper.h>

#define AUTH_METHOD_PR				"AuthNMethod"
#define MAC_ADDRESS_PR				"MacAddress"
#define PLAIN_PWD_PR				"PlainPwd"
#define USERNAME_PR					"UserName"
#define CLIENT_CERT_PR				"ClientCertificate"
#define NT_CHALLENGE_PR				"NtChallenge"
#define NT_RESPONSE_PR	            "NtClientResponse"
#define RADIUS_CUSTOM_PR			"RadiusCustom"
#define NTKEY_PR					"NtKey"

#define REQ_CUSTOM_ATTR_VAL_KEY     "Key"
#define REQ_CUSTOM_ATTR_VAL_VALUE   "Value"

#define RESP_CUSTOM_ATTR_VAL_KEY    "key"
#define RESP_CUSTOM_ATTR_VAL_VALUE  "value"

#define OPERATION_SUCCESS           0
#define ORG_ID_FAILED_GET_ERROR     -1
#define IDENTITY_NOT_FOUND_ERROR    -2
#define AUTH_REJECT_ERROR           -3

#define PAP_AUTH_METHOD             1
#define MSCHAP_AUTH_METHOD          2
#define CHAP_AUTH_METHOD            4
#define EAPTLS_AUTH_METHOD          5
#define MD5_AUTH_METHOD             6

#define ATTR_VALUE_BUF_SIZE         256

/* struct to specify concrete attribute processor */
typedef struct auth_attr_proc_t {
	char* attr_name;
    char* json_attr;
    void* user_data;
	void (* processor)(dstr*, void*);
} AUTH_SP_ATTR;

/* struct to specify concrete attribute processor */
typedef struct auth_attr_proc_list_t {
	AUTH_SP_ATTR *items;
	int count;
} AUTH_SP_ATTR_LIST;

typedef struct auth_info_t {
    AUTH_SP_ATTR_LIST *auth_attr_list;
    char* missed_orgid_error_code;
    char* missed_username_error_code;
    char* failed_auth_error_code;
} AUTH_INFO;

int portnox_auth(REQUEST *request, 
                int auth_method, 
                AUTH_INFO *auth_info, 
                VALUE_PAIR **output_pairs);

#endif //PORTNOX_AUTH_H