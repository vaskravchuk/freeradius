/*
 * portnox_config.h	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSIDH(portnox_auth_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dstr.h>

#define AUTH_METHOD_PR				"AuthNMethod"
#define MAC_ADDRESS_PR				"MacAddress"
#define PLAIN_PWD_PR				"PlainPwd"
#define USERNAME_PR					"UserName"
#define CLIENT_CERT_PR				"ClientCertificate"
#define NT_CHALLENGE_PR				"NtChallenge"
#define NT_CHALLENGE_RESPONSE_PR	"NtClientResponse"
#define RADIUS_CUSTOM_PR			"RadiusCustom"
#define NTKEY_PR					"NtKey"

#define USERNAME_ATTR				"User-Name"
#define USER_PWD_ATTR				"User-Password"
#define CALLING_STATION_ID_ATTR		"Calling-Station-Id"
#define CONTEXT_ID_ATTR				"CONTEXT_ID"
#define PORT_ATTR					"PORT"
#define NTKEY_ATTR					"Tmp-String-0"

#define REQ_CUSTOM_ATTR_VAL_KEY		"Key"
#define REQ_CUSTOM_ATTR_VAL_VALUE   "Value"

#define OPERATION_SUCCESS			0
#define ORG_ID_NOT_FOUND_ERROR      -1
#define ORG_ID_NOT_FAILED_GET_ERROR -2
#define IDENTITY_NOT_FOUND_ERROR    -3
#define AUTH_REJECT_ERROR    		-4

#define PAP_AUTH_METHOD 1
#define MSCHAP_AUTH_METHOD 2
#define CHAP_AUTH_METHOD 4
#define EAPTLS_AUTH_METHOD 5
#define MD5_AUTH_METHOD 6

/* struct to specify concrete attribute processor */
typedef struct auth_attr_proc_t {
	char* attr_name;
	char* json_attr;
	void (* processor)(dstr*)
} auth_attr_proc_t

/* struct to specify concrete attribute processor */
typedef struct auth_attr_proc_list_t {
	auth_attr_proc_t* items;
	int count;
} auth_attr_proc_list_t


int portnox_auth(REQUEST *request, 
                int auth_method, 
                auth_attr_proc_list_t *attr_proc_list, 
                VALUE_PAIR **output_pairs);