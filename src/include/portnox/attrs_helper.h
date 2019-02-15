/*
 * portnox_config.h	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSIDH(attrs_helper_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dstr.h>

#define USERNAME_ATTR				"User-Name"
#define USER_PWD_ATTR               "User-Password"
#define CHAP_RESPONSE_ATTR          "CHAP-Password"
#define CHAP_CHALLENGE_ATTR         "Packet-Authentication-Vector"
#define MSCHAP2_RESPONSE_ATTR       "MS-CHAP2-Response"
#define MSCHAP_RESPONSE_ATTR        "MS-CHAP-Response"
#define MSCHAP_CHALLENGE_ATTR       "MS-CHAP-Challenge"
#define MD5_RESPONSE_ATTR           "MD5-Password"
#define MD5_CHALLENGE_ATTR          "MD5-Challenge"
#define EAPTLS_CERT_ATTR            "TLS-Client-Cert-Filename"
#define CALLING_STATION_ID_ATTR		"Calling-Station-Id"
#define CONTEXT_ID_ATTR				"CONTEXT_ID"
#define PORT_ATTR					"PORT"
#define NTKEY_ATTR                  "Tmp-String-0"
#define NAS_PORT_ATTR               "NAS-Port-Type"

dstr get_vps_attr_or_empty(REQUEST *request, char *attr);
dstr get_username(REQUEST *request);
dstr get_mac(REQUEST *request);
dstr get_nas_port(REQUEST *request);