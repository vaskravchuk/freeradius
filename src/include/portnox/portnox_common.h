/*
 * portnox_common.h	portnox common.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */
#ifndef PORTNOX_COMMON_H
#define PORTNOX_COMMON_H

#include <freeradius-devel/ident.h>
RCSIDH(portnox_common_h, "$Id$")

#define ATTR_VALUE_BUF_SIZE         256

#define USERNAME_ATTR               "User-Name"
#define USER_PWD_ATTR               "User-Password"
#define CHAP_RESPONSE_ATTR          "CHAP-Password"
#define CHAP_CHALLENGE_ATTR         "Packet-Authentication-Vector"
#define MSCHAP2_RESPONSE_ATTR       "MS-CHAP2-Response"
#define MSCHAP_RESPONSE_ATTR        "MS-CHAP-Response"
#define MSCHAP_CHALLENGE_ATTR       "MS-CHAP-Challenge"
#define MD5_RESPONSE_ATTR           "MD5-Password"
#define MD5_CHALLENGE_ATTR          "MD5-Challenge"
#define EAPTLS_CERT_ATTR            "TLS-Client-Cert-Filename"
#define CALLING_STATION_ID_ATTR     "Calling-Station-Id"
#define CONTEXT_ID_ATTR             "CONTEXT_ID"
#define PORT_ATTR                   "PORT"
#define NTKEY_ATTR                  "Tmp-String-0"
#define NAS_PORT_ATTR               "NAS-Port-Type"
#define TUNNEL_CLIENT_ENDPOINT_ATTR "Tunnel-Client-Endpoint"
#define FRAMED_IP_ADDRESS_ATTR      "Framed-IP-Address"
#define ACCT_INPUT_OCTETS_ATTR      "Acct-Input-Octets"
#define ACCT_OUTPUT_OCTETS_ATTR     "Acct-Output-Octets"
#define ACCT_TERMINATE_CAUSE_ATTR   "Acct-Terminate-Cause"
#define ACCT_STATUS_TYPE_ATTR       "Acct-Status-Type"

#define AUTH_METHOD_PR				"AuthNMethod"
#define MAC_ADDRESS_PR				"MacAddress"
#define PLAIN_PWD_PR				"PlainPwd"
#define USERNAME_PR					"UserName"
#define CLIENT_CERT_PR				"ClientCertificate"
#define NT_CHALLENGE_PR				"NtChallenge"
#define NT_RESPONSE_PR	            "NtClientResponse"
#define RADIUS_CUSTOM_PR			"RadiusCustom"
#define SRC_IP_ADDRESS_PR			"AuthRequestIp"
#define NTKEY_PR					"NtKey"

#define EVENT_TYPE_PR               "EventType"
#define EVENT_SUBTYPE_PR            "EventSubType"
#define DEVICE_IP_PR                "DeviceIp"
#define DEVICE_MAC_PR               "DeviceMac"
#define EVENT_DATE_PR               "EventDate"
#define EVENT_TIME_PR               "EventTime"
#define DATA_IN_PR                  "DataIn"
#define DATA_OUT_PR                 "DataOut"
#define DISCONNECTION_REASON_PR     "DisconnectReason"

#endif //PORTNOX_COMMON_H