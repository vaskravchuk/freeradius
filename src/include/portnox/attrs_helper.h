/*
 * attrs_helper.h	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */
#ifndef ATTRS_HELPER_H
#define ATTRS_HELPER_H

#include <freeradius-devel/ident.h>
RCSIDH(attrs_helper_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dstr.h>

dstr get_vps_attr_or_empty(REQUEST *request, char *attr);
dstr get_username(REQUEST *request);
dstr get_mac(REQUEST *request);
dstr get_nas_port(REQUEST *request);
dstr get_device_ip(REQUEST *request);
dstr get_acct_data_in(REQUEST *request);
dstr get_acct_data_out(REQUEST *request);
dstr get_acct_disconnection_reason(REQUEST *request);
dstr get_acct_subtype(REQUEST *request);

#endif //ATTRS_HELPER_H
