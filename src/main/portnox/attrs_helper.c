/*
 * attrs_helper.c	portnox config.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dstr.h>
#include <freeradius-devel/portnox/attrs_helper.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/portnox_auth.h>
#include <freeradius-devel/portnox/string_helper.h>

dstr get_username(REQUEST *request) {
    return get_vps_attr_or_empty(request, USERNAME_ATTR);
}

dstr get_mac(REQUEST *request) {
	dstr str = {0};

	str = get_vps_attr_or_empty(request, CALLING_STATION_ID_ATTR);

	if (!is_nas(&str)) {
		dstr_replace_chars(&str, '-', ':');
		dstr_to_lower(&str);
	} else {
		str = dstr_cstr("00:00:00:00:00:00");
	}

	return str;
}

dstr get_nas_port(REQUEST *request) {
    return get_vps_attr_or_empty(request, NAS_PORT_ATTR);
}

dstr get_device_ip(REQUEST *request) {
    dstr str = {0};

    str = get_vps_attr_or_empty(request, TUNNEL_CLIENT_ENDPOINT_ATTR);

    if (is_nas(&str)) {
        str = get_vps_attr_or_empty(request, FRAMED_IP_ADDRESS_ATTR);
    }

    return str;
}

dstr get_acct_data_in(REQUEST *request) {
    return get_vps_attr_or_empty(request, ACCT_INPUT_OCTETS_ATTR);
}

dstr get_acct_data_out(REQUEST *request) {
    return get_vps_attr_or_empty(request, ACCT_OUTPUT_OCTETS_ATTR);
}

dstr get_acct_disconnection_reason(REQUEST *request) {
    return get_vps_attr_or_empty(request, ACCT_TERMINATE_CAUSE_ATTR);
}

dstr get_acct_subtype(REQUEST *request) {
    return get_vps_attr_or_empty(request, ACCT_STATUS_TYPE_ATTR);
}

dstr get_vps_attr_or_empty(REQUEST *request, char *attr) {
	int len = 0;
    char val[ATTR_VALUE_BUF_SIZE];
    char *val_escaped = NULL;
	dstr str = {0};

    if (request->packet) {
    	for (VALUE_PAIR *vp = request->packet->vps; vp; vp = vp->next) {
    		if (!vp->name || !(*vp->name)) continue;
    		if (strcmp(attr, vp->name) == 0) {
    			len = vp_prints_value(val, ATTR_VALUE_BUF_SIZE, vp, 0);

                val[len] = 0;

                val_escaped = str_replace(val, "\\\\", "\\");
                str = dstr_cstr(val_escaped);

                if (val_escaped) free(val_escaped);
    			break;	
    		}
    	}
    }

	return str;
}