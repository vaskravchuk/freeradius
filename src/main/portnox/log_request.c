/*
 * log.c	Logging module.
 *
 * Version:	$Id$
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/portnox_config.h>
#include <freeradius-devel/portnox/string_helper.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))


int vstr_format(char * s, int n, const char *format, va_list ap) {
	int len = 0;

	len = vsnprintf(s, n, format, ap);
	len = MIN(len, n-1);
	len = len < 0 ? 0 : len;

	return len;
}

int str_format(char * s, int n, const char *format, ...) {
	int len = 0;

	va_list ap;
	va_start(ap, format);
	len = vstr_format(s, n, format, ap);
	va_end(ap);

	return len;
}

inline int close_str(char *out, int outlen) {
	int l = 0;

	if (outlen - l > 0) out[l++] = '\"';
	if (outlen - l > 0) out[l++] = ',';

	return l;
}

int log_add_json_string(char *out, int outlen, const char *key, const char *value) {
	int len = 0;

	len = str_format(out, outlen, "\"%s\":\"", key);

	len += json_escape(value, out + len, outlen - len);

	len += close_str(out + len, outlen - len);

	return len;
}

int log_add_json_int(char *out, int outlen, const char *key, const int value) {
	return str_format(out, outlen, "\"%s\":\"%d\",", key, value);
}

int log_add_json_mac(char *out, int outlen, const char *key, VALUE_PAIR *vps) {
	static char *mac_attrs[] = { "Calling-Station-Id" };
	static char *mac_attrs_size = sizeof(mac_attrs) / sizeof(mac_attrs[0]);

	int len = 0;
	char mac_buffer[24];

	for (VALUE_PAIR *vp = vps; vp; vp = vp->next) {
		if (!vp->name || !(*vp->name)) return;
		if (is_contains(mac_attrs, mac_attrs_size, vp->name)) {
			vp_prints_value(mac_buffer, sizeof(mac_buffer), vp, 0);
			break;	
		}
	}

	if (mac_buffer[0]) {
		replace_char(mac_buffer, '-', ':');
		lower(mac_buffer);
		len += log_add_json_string(out + len, outlen - len, key, mac_buffer);
	}
	mac_buffer[len] = 0;

	return len;
}

int log_add_json_vps(char *out, int outlen, const char *key, VALUE_PAIR *vps, int full_info) {
	/* 
	 * Remove not interested attributes
	 * skip nt-key as password
	 */
	static char *except_attrs[] = { "TLS-Client-Cert-Filename", "EAP-Message", "Message-Authenticator", "MS-CHAP-Challenge", "MS-CHAP-Response", "MD5-Challenge", "MD5-Password", "CHAP-Challenge", "CHAP-Password", "User-Password", "Tmp-String-0", "MS-MPPE-Recv-Key", "MS-MPPE-Send-Key", "EAP-MSK", "EAP-EMSK" };
	static char *must_attrs[] = { "State", "User-Name", "NAS-IP-Address", "EAP-Type" };
	static char *except_attrs_size = sizeof(except_attrs) / sizeof(except_attrs[0]);
	static char *must_attrs_size = sizeof(must_attrs) / sizeof(must_attrs[0]);

	char buf[2048];
	int buf_size = sizeof(buf);
	int buf_offset = 0;
	int len = 0;

	for (VALUE_PAIR *vp = vps; vp; vp = vp->next) {
		if (!vp->name || !(*vp->name)) return;
		
		// Do not print except_attrs
		if (is_contains(except_attrs, except_attrs_size, vp->name)) {
			continue;	
		}

		if (!full_info && !is_contains(must_attrs, must_attrs_size, vp->name)) {
			continue;
		}

		// print attribute
		buf_offset += vp_to_string(buf + buf_offset, buf_size - buf_offset, vp);
	}
	if (buf[buf_offset-1] == ',') buf[buf_offset-1]=0;
	buf[buf_offset] = 0;
	if (buf[0]) {
		len = str_format(out, outlen, "\"%s\":{%s},", key, buf);
	}

	return len;
}

int log_add_json_clt_addrs(char *out, int outlen, const char *key, RADIUS_PACKET *packet) {
	int len = 0;

	len += str_format(out + len, outlen - len, "\"%s\":\"", key);

	// Source IP address
	if (*((uint32_t*)&packet->src_ipaddr.ipaddr) != INADDR_ANY) {
		inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 out + len, outlen - len);
		len = strlen(out);
		len += str_format(out + len, outlen - len, ":%d", packet->src_port);
	} else if (*((uint32_t*)&packet->dst_ipaddr.ipaddr) != INADDR_ANY) {
		inet_ntop(packet->dst_ipaddr.af,
				 &packet->dst_ipaddr.ipaddr,
				 out + len, outlen - len);
		len = strlen(out);
		len += str_format(out + len, outlen - len, ":%d", packet->dst_port);
	}
	len += close_str(out + len, outlen - len);

	return len;
}

int log_add_json_port_addrs(char *out, int outlen, const char *key, REQUEST *request) {
	int len = 0;
	RADIUS_PACKET *packet;

	packet = request->packet;

	len += str_format(out + len, outlen - len, "\"%s\":\"", key);

	// Source IP address
	if (packet && *((uint32_t*)&packet->src_ipaddr.ipaddr) == INADDR_ANY) {
		if (packet->src_port == 0) {
			// can be in proxy or tunneld case 
			len += str_format(out + len, outlen - len, "%s", request->client_shortname);
		}
		else {
			len += str_format(out + len, outlen - len, "%d", packet->src_port);
		}
	} else if (request && *((uint32_t*)&packet->dst_ipaddr.ipaddr) == INADDR_ANY) {
		if (packet->dst_port == 0) {
			// can be in proxy or tunneld case 
			len += str_format(out + len, outlen - len, "%s", request->client_shortname);
		}
		else {
			len += str_format(out + len, outlen - len, "%d", packet->dst_port);
		}
	}
	else if (request->client) {
		len += str_format(out + len, outlen - len, "%s", request->client_shortname);
	}

	len += close_str(out + len, outlen - len);

	return len;
}

int vp_to_string(char *out, int outlen, VALUE_PAIR *vp) {
	int len = 0;
	char namebuf[128];
	char valuebuf[256];
	memset(namebuf, 0, sizeof(namebuf));
	memset(valuebuf, 0, sizeof(namebuf));

	if (!vp->name || !*vp->name) {
		if (!vp_print_name(namebuf, sizeof(namebuf), vp->attribute)) {
			return 0;
		}
	}
	else {
		memcpy(namebuf, vp->name, strlen(vp->name));
	}
	if(vp->flags.has_tag) {
		int buf_size = strlen(namebuf);
		str_format(namebuf + buf_size, sizeof(namebuf) - buf_size, ":%d", vp->flags.tag);
	}

	if (!vp_prints_value(valuebuf, sizeof(valuebuf), vp, 0)) {
		return 0;
	}

	len += log_add_json_string(out + len, outlen - len, namebuf, valuebuf);

	return len;
}

int request_struct_to_string(char *out, int outlen, REQUEST *request, char *msg, int full_info, int reply) {
	int len = 0;
	RADIUS_PACKET *packet = NULL;

	if (outlen - len > 0) out[len++] = '{';

	// print direction
	len += log_add_json_string(out + len, outlen - len, "DIR", reply ? "out" : "in");
	// print msg
	len += log_add_json_string(out + len, outlen - len, "MSG", msg);

	if (request) {
		packet = reply ? request->reply : request->packet;

		// print step
		char *desc = reply ? request->logs->reply_desc : request->logs->request_desc;
		if (desc[0])
			len += log_add_json_string(out + len, outlen - len, "STEP", desc);

		// print packet Type
		if (packet) {
			if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
				len += log_add_json_string(out + len, outlen - len, "TYPE", fr_packet_codes[packet->code]);
			} else {
				len += log_add_json_int(out + len, outlen - len, "TYPE", packet->code);
			}
		}

		// print current module name
		if (full_info && request->logs->eap_type[0])
			len += log_add_json_string(out + len, outlen - len, "MODULE", request->logs->eap_type);

		// print packet number
		if (!reply && request->logs->trips >= 0)
			len += log_add_json_int(out + len, outlen - len, "N", request->logs->trips);


		// print context_id
		len += log_add_json_string(out + len, outlen - len, "CID", request->context_id);
		// print request_id
		len += log_add_json_string(out + len, outlen - len, "RID", request->request_id);
		// print local port
		len += log_add_json_port_addrs(out + len, outlen - len, "PORT", request);

		// Mac inside input attrs
		if (request->packet && request->packet->vps) {
			len += log_add_json_mac(out + len, outlen - len, "MAC", request->packet->vps);
		}

		if (packet) {
			// print address
			len += log_add_json_clt_addrs(out + len, outlen - len, "CLT_ADDRS", packet);

			// print attributes
			if (packet->vps) {
				len += log_add_json_vps(out + len, outlen - len, "ATTRS", packet->vps, full_info || reply);
			}
		}

		// tls state
		if (!reply && 
			(full_info || !desc[0]) && 
			request->logs && request->logs->tls[0])
			len += log_add_json_string(out + len, outlen - len, "TLS", request->logs->tls);

		// common state
		if (!reply && 
			(full_info || !desc[0]) && 
			request->logs && request->logs->flow[0])
			len += log_add_json_string(out + len, outlen - len, "FLOW", request->logs->flow);
	}
	if (out[len-1] == ',') --len;
	if (outlen - len > 0) out[len++] = '}';
	return len;
}

int request_to_string(char *out, int outlen, REQUEST *request, char *msg, int full_info) {
	return request_struct_to_string(out, outlen, request, msg, full_info, 0);
}

int response_to_string(char *out, int outlen, REQUEST *request, char *msg, int full_info) {
	return request_struct_to_string(out, outlen, request, msg, full_info, 1);
}

void log_request(REQUEST *request, int full_info, const char *msg, ...) {
	if (!portnox_config.log.allow_auth_flow_log) {
		return;
	}
	
	char buffer[6144];
	char msg_buffer[256];
	int len = 0;

	// print message
	if (msg) {
		va_list ap;
		va_start(ap, msg);
		len = vstr_format(msg_buffer, sizeof(msg_buffer), msg, ap);
		va_end(ap);
	}
	msg_buffer[len] = 0;

	len = request_to_string(buffer, sizeof(buffer), request, msg_buffer, full_info);
	buffer[len] = 0;

	radlog(L_ERR, buffer);
}

void log_response(REQUEST *request, const char *msg, ...) {
	if (!portnox_config.log.allow_auth_flow_log) {
		return;
	}
	
	char buffer[4096];
	char msg_buffer[64];
	int len = 0;

	// print message
	if (msg) {
		va_list ap;
		va_start(ap, msg);
		len = vstr_format(msg_buffer, sizeof(msg_buffer), msg, ap);
		va_end(ap);
	}
	msg_buffer[len] = 0;

	len = response_to_string(buffer, sizeof(buffer), request, msg_buffer, 0);
	buffer[len] = 0;

	radlog(L_ERR, buffer);
}

void logs_add_flow(REQUEST *request, const char *msg, ...) {
	int len = 0;

	len = strlen(request->logs->flow); 
	if (len > 0) {
		len += str_format(request->logs->flow + len, sizeof(request->logs->flow) - len, "->");
	}
	if (sizeof(request->logs->flow) - len > 0) request->logs->flow[len++] = '[';
	va_list ap;
	va_start(ap, msg);
	len += vstr_format(request->logs->flow + len, sizeof(request->logs->flow) - len, msg, ap);
	va_end(ap);
	if (sizeof(request->logs->flow) - len > 0) request->logs->flow[len++] = ']';

	request->logs->flow[len] = 0;
}

void logs_add_tls(REQUEST *request, const char *msg, ...) {
	int len = 0;

	len = strlen(request->logs->tls); 
	if (len > 0) {
		len += str_format(request->logs->tls + len, sizeof(request->logs->tls) - len, "->");
	}
	if (sizeof(request->logs->tls) - len > 0) request->logs->tls[len++] = '[';
	va_list ap;
	va_start(ap, msg);
	len += vstr_format(request->logs->tls + len, sizeof(request->logs->tls) - len, msg, ap);
	va_end(ap);
	if (sizeof(request->logs->tls) - len > 0) request->logs->tls[len++] = ']';

	request->logs->tls[len] = 0;
}

void logs_set_eaptype(REQUEST *request, const char *msg, ...) {
	int len = 0;

	memset(request->logs->eap_type, 0, sizeof(request->logs->eap_type));
	va_list ap;
	va_start(ap, msg);
	len += vstr_format(request->logs->eap_type, sizeof(request->logs->eap_type), msg, ap);
	va_end(ap);

	request->logs->eap_type[len] = 0;
}

void logs_set_trips(REQUEST *request, int trips) {
	request->logs->trips = trips;
}

void logs_set_request_desc(REQUEST *request, int overwrite, const char *msg, ...) {
	if (!overwrite && request->logs->request_desc[0]) {
		return;
	}

	int len = 0;

	memset(request->logs->request_desc, 0, sizeof(request->logs->request_desc));
	va_list ap;
	va_start(ap, msg);
	len += vstr_format(request->logs->request_desc, sizeof(request->logs->request_desc), msg, ap);
	va_end(ap);

	request->logs->request_desc[len] = 0;
}

void logs_set_reply_desc(REQUEST *request, int overwrite, const char *msg, ...) {
	if (!overwrite && request->logs->reply_desc[0]) {
		return;
	}
	
	int len = 0;

	memset(request->logs->reply_desc, 0, sizeof(request->logs->reply_desc));
	va_list ap;
	va_start(ap, msg);
	len += vstr_format(request->logs->reply_desc, sizeof(request->logs->reply_desc)-1, msg, ap);
	va_end(ap);

	request->logs->reply_desc[len] = 0;
}

void reset_logs(REQUEST *request) {
	memset(request->logs, 0, sizeof(LOG_DESC));
}