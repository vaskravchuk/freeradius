/*
 * log.c	Logging module.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Chad Miller <cmiller@surfsouth.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

extern int allow_portnox_request_log;

void vp_to_string(char *out, size_t outlen, VALUE_PAIR *vp)
{
	size_t		len;
	const char	*name;
	char		namebuf[128];

	out[0] = 0;
	if (!vp) return 0;

	name = vp->name;
	len = 0;

	if (!name || !*name) {
		if (!vp_print_name(namebuf, sizeof(namebuf), vp->attribute)) {
			return 0;
		}
		name = namebuf;
	}

	if( vp->flags.has_tag ) {
		snprintf(out, outlen, "%s:%d:", name, vp->flags.tag);
		len = strlen(out);

	} else {
	    snprintf(out, outlen, "%s:", name);
		len = strlen(out);
	}
	if (outlen - len > 0) out[len++]='\"';
	vp_prints_value(out + len, outlen - len, vp, 0);
	len = strlen(out);
	if (outlen - len > 0) out[len++]='\"';
}

void request_struct_to_string(char *out, size_t outlen, REQUEST *request, int full_info, int reply)
{
	/* 
	 * Remove not interested attributes
	 * skip nt-key as password
	 */
	static char *except_attrs[] = { "EAP-Message", "Message-Authenticator", "Tmp-String-0" };
	static char *except_attrs_size = sizeof(except_attrs) / sizeof(except_attrs[0]);
	size_t len = 0;
	RADIUS_PACKET *packet = NULL;

	packet = reply ? request->reply : request->packet;

	char *desc = reply ? request->logs->reply_desc : request->logs->request_desc;
	if (desc[0]) {
		snprintf(out + len, outlen - len, "STEP:\"%s\" ", desc);
		len = strlen(out);
	}

	// Packet Type
	if (packet) {
		if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
			snprintf(out + len, outlen - len, "TYPE:\"%s\" ", fr_packet_codes[packet->code]);
		} else {
			snprintf(out + len, outlen - len, "TYPE:\"%d\" ", packet->code);
		}
		len = strlen(out);
	}

	if (request->logs->eap_type[0]) {
		snprintf(out + len, outlen - len, "EAP_TYPE:\"%s\" ", request->logs->eap_type);
		len = strlen(out);	
	}

	if (request->logs->trips >= 0) {
		snprintf(out + len, outlen - len, "TRIPS:\"%d\" ", request->logs->trips);
		len = strlen(out);	
	}

	// print context_id
	snprintf(out + len, outlen - len, "CID:\"%s\" ", request->context_id);
	len = strlen(out);

	// print request_id
	snprintf(out + len, outlen - len, "RID:\"%s\" ", request->request_id);
	len = strlen(out);	

	if (packet) {
		// Source IP address
		if (*((uint32_t*)&packet->src_ipaddr.ipaddr) != INADDR_ANY) {
			inet_ntop(packet->src_ipaddr.af,
					 &packet->src_ipaddr.ipaddr,
					 out + len, outlen - len);
			len = strlen(out);
		}
		snprintf(out + len, outlen - len, ":%d", packet->src_port);
		len = strlen(out);
		snprintf(out + len, outlen - len, "->");
		len += 2;

		// Destination IP address
		if (*((uint32_t*)&packet->dst_ipaddr.ipaddr) != INADDR_ANY) {
			inet_ntop(packet->dst_ipaddr.af,
					 &packet->dst_ipaddr.ipaddr,
					 out + len, outlen - len);
			len = strlen(out);
		}
		if (request->packet->dst_port == 0) {
			// can be in proxy or tunneld case 
			snprintf(out + len, outlen - len, ":%s", request->client->shortname);
		}
		else {
			snprintf(out + len, outlen - len, ":%d", packet->dst_port);
		}
		len = strlen(out);

		// print attributes
		if (packet->vps) {
			if (outlen - len > 0) out[len++] = ' ';
			snprintf(out + len, outlen - len, "AVP:[");
			len = strlen(out);
			for (VALUE_PAIR *vp = packet->vps; vp; vp = vp->next) {
				int need_escape = 0;

				// Do not print except_attrs
				if (vp->name && *vp->name) {
					for (int i = 0; i < except_attrs_size; ++i) {
						char* esc_name = except_attrs[i];
						if (strcmp(esc_name, vp->name) == 0) {
							// escaped attr 
							need_escape = 1;
							break;
						}
					}
				}

				if (need_escape) {
					continue;
				}

				// print attribute
				vp_to_string(out + len, outlen - len, vp);
				len = strlen(out);
				if (outlen - len > 0) out[len++] = ' ';
			}
			if (outlen - len > 0) out[len++] = ']';
		}
	}

	// tls state
	if (full_info && request->logs && request->logs->tls[0]) {
		if (outlen - len > 0) out[len++] = ' ';
		snprintf(out + len, outlen - len, "TLS:\"%s\"", request->logs->tls);
		len = strlen(out);
	}	

	// common state
	if (full_info && request->logs && request->logs->flow[0]) {
		if (outlen - len > 0) out[len++] = ' ';
		snprintf(out + len, outlen - len, "FLOW:\"%s\" ", request->logs->flow);
		len = strlen(out);
	}
}

void request_to_string(char *out, size_t outlen, REQUEST *request, int full_info)
{
	request_struct_to_string(out, outlen, request, full_info, 0);
}

void response_to_string(char *out, size_t outlen, REQUEST *request, int full_info) 
{
	request_struct_to_string(out, outlen, request, full_info, 1);
}

void log_request(REQUEST *request, const char *msg, ...)
{
	if (!allow_portnox_request_log) {
		return;
	}
	
	size_t len = 0;
	char buffer[2048];
	memset(buffer, 0, sizeof(buffer));

	// print direction
	snprintf(buffer + len, sizeof(buffer) - len, "[%s] ", "IN");
	len = strlen(buffer);

	// print message
	if (msg) {
		snprintf(buffer + len, sizeof(buffer) - len, "MSG:\"");
		len = strlen(buffer);
		va_list ap;
		va_start(ap, msg);
		vsnprintf(buffer + len, sizeof(buffer) - len, msg, ap);
		va_end(ap);
		len = strlen(buffer);
		if (sizeof(buffer) - len > 0) buffer[len++] = '\"';
	}

	if (request) {
		if (sizeof(buffer) - len > 0) buffer[len++] = ' ';
		request_to_string(buffer + len, sizeof(buffer) - len, request, 1);
	}

	radlog(L_ERR, buffer);
}

void log_response(REQUEST *request, const char *msg, ...)
{
	if (!allow_portnox_request_log) {
		return;
	}
	
	size_t len = 0;
	char buffer[2048];
	memset(buffer, 0, sizeof(buffer));

	// print direction
	snprintf(buffer + len, sizeof(buffer) - len, "[%s] ", "OUT");
	len = strlen(buffer);

	// print message
	if (msg) {
		snprintf(buffer + len, sizeof(buffer) - len, "MSG:\"");
		len = strlen(buffer);
		va_list ap;
		va_start(ap, msg);
		vsnprintf(buffer + len, sizeof(buffer) - len, msg, ap);
		va_end(ap);
		len = strlen(buffer);
		if (sizeof(buffer) - len > 0) buffer[len++] = '\"';
	}

	if (request) {
		if (sizeof(buffer) - len > 0) buffer[len++] = ' ';
		response_to_string(buffer + len, sizeof(buffer) - len, request, 0);
	}

	radlog(L_ERR, buffer);
}

void logs_add_flow(REQUEST *request, const char *msg, ...) 
{
	size_t len;

	len = strlen(request->logs->flow); 
	if (len > 0) {
		snprintf(request->logs->flow + len, sizeof(request->logs->flow) - len, "->");
		len += 2;
	}
	if (sizeof(request->logs->flow) - len > 0) request->logs->flow[len++] = '[';
	va_list ap;
	va_start(ap, msg);
	vsnprintf(request->logs->flow + len, sizeof(request->logs->flow) - len, msg, ap);
	va_end(ap);
	len = strlen(request->logs->flow);
	if (sizeof(request->logs->flow) - len > 0) request->logs->flow[len++] = ']';

	request->logs->flow[len] = 0;
}

void logs_add_tls(REQUEST *request, const char *msg, ...) 
{
	size_t len;

	len = strlen(request->logs->tls); 
	if (len > 0) {
		snprintf(request->logs->tls + len, sizeof(request->logs->tls) - len, "->");
		len += 2;
	}
	if (sizeof(request->logs->tls) - len > 0) request->logs->tls[len++] = '[';
	va_list ap;
	va_start(ap, msg);
	vsnprintf(request->logs->tls + len, sizeof(request->logs->tls) - len, msg, ap);
	va_end(ap);
	len = strlen(request->logs->tls);
	if (sizeof(request->logs->tls) - len > 0) request->logs->tls[len++] = ']';

	request->logs->tls[len] = 0;
}

void logs_set_eaptype(REQUEST *request, const char *msg, ...) 
{
	size_t len;

	memset(request->logs->eap_type, 0, sizeof(request->logs->eap_type));
	va_list ap;
	va_start(ap, msg);
	vsnprintf(request->logs->eap_type, sizeof(request->logs->eap_type), msg, ap);
	va_end(ap);
	len = strlen(request->logs->eap_type);

	request->logs->eap_type[len] = 0;
}

void logs_set_trips(REQUEST *request, int trips) 
{
	request->logs->trips = trips;
}

void logs_set_request_desc(REQUEST *request, int overwrite, const char *msg, ...) 
{
	if (!overwrite && request->logs->request_desc[0]) {
		return;
	}

	size_t len;

	memset(request->logs->request_desc, 0, sizeof(request->logs->request_desc));
	va_list ap;
	va_start(ap, msg);
	vsnprintf(request->logs->request_desc, sizeof(request->logs->request_desc), msg, ap);
	va_end(ap);
	len = strlen(request->logs->request_desc);

	request->logs->request_desc[len] = 0;
}

void logs_set_reply_desc(REQUEST *request, int overwrite, const char *msg, ...) 
{
	if (!overwrite && request->logs->reply_desc[0]) {
		return;
	}
	
	size_t len;

	memset(request->logs->reply_desc, 0, sizeof(request->logs->reply_desc));
	va_list ap;
	va_start(ap, msg);
	vsnprintf(request->logs->reply_desc, sizeof(request->logs->reply_desc), msg, ap);
	va_end(ap);
	len = strlen(request->logs->reply_desc);

	request->logs->reply_desc[len] = 0;
}

void reset_logs(REQUEST *request) 
{
	memset(request->logs, 0, sizeof(LOG_DESC));
}