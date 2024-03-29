/*
 * cb.c
 *
 * Version:     $Id$
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "eap_tls.h"
#include <freeradius-devel/portnox/string_helper.h>

#ifndef NO_OPENSSL

void ssl_error_to_error_id(char *ssl_error, char *error_id, size_t err_len) {
    if (!ssl_error) {
        return;
    }
    int len;
    int id = 60060;
    int offset = 0;

    if (strcmp(ssl_error, "UM") == 0) {
        offset = 0;
    } else if (strcmp(ssl_error, "BM") == 0) {
        offset = 1;
    } else if (strcmp(ssl_error, "DF") == 0) {
        offset = 2;
    } else if (strcmp(ssl_error, "HF") == 0) {
        offset = 3;
    } else if (strcmp(ssl_error, "NC") == 0) {
        offset = 4;
    } else if (strcmp(ssl_error, "BC") == 0) {
        offset = 5;
    } else if (strcmp(ssl_error, "UC") == 0) {
        offset = 6;
    } else if (strcmp(ssl_error, "CR") == 0) {
        offset = 7;
    } else if (strcmp(ssl_error, "CE") == 0) {
        offset = 8;
    } else if (strcmp(ssl_error, "CU") == 0) {
        offset = 9;
    } else if (strcmp(ssl_error, "IP") == 0) {
        offset = 10;
    } else if (strcmp(ssl_error, "DC") == 0) {
        offset = 11;
    } else if (strcmp(ssl_error, "RO") == 0) {
        offset = 12;
    } else if (strcmp(ssl_error, "CA") == 0) {
        offset = 13;
    } else if (strcmp(ssl_error, "AD") == 0) {
        offset = 14;
    } else if (strcmp(ssl_error, "DE") == 0) {
        offset = 15;
    } else if (strcmp(ssl_error, "CY") == 0) {
        offset = 16;
    } else if (strcmp(ssl_error, "ER") == 0) {
        offset = 17;
    } else if (strcmp(ssl_error, "PV") == 0) {
        offset = 18;
    } else if (strcmp(ssl_error, "IS") == 0) {
        offset = 19;
    } else if (strcmp(ssl_error, "IE") == 0) {
        offset = 20;
    } else if (strcmp(ssl_error, "US") == 0) {
        offset = 21;
    } else if (strcmp(ssl_error, "NR") == 0) {
        offset = 22;
    } else if (strcmp(ssl_error, "UP") == 0) {
        offset = 23;
    } else if (strcmp(ssl_error, "UK") == 0) {
        offset = 24;
    } else {
        id = 60030;
    }

    len = snprintf(error_id, err_len, "%d", id + offset);
	len = MIN(len, err_len - 1) < 0 ? 0 : len;
    
    error_id[len] = 0;
}

void handler_set_ssl_error(EAP_HANDLER *handler, char *error, char *description) {
	if (!error && !description) {
		return;
	}
	char error_id[7] = {0};

	ssl_error_to_error_id(error, error_id, sizeof(error_id));

	/*memcpy(handler->ssl_error, error_id, sizeof(error_id));
	memcpy(handler->ssl_error_desc, description, sizeof(description));*/

	/*snprintf(handler->ssl_error, sizeof(error_id), "%s", error_id);
	snprintf(handler->ssl_error_desc, sizeof(handler->ssl_error_desc), "%s", description);*/

	int len_error = str_format(handler->ssl_error, sizeof(handler->ssl_error), "%s", error_id);
	int len_desc = str_format(handler->ssl_error_desc, sizeof(handler->ssl_error_desc), "%s", description);

	handler->ssl_error[len_error] = 0;
	handler->ssl_error_desc[len_desc] = 0;
}

void cbtls_info(const SSL *s, int where, int ret)
{
	const char *str, *state;
	char *alert_desc;
	int w;
	EAP_HANDLER *handler = (EAP_HANDLER *)SSL_get_ex_data(s, 0);
	REQUEST *request = NULL;
	char buffer[1024];

	if (handler) request = handler->request;

	w = where & ~SSL_ST_MASK;
	if (w & SSL_ST_CONNECT) str="TLS_connect";
	else if (w & SSL_ST_ACCEPT) str="TLS_accept";
	else str="(other)";

	state = SSL_state_string_long(s);
	state = state ? state : "NULL";
	buffer[0] = '\0';

	if (where & SSL_CB_LOOP) {
		if (handler) logs_add_tls(handler->request, "%s: %s", str, state);
		RDEBUG2("    %s: %s", str, state);
	} else if (where & SSL_CB_HANDSHAKE_START) {
		if (handler) logs_add_tls(handler->request, "%s: %s", str, state);
		RDEBUG2("    %s: %s", str, state);
	} else if (where & SSL_CB_HANDSHAKE_DONE) {
		if (handler) logs_add_tls(handler->request, "%s: %s", str, state);
		RDEBUG2("    %s: %s", str, state);
	} else if (where & SSL_CB_ALERT) {
		str=(where & SSL_CB_READ)?"read":"write";

		alert_desc = SSL_alert_desc_string_long(ret);

		snprintf(buffer, sizeof(buffer), "TLS Alert %s:%s:%s",
			 str,
			 SSL_alert_type_string_long(ret),
			 alert_desc);

			handler_set_ssl_error(handler, SSL_alert_desc_string(ret), alert_desc);
	} else if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			snprintf(buffer, sizeof(buffer), "%s: failed in %s",
				 str, state);

		} else if (ret < 0) {
			if (SSL_want_read(s)) {
				if (handler) logs_add_tls(handler->request, "%s: Need to read more data: %s", str, state);
				RDEBUG2("%s: Need to read more data: %s",
				       str, state);
			} else {
				snprintf(buffer, sizeof(buffer),
					 "%s: error in %s", str, state);
			}
		}
	}

	if (buffer[0]) {
		if (handler) logs_add_tls(handler->request, "%s", buffer);
		radlog(L_DBG, "%s", buffer);
		
		if (request) {
			VALUE_PAIR *vp;
			
			vp = pairmake("Module-Failure-Message", buffer, T_OP_ADD);
			if (vp) pairadd(&request->packet->vps, vp);
		}
	}
}

/*
 *	Fill in our 'info' with TLS data.
 */
void cbtls_msg(int write_p, int msg_version, int content_type,
	       const void *buf, size_t len,
	       SSL *ssl UNUSED, void *arg)
{
	tls_session_t *state = (tls_session_t *)arg;

	/*
	 *	Work around bug #298, where we may be called with a NULL
	 *	argument.  We should really log a serious error
	 */
	if (!arg) return;

	state->info.origin = (unsigned char)write_p;
	state->info.content_type = (unsigned char)content_type;
	state->info.record_len = len;
	state->info.version = msg_version;
	state->info.initialized = 1;

	if (content_type == SSL3_RT_ALERT) {
		state->info.alert_level = ((const unsigned char*)buf)[0];
		state->info.alert_description = ((const unsigned char*)buf)[1];
		state->info.handshake_type = 0x00;

	} else if (content_type == SSL3_RT_HANDSHAKE) {
		state->info.handshake_type = ((const unsigned char*)buf)[0];
		state->info.alert_level = 0x00;
		state->info.alert_description = 0x00;

#ifdef SSL3_RT_HEARTBEAT
	} else if (content_type == TLS1_RT_HEARTBEAT) {
		uint8_t *p = buf;

		if ((len >= 3) && (p[0] == 1)) {
			size_t payload_len;

			payload_len = (p[1] << 8) | p[2];

			if ((payload_len + 3) > len) {
				state->invalid_hb_used = TRUE;
				ERROR("OpenSSL Heartbeat attack detected.  Closing connection");
				return;
			}
		}
#endif
	}

	tls_session_information(state);
}

int cbtls_password(char *buf,
		   int num UNUSED,
		   int rwflag UNUSED,
		   void *userdata)
{
	strcpy(buf, (char *)userdata);
	return(strlen((char *)userdata));
}

/*
 *	For callbacks
 */
int eaptls_handle_idx = -1;
int eaptls_conf_idx = -1;
int eaptls_store_idx = -1; /* OCSP Store */
int eaptls_session_idx = -1;

#endif /* !defined(NO_OPENSSL) */
