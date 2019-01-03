/*
 * eap_tls.c
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
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */

/*
 *
 *  TLS Packet Format in EAP
 *  --- ------ ------ -- ---
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |   Identifier  |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Flags     |      TLS Message Length
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     TLS Message Length        |       TLS Data...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <assert.h>
#include "eap_tls.h"
#include "rlm_eap.h"

/*
 *      Allocate a new TLS_PACKET
 */
EAPTLS_PACKET *eaptls_alloc(void)
{
	EAPTLS_PACKET   *rp;

	if ((rp = malloc(sizeof(EAPTLS_PACKET))) == NULL) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return NULL;
	}
	memset(rp, 0, sizeof(EAPTLS_PACKET));
	return rp;
}

/*
 *      Free EAPTLS_PACKET
 */
void eaptls_free(EAPTLS_PACKET **eaptls_packet_ptr)
{
	EAPTLS_PACKET *eaptls_packet;

	if (!eaptls_packet_ptr) return;
	eaptls_packet = *eaptls_packet_ptr;
	if (eaptls_packet == NULL) return;

	if (eaptls_packet->data) {
		free(eaptls_packet->data);
		eaptls_packet->data = NULL;
	}

	free(eaptls_packet);
	*eaptls_packet_ptr = NULL;
}

/*
   The S flag is set only within the EAP-TLS start message
   sent from the EAP server to the peer.
*/
int eaptls_start(EAP_HANDLER *handler, int peap_flag)
{
	EAPTLS_PACKET 	reply;
	EAP_DS 			*eap_ds;

	eap_ds = handler->eap_ds;

	reply.code = EAPTLS_START;
	reply.length = TLS_HEADER_LEN + 1/*flags*/;

	reply.flags = peap_flag;
	reply.flags = SET_START(reply.flags);

	reply.data = NULL;
	reply.dlen = 0;

	eaptls_compose(eap_ds, &reply);

	return 1;
}

int eaptls_success(EAP_HANDLER *handler, int peap_flag)
{
	EAPTLS_PACKET	reply;
	VALUE_PAIR *vp, *vps = NULL;
	VALUE_PAIR **output_pairs = NULL;
	REQUEST *request = handler->request;
	tls_session_t *tls_session = handler->opaque;

	handler->finished = TRUE;
	reply.code = EAPTLS_SUCCESS;
	reply.length = TLS_HEADER_LEN;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;
	logs_add_flow(handler->request, "eaptls_success");

	/*
	 *	If there's no session resumption, delete the entry
	 *	from the cache.  This means either it's disabled
	 *	globally for this SSL context, OR we were told to
	 *	disable it for this user.
	 *
	 *	This also means you can't turn it on just for one
	 *	user.
	 */
	if ((!tls_session->allow_session_resumption) ||
	    (((vp = pairfind(request->config_items, 1127)) != NULL) &&
	     (vp->vp_integer == 0))) {
		SSL_CTX_remove_session(tls_session->ctx,
				       tls_session->ssl->session);
		tls_session->allow_session_resumption = 0;

		/*
		 *	If we're in a resumed session and it's
		 *	not allowed, 
		 */
		if (SSL_session_reused(tls_session->ssl)) {
			logs_add_flow(handler->request, "EAPTLS_SUCCESS FAILED (FAIL: Forcibly stopping session resumption as it is not allowed)");
			RDEBUG("FAIL: Forcibly stopping session resumption as it is not allowed.");
			return eaptls_fail(handler, peap_flag);
		}
		
		/*
		 *	Else resumption IS allowed, so we store the
		 *	user data in the cache.
		 */
	} else if (!SSL_session_reused(tls_session->ssl)) {
		RDEBUG2("Saving response in the cache");
		
		vp = paircopy2(request->reply->vps, PW_USER_NAME);
		if (vp) pairadd(&vps, vp);
		
		vp = paircopy2(request->packet->vps, PW_STRIPPED_USER_NAME);
		if (vp) pairadd(&vps, vp);

		vp = paircopy2(request->reply->vps, PW_CHARGEABLE_USER_IDENTITY);
		if (vp) pairadd(&vps, vp);
		
		vp = paircopy2(request->reply->vps, PW_CACHED_SESSION_POLICY);
		if (vp) pairadd(&vps, vp);

		if (handler->certs) {
			pairadd(&vps, paircopy(handler->certs));

			pairadd(&request->packet->vps, paircopy(handler->certs));
		}

		if (vps) {
			SSL_SESSION_set_ex_data(tls_session->ssl->session,
						eaptls_session_idx, vps);
		} else {
			RDEBUG2("WARNING: No information to cache: session caching will be disabled for this session.");
			SSL_CTX_remove_session(tls_session->ctx,
					       tls_session->ssl->session);
		}

		/*
		 *	Else the session WAS allowed.  Copy the cached
		 *	reply.
		 */
	} else {
	       
		vps = SSL_SESSION_get_ex_data(tls_session->ssl->session,
					     eaptls_session_idx);
		if (!vps) {
			RDEBUG("WARNING: No information in cached session!");
			return eaptls_fail(handler, peap_flag);
		} else {
			RDEBUG("Adding cached attributes:");
			debug_pair_list(vps);

			for (vp = vps; vp != NULL; vp = vp->next) {
				/*
				 *	TLS-* attrs get added back to
				 *	the request list.
				 */
				if ((vp->attribute >= 1910) &&
				    (vp->attribute < 1929)) {
					pairadd(&request->packet->vps,
						paircopyvp(vp));
				} else {
					pairadd(&request->reply->vps,
						paircopyvp(vp));
				}
			}

			/*
			 *	Mark the request as resumed.
			 */
			vp = pairmake("EAP-Session-Resumed", "1", T_OP_SET);
			if (vp) pairadd(&request->packet->vps, vp);
		}
	}

	/*
	 *	Call compose AFTER checking for cached data.
	 */
	eaptls_compose(handler->eap_ds, &reply);

	/*
	 *	Automatically generate MPPE keying material.
	 */
	if (tls_session->prf_label) {
		eaptls_gen_mppe_keys(&handler->request->reply->vps,
				     tls_session->ssl, tls_session->prf_label);
	} else {
		RDEBUG("WARNING: Not adding MPPE keys because there is no PRF label");
	}

	eaptls_gen_eap_key(tls_session->ssl,
			   handler->eap_type, &handler->request->reply->vps);

	if (tls_session->output_pairs)
	{
		if (request->reply != NULL) {
			output_pairs = &request->reply->vps;
			if (output_pairs != NULL) {
				RDEBUG("rlm_eap_tls: Moving script value pairs to the reply");
				pairmove(output_pairs, &(tls_session->output_pairs));
			}
			else {
				RDEBUG("rlm_eap_tls: output_pairs==NULL");
			}
		}
		else {
			RDEBUG("rlm_eap_tls: request->reply==NULL");
		}
	}
	else {
		RDEBUG("rlm_eap_tls: tls_session->output_pairs==NULL");
	}

	logs_set_reply_desc(handler->request, 0, "TLS SUCCESS");

	return 1;
}

int eaptls_fail(EAP_HANDLER *handler, int peap_flag)
{
	EAPTLS_PACKET	reply;
	tls_session_t *tls_session = handler->opaque;

	handler->finished = TRUE;
	reply.code = EAPTLS_FAIL;
	reply.length = TLS_HEADER_LEN;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	logs_add_flow(handler->request, "eaptls_fail");

	/*
	 *	Force the session to NOT be cached.
	 */
	SSL_CTX_remove_session(tls_session->ctx, tls_session->ssl->session);

	eaptls_compose(handler->eap_ds, &reply);

	logs_set_reply_desc(handler->request, 0, "TLS FAILED");

	return 1;
}

/*
   A single TLS record may be up to 16384 octets in length, but a TLS
   message may span multiple TLS records, and a TLS certificate message
   may in principle be as long as 16MB.
*/

/*
 *	Frame the Dirty data that needs to be send to the client in an
 *	EAP-Request.  We always embed the TLS-length in all EAP-TLS
 *	packets that we send, for easy reference purpose.  Handle
 *	fragmentation and sending the next fragment etc.
 */
int eaptls_request(EAP_HANDLER *handler, tls_session_t *ssn)
{
	EAPTLS_PACKET	reply;
	unsigned int	size;
	unsigned int 	nlen;
	unsigned int 	lbit = 0;
	EAP_DS 			*eap_ds;

	eap_ds = handler->eap_ds;

	/* This value determines whether we set (L)ength flag for
		EVERY packet we send and add corresponding
		"TLS Message Length" field.

	length_flag = TRUE;
		This means we include L flag and "TLS Msg Len" in EVERY
		packet we send out.

	length_flag = FALSE;
		This means we include L flag and "TLS Msg Len" **ONLY**
		in First packet of a fragment series. We do not use
		it anywhere else.

		Having L flag in every packet is prefered.

	*/
	if (ssn->length_flag) {
		lbit = 4;
	}
	if (ssn->fragment == 0) {
		ssn->tls_msg_len = ssn->dirty_out.used;
	}

	reply.code = EAPTLS_REQUEST;
	reply.flags = ssn->peap_flag;

	/* Send data, NOT more than the FRAGMENT size */
	if (ssn->dirty_out.used > ssn->offset) {
		size = ssn->offset;
		reply.flags = SET_MORE_FRAGMENTS(reply.flags);
		/* Length MUST be included if it is the First Fragment */
		if (ssn->fragment == 0) {
			lbit = 4;
		}
		ssn->fragment = 1;
	} else {
		size = ssn->dirty_out.used;
		ssn->fragment = 0;
	}

	reply.dlen = lbit + size;
	reply.length = TLS_HEADER_LEN + 1/*flags*/ + reply.dlen;

	reply.data = malloc(reply.dlen);
	if (lbit) {
		nlen = htonl(ssn->tls_msg_len);
		memcpy(reply.data, &nlen, lbit);
		reply.flags = SET_LENGTH_INCLUDED(reply.flags);
	}
	(ssn->record_minus)(&ssn->dirty_out, reply.data + lbit, size);

	eaptls_compose(eap_ds, &reply);
	free(reply.data);
	reply.data = NULL;

	return 1;
}

/*
 * Acknowledge received is for one of the following messages sent earlier
 * 1. Handshake completed Message, so now send, EAP-Success
 * 2. Alert Message, now send, EAP-Failure
 * 3. Fragment Message, now send, next Fragment
 */
static eaptls_status_t eaptls_ack_handler(EAP_HANDLER *handler)
{
	logs_add_flow(handler->request, "eaptls_ack_handler");
	tls_session_t *tls_session;
	REQUEST *request = handler->request;

	tls_session = (tls_session_t *)handler->opaque;
	if (tls_session == NULL){
		logs_add_flow(handler->request, "EAPTLS_ACK_HANDLER FAILED (FAIL: Unexpected ACK received.  Could not obtain session information)");
		radlog_request(L_ERR, 0, request, "FAIL: Unexpected ACK received.  Could not obtain session information.");
		return EAPTLS_FAIL;
	}
	if (tls_session->info.initialized == 0) {
		logs_add_flow(handler->request, "No SSL info available. Waiting for more SSL data");
		RDEBUG("No SSL info available. Waiting for more SSL data.");
		return EAPTLS_REQUEST;
	}
	if ((tls_session->info.content_type == handshake) &&
	    (tls_session->info.origin == 0)) {
		logs_add_flow(handler->request, "FAIL: ACK without earlier message");
		radlog_request(L_ERR, 0, request, "FAIL: ACK without earlier message.");
		return EAPTLS_FAIL;
	}

	logs_add_flow(handler->request, "tls fragment dirty_out.used:%d", tls_session->dirty_out.used);

	switch (tls_session->info.content_type) {
	case alert:
		logs_add_flow(handler->request, "EAPTLS_ACK_HANDLER FAILED (ACK alert)");
		RDEBUG2("ACK alert");
		eaptls_fail(handler, tls_session->peap_flag);
		return EAPTLS_FAIL;

	case handshake:
		if ((tls_session->info.handshake_type == finished) &&
		    (tls_session->dirty_out.used == 0)) {
			logs_add_flow(handler->request, "ACK handshake is finished");
			RDEBUG2("ACK handshake is finished");

			/* 
			 *	From now on all the content is
			 *	application data set it here as nobody else
			 *	sets it.
			 */
			tls_session->info.content_type = application_data;
			logs_set_request_desc(handler->request, 1, "TLS HANDSHAKE ACK SUCCESS");
			return EAPTLS_SUCCESS;
		} /* else more data to send */

		logs_add_flow(handler->request, "ACK handshake fragment handler");
		RDEBUG2("ACK handshake fragment handler");
		logs_set_reply_desc(handler->request, 1, "TLS HANDSHAKE SERVER FRAGMENT");
		/* Fragmentation handler, send next fragment */
		return EAPTLS_REQUEST;

	case application_data:
		logs_add_flow(handler->request, "ACK handshake fragment handler in application data");
		RDEBUG2("ACK handshake fragment handler in application data");
		return EAPTLS_REQUEST;
						
		/*
		 *	For the rest of the conditions, switch over
		 *	to the default section below.
		 */
	default:
		RDEBUG2("ACK default");
		logs_add_flow(handler->request, "EAPTLS_ACK_HANDLER FAILED (Invalid ACK received)");
		radlog_request(L_ERR, 0, request, "Invalid ACK received: %d",
		       tls_session->info.content_type);
		return EAPTLS_FAIL;
	}
}

/*
 *	Similarly, when the EAP server receives an EAP-Response with
 *	the M bit set, it MUST respond with an EAP-Request with
 *	EAP-Type=EAP-TLS and no data. This serves as a fragment ACK.
 *
 *	In order to prevent errors in the processing of fragments, the
 *	EAP server MUST use increment the Identifier value for each
 *	fragment ACK contained within an EAP-Request, and the peer
 *	MUST include this Identifier value in the subsequent fragment
 *	contained within an EAP- Reponse.
 *
 *	EAP server sends an ACK when it determines there are More
 *	fragments to receive to make the complete
 *	TLS-record/TLS-Message
 */
static int eaptls_send_ack(EAP_HANDLER *handler, int peap_flag)
{
	EAPTLS_PACKET 	reply;
	EAP_DS *eap_ds;

	eap_ds = handler->eap_ds;

	reply.code = EAPTLS_ACK;
	reply.length = TLS_HEADER_LEN + 1/*flags*/;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	eaptls_compose(eap_ds, &reply);
	logs_set_reply_desc(handler->request, 1, "TLS ACK");

	return 1;
}

/*
 *	The S flag is set only within the EAP-TLS start message sent
 *	from the EAP server to the peer.
 *
 *	Similarly, when the EAP server receives an EAP-Response with
 *	the M bit set, it MUST respond with an EAP-Request with
 *	EAP-Type=EAP-TLS and no data. This serves as a fragment
 *	ACK. The EAP peer MUST wait.
 */
static eaptls_status_t eaptls_verify(EAP_HANDLER *handler)
{
	EAP_DS *eap_ds = handler->eap_ds;
	EAP_DS *prev_eap_ds = handler->prev_eapds;
	eaptls_packet_t	*eaptls_packet, *eaptls_prev = NULL;
	REQUEST *request = handler->request;

	logs_add_flow(handler->request, "eaptls_verify");

	/*
	 *	We don't check ANY of the input parameters.  It's all
	 *	code which works together, so if something is wrong,
	 *	we SHOULD core dump.
	 *
	 *	e.g. if eap_ds is NULL, of if eap_ds->response is
	 *	NULL, of if it's NOT an EAP-Response, or if the packet
	 *	is too short.  See eap_validation()., in ../../eap.c
	 *
	 *	Also, eaptype_select() takes care of selecting the
	 *	appropriate type, so we don't need to check
	 *	eap_ds->response->type.type == PW_EAP_TLS, or anything
	 *	else.
	 */
	eaptls_packet = (eaptls_packet_t *)eap_ds->response->type.data;
	if (prev_eap_ds && prev_eap_ds->response)
		eaptls_prev = (eaptls_packet_t *)prev_eap_ds->response->type.data;

	/*
	 *	check for ACK
	 *
	 *	If there's no TLS data, or there's 1 byte of TLS data,
	 *	with the flags set to zero, then it's an ACK.
	 *
	 *	Find if this is a reply to the previous request sent
	 */
	if ((eaptls_packet == NULL) ||
	    ((eap_ds->response->length == EAP_HEADER_LEN + 2) &&
	     ((eaptls_packet->flags & 0xc0) == 0x00))) {

#if 0
		/*
		 *	Un-comment this for TLS inside of TTLS/PEAP
		 */
		RDEBUG2("Received EAP-TLS ACK message");
		return eaptls_ack_handler(handler);
#else
		logs_set_request_desc(handler->request, 1, "TLS ACK");
		if (prev_eap_ds &&
		    (prev_eap_ds->request->id == eap_ds->response->id)) {
			/*
			 *	Run the ACK handler directly from here.
			 */
			logs_add_flow(handler->request, "Received TLS ACK");
			RDEBUG2("Received TLS ACK");
			return eaptls_ack_handler(handler);
		} else {
			logs_add_flow(handler->request, "EAPTLS_VERIFY FAILED (Received Invalid TLS ACK)");
			radlog_request(L_ERR, 0, request, "Received Invalid TLS ACK");
			return EAPTLS_INVALID;
		}
#endif
	}

	/*
	 *	We send TLS_START, but do not receive it.
	 */
	if (TLS_START(eaptls_packet->flags)) {
		logs_add_flow(handler->request, "Received unexpected EAP-TLS Start message");
		RDEBUG("Received unexpected EAP-TLS Start message");
		return EAPTLS_INVALID;
	}

	/*
	 *	The L bit (length included) is set to indicate the
	 *	presence of the four octet TLS Message Length field,
	 *	and MUST be set for the first fragment of a fragmented
	 *	TLS message or set of messages.
	 *
	 *	The M bit (more fragments) is set on all but the last
	 *	fragment.
	 *
	 *	The S bit (EAP-TLS start) is set in an EAP-TLS Start
	 *	message. This differentiates the EAP-TLS Start message
	 *	from a fragment acknowledgement.
	 */
	if (TLS_LENGTH_INCLUDED(eaptls_packet->flags)) {
		DEBUG2("  TLS Length %d",
		       eaptls_packet->data[2] * 256 | eaptls_packet->data[3]);
		if (TLS_MORE_FRAGMENTS(eaptls_packet->flags)) {
			/*
			 * FIRST_FRAGMENT is identified
			 * 1. If there is no previous EAP-response received.
			 * 2. If EAP-response received, then its M bit not set.
			 * 	(It is because Last fragment will not have M bit set)
			 */
			if (!prev_eap_ds ||
			    (prev_eap_ds->response == NULL) ||
			    (eaptls_prev == NULL) ||
			    !TLS_MORE_FRAGMENTS(eaptls_prev->flags)) {

				logs_add_flow(handler->request, "Received EAP-TLS First Fragment of the message");
				RDEBUG2("Received EAP-TLS First Fragment of the message");
				return EAPTLS_FIRST_FRAGMENT;
			} else {
				logs_add_flow(handler->request, "More Fragments with length included");
				RDEBUG2("More Fragments with length included");
				return EAPTLS_MORE_FRAGMENTS_WITH_LENGTH;
			}
		} else {
			logs_add_flow(handler->request, "Length Included");
			RDEBUG2("Length Included");
			return EAPTLS_LENGTH_INCLUDED;
		}
	}

	if (TLS_MORE_FRAGMENTS(eaptls_packet->flags)) {
		logs_add_flow(handler->request, "More fragments to follow");
		RDEBUG2("More fragments to follow");
		return EAPTLS_MORE_FRAGMENTS;
	}

	/*
	 *	None of the flags are set, but it's still a valid
	 *	EAPTLS packet.
	 */
	return EAPTLS_OK;
}

/*
 * EAPTLS_PACKET
 * code   =  EAP-code
 * id     =  EAP-id
 * length = code + id + length + flags + tlsdata
 *        =  1   +  1 +   2    +  1    +  X
 * length = EAP-length - 1(EAP-Type = 1 octet)
 * flags  = EAP-typedata[0] (1 octet)
 * dlen   = EAP-typedata[1-4] (4 octets), if L flag set
 *        = length - 5(code+id+length+flags), otherwise
 * data   = EAP-typedata[5-n], if L flag set
 *        = EAP-typedata[1-n], otherwise
 * packet = EAP-typedata (complete typedata)
 *
 * Points to consider during EAP-TLS data extraction
 * 1. In the received packet, No data will be present incase of ACK-NAK
 * 2. Incase if more fragments need to be received then ACK after retreiving this fragment.
 *
 *  RFC 2716 Section 4.2.  PPP EAP TLS Request Packet
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |   Identifier  |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Flags     |      TLS Message Length
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     TLS Message Length        |       TLS Data...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  The Length field is two octets and indicates the length of the EAP
 *  packet including the Code, Identifir, Length, Type, and TLS data
 *  fields.
 */
static EAPTLS_PACKET *eaptls_extract(EAP_HANDLER *handler, EAP_DS *eap_ds, eaptls_status_t status)
{
	EAPTLS_PACKET	*tlspacket;
	uint32_t	data_len = 0;
	uint32_t	len = 0;
	uint8_t		*data = NULL;
	REQUEST  	*request = NULL;

	request = handler->request;

	if (status  == EAPTLS_INVALID)
		return NULL;

	/*
	 *	The main EAP code & eaptls_verify() take care of
	 *	ensuring that the packet is OK, and that we can
	 *	extract the various fields we want.
	 *
	 *	e.g. a TLS packet with zero data is allowed as an ACK,
	 *	but we will never see it here, as we will simply
	 *	send another fragment, instead of trying to extract
	 *	the data.
	 *
	 *	MUST have TLS type octet, followed by flags, followed
	 *	by data.
	 */
	assert(eap_ds->response->length > 2);

	tlspacket = eaptls_alloc();
	if (tlspacket == NULL) return NULL;

	/*
	 *	Code & id for EAPTLS & EAP are same
	 *	but eaptls_length = eap_length - 1(EAP-Type = 1 octet)
	 *
	 *	length = code + id + length + type + tlsdata
	 *	       =  1   +  1 +   2    +  1    +  X
	 */
	tlspacket->code = eap_ds->response->code;
	tlspacket->id = eap_ds->response->id;
	tlspacket->length = eap_ds->response->length - 1; /* EAP type */
	tlspacket->flags = eap_ds->response->type.data[0];

	/*
	 *	A quick sanity check of the flags.  If we've been told
	 *	that there's a length, and there isn't one, then stop.
	 */
	if (TLS_LENGTH_INCLUDED(tlspacket->flags) &&
	    (tlspacket->length < 5)) { /* flags + TLS message length */
		RDEBUG("Invalid EAP-TLS packet received.  (Length bit is set, but no length was found.)");
		eaptls_free(&tlspacket);
		logs_add_flow(handler->request, "EAPTLS FAILED LBIT_WITHOUT_LENGTH");
		return NULL;
	}

	/*
	 *	If the final TLS packet is larger than we can handle, die
	 *	now.
	 *
	 *	Likewise, if the EAP packet says N bytes, and the TLS
	 *	packet says there's fewer bytes, it's a problem.
	 *
	 *	FIXME: Try to ensure that the claimed length is
	 *	consistent across multiple TLS fragments.
	 */
	if (TLS_LENGTH_INCLUDED(tlspacket->flags)) {
		memcpy(&data_len, &eap_ds->response->type.data[1], 4);
		data_len = ntohl(data_len);
		if (data_len > MAX_RECORD_SIZE) {
			RDEBUG("The EAP-TLS packet will contain more data than we can process.");
			eaptls_free(&tlspacket);
			logs_add_flow(handler->request, "EAPTLS FAILED MORE_DATA");
			return NULL;
		}

#if 0
		DEBUG2(" TLS: %d %d\n", data_len, tlspacket->length);

		if (data_len < tlspacket->length) {
			RDEBUG("EAP-TLS packet claims to be smaller than the encapsulating EAP packet.");
			eaptls_free(&tlspacket);
			return NULL;
		}
#endif
	}

	switch (status) {
	/*
	 *	The TLS Message Length field is four octets, and
	 *	provides the total length of the TLS message or set of
	 *	messages that is being fragmented; this simplifies
	 *	buffer allocation.
	 *
	 *	Dynamic allocation of buffers as & when we know the
	 *	length should solve the problem.
	 */
	case EAPTLS_FIRST_FRAGMENT:
	case EAPTLS_LENGTH_INCLUDED:
	case EAPTLS_MORE_FRAGMENTS_WITH_LENGTH:
		if (tlspacket->length < 5) { /* flags + TLS message length */
			RDEBUG("Invalid EAP-TLS packet received.  (Expected length, got none.)");
			eaptls_free(&tlspacket);
			logs_add_flow(handler->request, "EAPTLS FAILED EXCPECTED_LENGTH");
			return NULL;
		}

		/*
		 *	Extract all the TLS fragments from the
		 *	previous eap_ds Start appending this
		 *	fragment to the above ds
		 */
		memcpy(&data_len, &eap_ds->response->type.data[1], sizeof(uint32_t));
		data_len = ntohl(data_len);
		data = (eap_ds->response->type.data + 5/*flags+TLS-Length*/);
		len = eap_ds->response->type.length - 5/*flags+TLS-Length*/;

		/*
		 *	Hmm... this should be an error, too.
		 */
		if (data_len > len) {
			data_len = len;
		}
		break;

		/*
		 *	Data length is implicit, from the EAP header.
		 */
	case EAPTLS_MORE_FRAGMENTS:
	case EAPTLS_OK:
		data_len = eap_ds->response->type.length - 1/*flags*/;
		data = eap_ds->response->type.data + 1/*flags*/;
		break;

	default:
		RDEBUG("Invalid EAP-TLS packet received");
		eaptls_free(&tlspacket);
		logs_add_flow(handler->request, "EAPTLS FAILED INVALID_PACKET");
		return NULL;
	}

	tlspacket->dlen = data_len;
	if (data_len) {
		tlspacket->data = (unsigned char *)malloc(data_len);
		if (tlspacket->data == NULL) {
			RDEBUG("out of memory");
			eaptls_free(&tlspacket);
			return NULL;
		}
		memcpy(tlspacket->data, data, data_len);
	}

	return tlspacket;
}



/*
 * To process the TLS,
 *  INCOMING DATA:
 * 	1. EAP-TLS should get the compelete TLS data from the peer.
 * 	2. Store that data in a data structure with any other required info
 *	3. Handle that data structure to the TLS module.
 *	4. TLS module will perform its operations on the data and
 *	handle back to EAP-TLS
 *
 *  OUTGOING DATA:
 * 	1. EAP-TLS if necessary will fragment it and send it to the
 * 	destination.
 *
 *	During EAP-TLS initialization, TLS Context object will be
 *	initialized and stored.  For every new authentication
 *	requests, TLS will open a new session object and that session
 *	object should be maintained even after the session is
 *	completed for session resumption. (Probably later as a feature
 *	as we donot know who maintains these session objects ie,
 *	SSL_CTX (internally) or TLS module(explicitly). If TLS module,
 *	then how to let SSL API know about these sessions.)
 */
static eaptls_status_t eaptls_operation(eaptls_status_t status,
					EAP_HANDLER *handler)
{
	tls_session_t *tls_session;

	tls_session = (tls_session_t *)handler->opaque;

	logs_add_flow(handler->request, "eaptls_operation");

	if ((status == EAPTLS_MORE_FRAGMENTS) ||
	    (status == EAPTLS_MORE_FRAGMENTS_WITH_LENGTH) ||
	    (status == EAPTLS_FIRST_FRAGMENT)) {
		/*
		 *	Send the ACK.
		 */
		logs_set_request_desc(handler->request, 1, "TLS HANDSHAKE CLIENT INFO FRAGMENT");
		eaptls_send_ack(handler, tls_session->peap_flag);
		return EAPTLS_HANDLED;

	}

	/*
	 *	We have the complete TLS-data or TLS-message.
	 *
	 *	Clean the dirty message.
	 *
	 *	Authenticate the user and send
	 *	Success/Failure.
	 *
	 *	If more info
	 *	is required then send another request.
	 */
	int hs_result = tls_handshake_recv(handler->request, tls_session);

	logs_add_flow(handler->request, "tls_session->info.handshake_type %d", tls_session->info.handshake_type);
	switch (tls_session->info.handshake_type) {
		case client_hello:
		case server_hello_done:
		case certificate_request:
			logs_set_request_desc(handler->request, 1, "TLS HANDSHAKE CLIENT HELLO");
			break;
		default:
			logs_set_request_desc(handler->request, 1, "TLS HANDSHAKE CLIENT INFO");
	}

	if (!hs_result) {
		logs_add_flow(handler->request, "EAPTLS FAILED HANDSHAKE");
		DEBUG2("TLS receive handshake failed during operation");
		SSL_CTX_remove_session(tls_session->ctx, tls_session->ssl->session);
		return EAPTLS_FAIL;
	}
	/*
	 *	FIXME: return success/fail.
	 *
	 *	TLS proper can decide what to do, then.
	 */
	if (tls_session->dirty_out.used > 0) {
		if (tls_session->info.handshake_type == finished) {
			logs_set_reply_desc(handler->request, 1, "TLS HANDSHAKE CIPHER EXCHANGE");
		}
		else {
			logs_set_reply_desc(handler->request, 1, "TLS HANDSHAKE SERVER INFO");
		}
		eaptls_request(handler, tls_session);
		return EAPTLS_HANDLED;
	}
		
	/* 
	 *	If there is no data to send i.e
	 *	dirty_out.used <=0 and if the SSL
	 *	handshake is finished, then return a
	 *	EPTLS_SUCCESS
	 */
	
	if (SSL_is_init_finished(tls_session->ssl)) {
		/*
		 *	Init is finished.  The rest is
		 *	application data.
		 */
		tls_session->info.content_type = application_data; 
		return EAPTLS_SUCCESS;
	}
	
	/*
	 *	Who knows what happened...
	 */
	logs_add_flow(handler->request, "TLS failed during operation");
	DEBUG2("TLS failed during operation");
	return EAPTLS_FAIL;
}


/*
 * In the actual authentication first verify the packet and then create the data structure
 */
/*
 * To process the TLS,
 *  INCOMING DATA:
 * 	1. EAP-TLS should get the compelete TLS data from the peer.
 * 	2. Store that data in a data structure with any other required info
 *	3. Hand this data structure to the TLS module.
 *	4. TLS module will perform its operations on the data and hands back to EAP-TLS
 *  OUTGOING DATA:
 * 	1. EAP-TLS if necessary will fragment it and send it to the destination.
 *
 *	During EAP-TLS initialization, TLS Context object will be
 *	initialized and stored.  For every new authentication
 *	requests, TLS will open a new session object and that
 *	session object SHOULD be maintained even after the session
 *	is completed, for session resumption. (Probably later as a
 *	feature, as we do not know who maintains these session
 *	objects ie, SSL_CTX (internally) or TLS module (explicitly). If
 *	TLS module, then how to let SSL API know about these
 *	sessions.)
 */

/*
 *	Process an EAP request
 */
eaptls_status_t eaptls_process(EAP_HANDLER *handler)
{
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	EAPTLS_PACKET	*tlspacket;
	eaptls_status_t	status;
	REQUEST *request = handler->request;

	logs_add_flow(handler->request, "eaptls_process");

	logs_add_flow(handler->request, "processing EAP-TLS");
	RDEBUG2("processing EAP-TLS");
	if (handler->certs) pairadd(&request->packet->vps,
				    paircopy(handler->certs));

	/* This case is when SSL generates Alert then we
	 * send that alert to the client and then send the EAP-Failure
	 */
	status = eaptls_verify(handler);
	logs_add_flow(handler->request, "eaptls_verify returned %d", status);
	RDEBUG2("eaptls_verify returned %d\n", status);

	switch (status) {
	default:
	case EAPTLS_INVALID:
	case EAPTLS_FAIL:

		/*
		 *	Success means that we're done the initial
		 *	handshake.  For TTLS, this means send stuff
		 *	back to the client, and the client sends us
		 *	more tunneled data.
		 */
	case EAPTLS_SUCCESS:
		return status;
		break;

		/*
		 *	Normal TLS request, continue with the "get rest
		 *	of fragments" phase.
		 */
	case EAPTLS_REQUEST:
		eaptls_request(handler, tls_session);
		return EAPTLS_HANDLED;
		break;

		/*
		 *	The handshake is done, and we're in the "tunnel
		 *	data" phase.
		 */
	case EAPTLS_OK:
		logs_add_flow(handler->request, "Done initial handshake");
		RDEBUG2("Done initial handshake");

		/*
		 *	Get the rest of the fragments.
		 */
	case EAPTLS_FIRST_FRAGMENT:
	case EAPTLS_MORE_FRAGMENTS:
	case EAPTLS_LENGTH_INCLUDED:
	case EAPTLS_MORE_FRAGMENTS_WITH_LENGTH:
		break;
	}

	/*
	 *	Extract the TLS packet from the buffer.
	 */
	if ((tlspacket = eaptls_extract(handler, handler->eap_ds, status)) == NULL)
	{
		logs_add_flow(handler->request, "EAPTLS FAILED EAPTLS_EXTRACT_FAILED");
		return EAPTLS_FAIL;
	}

	/*
	 *	Get the session struct from the handler
	 *
	 *	update the dirty_in buffer
	 *
	 *	NOTE: This buffer will contain partial data when M bit is set.
	 *
	 * 	CAUTION while reinitializing this buffer, it should be
	 * 	reinitialized only when this M bit is NOT set.
	 */
	if (tlspacket->dlen !=
	    (tls_session->record_plus)(&tls_session->dirty_in, tlspacket->data, tlspacket->dlen)) {
		eaptls_free(&tlspacket);
		logs_add_flow(handler->request, "EAPTLS FAILED (Exceeded maximum record size)");
		RDEBUG("Exceeded maximum record size");
		return EAPTLS_FAIL;
	}

	/*
	 *	No longer needed.
	 */
	eaptls_free(&tlspacket);

	/*
	 *	SSL initalization is done.  Return.
	 *
	 *	The TLS data will be in the tls_session structure.
	 */
	if (SSL_is_init_finished(tls_session->ssl)) {
		int err;

		/*
		 *	The initialization may be finished, but if
		 *	there more fragments coming, then send ACK,
		 *	and get the caller to continue the
		 *	conversation.
		 */	
	        if ((status == EAPTLS_MORE_FRAGMENTS) ||
        	    (status == EAPTLS_MORE_FRAGMENTS_WITH_LENGTH) ||
            	    (status == EAPTLS_FIRST_FRAGMENT)) {
			/*
			 *	Send the ACK.
			 */
			eaptls_send_ack(handler,
					tls_session->peap_flag);
			logs_set_request_desc(handler->request, 1, "TLS FRAGMENT");
			logs_add_flow(handler->request, "Init is done, but tunneled data is fragmented");
			RDEBUG2("Init is done, but tunneled data is fragmented");
			return EAPTLS_HANDLED;
		}

		/*	
		 *	Decrypt the complete record.
		 */
		BIO_write(tls_session->into_ssl, tls_session->dirty_in.data,
			  tls_session->dirty_in.used);

		/*
		 *      Clear the dirty buffer now that we are done with it
		 *      and init the clean_out buffer to store decrypted data
		 */
		(tls_session->record_init)(&tls_session->dirty_in);
		(tls_session->record_init)(&tls_session->clean_out);

		/*
		 *      Read (and decrypt) the tunneled data from the
		 *      SSL session, and put it into the decrypted
		 *      data buffer.
		 */
		err = SSL_read(tls_session->ssl, tls_session->clean_out.data,
			       sizeof(tls_session->clean_out.data));

		if (err < 0) {
			RDEBUG("SSL_read Error");

			switch (SSL_get_error(tls_session->ssl, err)) {
			case SSL_ERROR_WANT_READ:
				logs_add_flow(handler->request, "EAPTLS FAILED SSL_ERROR_WANT_READ");
				break;
			case SSL_ERROR_WANT_WRITE:
				logs_add_flow(handler->request, "EAPTLS FAILED SSL_ERROR_WANT_WRITE");
				RDEBUG("Error in fragmentation logic");
				break;
			default:
				logs_add_flow(handler->request, "EAPTLS FAILED");
				/*
				 *	FIXME: Call int_ssl_check?
				 */
				break;
			}
			return EAPTLS_FAIL;
		}

		if (err == 0) {
			logs_add_flow(handler->request, "No data inside of the tunnel");
			RDEBUG("WARNING: No data inside of the tunnel.");
		}
	
		/*
		 *	Passed all checks, successfully decrypted data
		 */
		tls_session->clean_out.used = err;
		
		return EAPTLS_OK;
	}

	/*
	 *	Continue the handshake.
	 */
	return eaptls_operation(status, handler);
}


/*
 *	compose the TLS reply packet in the EAP reply typedata
 */
int eaptls_compose(EAP_DS *eap_ds, EAPTLS_PACKET *reply)
{
	uint8_t *ptr;

	/*
	 *	Don't set eap_ds->request->type.type, as the main EAP
	 *	handler will do that for us.  This allows the TLS
	 *	module to be called from TTLS & PEAP.
	 */

	/*
	 * 	When the EAP server receives an EAP-Response with the
	 * 	M bit set, it MUST respond with an EAP-Request with
	 * 	EAP-Type=EAP-TLS and no data. This serves as a
	 * 	fragment ACK. The EAP peer MUST wait until it receives
	 * 	the EAP-Request before sending another fragment.
	 *
	 *	In order to prevent errors in the processing of
	 *	fragments, the EAP server MUST use increment the
	 *	Identifier value for each fragment ACK contained
	 *	within an EAP-Request, and the peer MUST include this
	 *	Identifier value in the subsequent fragment contained
	 *	within an EAP- Reponse.
	 */
	eap_ds->request->type.data = malloc(reply->length - TLS_HEADER_LEN + 1);
	if (eap_ds->request->type.data == NULL) {
		radlog(L_ERR, "out of memory");
		return 0;
	}

	/* EAPTLS Header length is excluded while computing EAP typelen */
	eap_ds->request->type.length = reply->length - TLS_HEADER_LEN;

	ptr = eap_ds->request->type.data;
	*ptr++ = (uint8_t)(reply->flags & 0xFF);

	if (reply->dlen) memcpy(ptr, reply->data, reply->dlen);

	switch (reply->code) {
	case EAPTLS_ACK:
	case EAPTLS_START:
	case EAPTLS_REQUEST:
		eap_ds->request->code = PW_EAP_REQUEST;
		break;
	case EAPTLS_SUCCESS:
		eap_ds->request->code = PW_EAP_SUCCESS;
		break;
	case EAPTLS_FAIL:
		eap_ds->request->code = PW_EAP_FAILURE;
		break;
	default:
		/* Should never enter here */
		eap_ds->request->code = PW_EAP_FAILURE;
		break;
	}

	return 1;
}

