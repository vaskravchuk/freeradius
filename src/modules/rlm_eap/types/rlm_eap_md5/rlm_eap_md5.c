/*
 * rlm_eap_md5.c    Handles that are called from eap
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
 * Copyright 2000,2001,2006  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>

#include <stdio.h>
#include <stdlib.h>

#include "eap_md5.h"

#include <freeradius-devel/rad_assert.h>

#include <freeradius-devel/portnox/portnox_auth.h>

static const CONF_PARSER module_config[] = {
	{ "use_script",    PW_TYPE_BOOLEAN,
	  offsetof(eap_md5_t,use_script), NULL, "no" },
	{ "md5_auth", PW_TYPE_STRING_PTR,
	  offsetof(eap_md5_t, md5_auth), NULL, NULL },

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

/*
 *	Detach the EAP-MD5 module.
 */
static int md5_detach(void *arg)
{
	eap_md5_t 	 *inst;

	inst = (eap_md5_t *) arg;

	free(inst);

	return 0;
}


/*
 *	Attach the EAP-MD5 module.
 */
static int md5_attach(CONF_SECTION *cs, void **instance)
{
	eap_md5_t 	 *inst;

	/* Store all these values in the data structure for later references */
	inst = (eap_md5_t *)malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_md5: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	Hack: conf is the first structure inside of inst.  The
	 *	CONF_PARSER stuff above uses offsetof() and
	 *	EAP_md5_CONF, which is technically wrong.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		eapmd5_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}

/*
 *	Initiate the EAP-MD5 session by sending a challenge to the peer.
 */
static int md5_initiate(void *type_data, EAP_HANDLER *handler)
{
	int		i;
	MD5_PACKET	*reply;

	type_data = type_data;	/* -Wunused */

	logs_add_flow(handler->request, "md5_initiate");

	/*
	 *	Allocate an EAP-MD5 packet.
	 */
	reply = eapmd5_alloc();
	if (reply == NULL)  {
		radlog(L_ERR, "rlm_eap_md5: out of memory");
		return 0;
	}

	/*
	 *	Fill it with data.
	 */
	reply->code = PW_MD5_CHALLENGE;
	reply->length = 1 + MD5_CHALLENGE_LEN; /* one byte of value size */
	reply->value_size = MD5_CHALLENGE_LEN;

	/*
	 *	Allocate user data.
	 */
	reply->value = malloc(reply->value_size);
	if (reply->value == NULL) {
		radlog(L_ERR, "rlm_eap_md5: out of memory");
		eapmd5_free(&reply);
		return 0;
	}

	/*
	 *	Get a random challenge.
	 */
	for (i = 0; i < reply->value_size; i++) {
		reply->value[i] = fr_rand();
	}
	logs_set_request_desc(handler->request, 1, "MD5 ISSUING CHALLENGE");
	logs_set_reply_desc(handler->request, 1, "MD5 CHALLENGE");
	logs_add_flow(handler->request, "Issuing Challenge");
	DEBUG2("rlm_eap_md5: Issuing Challenge");

	/*
	 *	Keep track of the challenge.
	 */
	handler->opaque = malloc(reply->value_size);
	rad_assert(handler->opaque != NULL);
	memcpy(handler->opaque, reply->value, reply->value_size);
	handler->free_opaque = free;

	/*
	 *	Compose the EAP-MD5 packet out of the data structure,
	 *	and free it.
	 */
	eapmd5_compose(handler->eap_ds, reply);

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'handler->eap_ds', which will be given back
	 *	to us...
	 */
	handler->stage = AUTHENTICATE;

	return 1;
}


/*
 *	Authenticate a previously sent challenge.
 */
static int md5_authenticate(UNUSED void *arg, EAP_HANDLER *handler)
{
    static AUTH_SP_ATTR procs[2] = { (AUTH_SP_ATTR){MD5_RESPONSE_ATTR, NT_RESPONSE_PR, NULL, NULL},
    								 (AUTH_SP_ATTR){MD5_CHALLENGE_ATTR, NT_CHALLENGE_PR, NULL, NULL} };
    static AUTH_SP_ATTR_LIST proc_list = {procs, sizeof(procs)/sizeof(procs[0])};
    static AUTH_INFO auth_info = {&proc_list,"60000","60001","60039"};
	MD5_PACKET	*packet;
	MD5_PACKET	*reply;
	VALUE_PAIR	*password;
	int result;

	logs_set_request_desc(handler->request, 1, "MD5 AUTHENTICATE");
	logs_add_flow(handler->request, "md5_authenticate");

	handler->request->auth_subtype = "MD5";
	
	/*
	 *	Get the Cleartext-Password for this user.
	 */
	rad_assert(handler->request != NULL);
	rad_assert(handler->stage == AUTHENTICATE);

	password = pairfind(handler->request->config_items, PW_CLEARTEXT_PASSWORD);
	if (password == NULL) {
		//DEBUG2("rlm_eap_md5: Cleartext-Password is required for EAP-MD5 authentication");
		//return 0; /// 'mac_bypass' Don't have password field
	}
	/*
	 *	Extract the EAP-MD5 packet.
	 */
	if (!(packet = eapmd5_extract(handler->eap_ds))) {
		logs_add_flow(handler->request, "EAPMD5 FAILED (eapmd5_extract failed)");
		DEBUG2("rlm_eap_md5: !eapmd5_extract");
		return 0;
	}
	/*
	 *	Create a reply, and initialize it.
	 */
	reply = eapmd5_alloc();
	if (!reply) {
		logs_add_flow(handler->request, "EAPMD5 FAILED (eapmd5_alloc failed)");
		eapmd5_free(&packet);
		DEBUG2("rlm_eap_md5: !reply");
		return 0;
	}
	reply->id = handler->eap_ds->request->id;
	reply->length = 0;

	/*
	 *	Verify the received packet against the previous packet
	 *	(i.e. challenge) which we sent out.
	 */
	// if (password) {
	// 	if (eapmd5_verify(packet, password, handler->opaque)) {
	// 		reply->code = PW_MD5_SUCCESS;
	// 		DEBUG2("rlm_eap_md5: PW_MD5_SUCCESS");
	// 	} else {
	// 		reply->code = PW_MD5_FAILURE;
	// 		DEBUG2("rlm_eap_md5: PW_MD5_FAILURE");
	// 	}
	// }

    // MD5 Chalange should be trimmed to MD5_CHALLENGE_LEN
    int challenge_size = MD5_CHALLENGE_LEN+1;
    char *challenge = malloc(challenge_size);
    memset(challenge, 0, challenge_size);
    if (!challenge) {
        eapmd5_free(&packet);
		logs_add_flow(handler->request, "EAPMD5 FAILED (challenge alloc failed)");
        DEBUG2("rlm_eap_md5: !challenge");
        return 0;
    }
    memcpy(challenge, handler->opaque, MD5_CHALLENGE_LEN);
    if (!radius_pairmake(handler->request, &handler->request->packet->vps, "MD5-Challenge", challenge, PW_TYPE_OCTETS)) {
		logs_add_flow(handler->request, "[EAPMD5 FAILED (Failed creating MD5-Challenge)]");
        radlog(L_ERR, "rlm_eap_md5: Failed creating MD5-Challenge");
    }
    free(challenge);
    challenge = NULL;

    // MD5 Chalange Response should containes packet id as first byte
    DEBUG2("rlm_eap_md5: packet->id %u", packet->id);
    int response_size = packet->value_size + 1 + 1;
    char *response = malloc(response_size);
    memset(response, 0, response_size);
    if (!response) {
        eapmd5_free(&packet);
		logs_add_flow(handler->request, "EAPMD5 FAILED (response alloc failed)");
        DEBUG2("rlm_eap_md5: !response");
        return 0;
    }
    *response = packet->id;
    ++response;
    memcpy(response, packet->value, packet->value_size);
    --response;
    if (!radius_pairmake(handler->request, &handler->request->packet->vps, "MD5-Password", response, PW_TYPE_OCTETS)) {
		logs_add_flow(handler->request, "EAPMD5 FAILED (Failed creating MD5-Password)");
        radlog(L_ERR, "rlm_eap_md5: Failed creating MD5-Password");
    }
    free(response);
    response = NULL;

	char buffer[1024] = {0};
	eap_md5_t *inst = arg;
	VALUE_PAIR *answer = NULL;
	VALUE_PAIR **output_pairs = NULL;

	if (reply->code != PW_MD5_FAILURE &&
		(inst && inst->md5_auth))
	{
		logs_add_flow(handler->request, "EAPMD5 BE");
		if (inst->use_script) {
			result = radius_exec_program_centrale(inst->md5_auth, handler->request,
				TRUE, /* wait */
				buffer, sizeof(buffer),
				EXEC_TIMEOUT,
				handler->request->packet->vps, &answer, 1, 60040);
		}
		else {
		    result = portnox_auth(handler->request, 
		    					  MD5_AUTH_METHOD, 
		    					  &auth_info, 
		    					  &answer,
		    					  buffer, sizeof(buffer));
		}

		if (result != 0) {
			logs_add_flow(handler->request, "EAPMD5 DENY (External script '%s' failed)", inst->md5_auth);
			DEBUG2("rlm_eap_md5: 60041 rlm_eap_md5: External script '%s' failed", inst->md5_auth);
			radius_exec_logger_centrale(handler->request, "60041", "rlm_eap_md5: External script '%s' failed", inst->md5_auth);
			logs_set_reply_desc(handler->request, 1, "MD5 FAILED");
			reply->code = PW_MD5_FAILURE;
		} else {
		    if (answer != NULL) {
		        if (handler->request->reply != NULL) {
        	        output_pairs = &handler->request->reply->vps;
    	            if (output_pairs != NULL) {
			            DEBUG2("rlm_eap_md5: Moving script value pairs to the reply");
			            pairmove(output_pairs, &answer);
	    	        }
	    	        else {
			            DEBUG2("rlm_eap_md5: output_pairs==NULL");
	    	        }
	    	        pairfree(&answer);
	    	    }
	    	    else {
		            DEBUG2("rlm_eap_md5: request->reply==NULL");
	    	    }
	        }
	        else {
		        DEBUG2("rlm_eap_md5: answer==NULL");
	        }

			logs_set_reply_desc(handler->request, 1, "MD5 SUCCESS");
			reply->code = PW_MD5_SUCCESS;

			logs_add_flow(handler->request, "EAPMD5 BE SUCCESS");
			DEBUG2("rlm_eap_md5: PW_MD5_SUCCESS");
		}
	}
	else {
		logs_add_flow(handler->request, "EAPMD5 FAILED (PW_MD5_FAILURE)");
		reply->code = PW_MD5_FAILURE;
	}

	/*
	 *	Compose the EAP-MD5 packet out of the data structure,
	 *	and free it.
	 */
	eapmd5_compose(handler->eap_ds, reply);

	eapmd5_free(&packet);
	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_md5 = {
	"eap_md5",
	md5_attach,				/* attach */
	md5_initiate,			/* Start the initial request */
	NULL,				/* authorization */
	md5_authenticate,		/* authentication */
	md5_detach				/* detach */
};
