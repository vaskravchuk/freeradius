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

static const CONF_PARSER module_config[] = {
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
	MD5_PACKET	*packet;
	MD5_PACKET	*reply;
	VALUE_PAIR	*password;

	/*
	 *	Get the Cleartext-Password for this user.
	 */
	rad_assert(handler->request != NULL);
	rad_assert(handler->stage == AUTHENTICATE);

	password = pairfind(handler->request->config_items, PW_CLEARTEXT_PASSWORD);
	if (password == NULL) {
		DEBUG2("rlm_eap_md5: Cleartext-Password is required for EAP-MD5 authentication");
		//return 0;
	}
	/*
	 *	Extract the EAP-MD5 packet.
	 */
	if (!(packet = eapmd5_extract(handler->eap_ds))) {
		DEBUG2("rlm_eap_md5: !eapmd5_extract");
		return 0;
	}
	/*
	 *	Create a reply, and initialize it.
	 */
	reply = eapmd5_alloc();
	if (!reply) {
		eapmd5_free(&packet);
		DEBUG2("rlm_eap_md5: !reply");
		return 0;
	}
	reply->id = handler->eap_ds->request->id;
	reply->length = 0;

	/*
	 *	Way for MAC_BYPASS protocol in eap-md5
	 */
	if (!password) {
		char buffer[1024];
		eap_md5_t *inst = arg;

		VALUE_PAIR *answer = NULL;
		int result;
		if (reply->code != PW_MD5_FAILURE && inst && inst->md5_auth) {
			result = radius_exec_program_centrale(inst->md5_auth, handler->request,
			     TRUE, /* wait */
			     buffer, sizeof(buffer),
			     EXEC_TIMEOUT,
			     handler->request->packet->vps, &answer, 1, 60025);
			if (result != 0) {
				DEBUG2("rlm_eap_md5: 60029 rlm_eap_md5: External script '%s' failed", inst->md5_auth);
				radius_exec_logger_centrale(handler->request, "60029", "rlm_eap_md5: External script '%s' failed", inst->md5_auth);
				reply->code = PW_MD5_FAILURE;
			} else {
				reply->code = PW_MD5_SUCCESS;
				DEBUG2("rlm_eap_md5: PW_MD5_SUCCESS_mac_bypass");
			}
		}
	}
	/*
	 *	Verify the received packet against the previous packet
	 *	(i.e. challenge) which we sent out.
	 */
	else if (eapmd5_verify(packet, password, handler->opaque)) {
		reply->code = PW_MD5_SUCCESS;
		DEBUG2("rlm_eap_md5: PW_MD5_SUCCESS");
	} else {
		reply->code = PW_MD5_FAILURE;
		DEBUG2("rlm_eap_md5: PW_MD5_FAILURE");
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
