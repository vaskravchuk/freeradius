/*
 * rlm_portnox_pap.c
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
 * Copyright 2002,2006  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/portnox/portnox_auth.h>

/* do chap authentication */
static int portnox_chap_auth(void *instance, REQUEST *request)
{
    static AUTH_SP_ATTR procs[2] = { (AUTH_SP_ATTR){CHAP_RESPONSE_ATTR, NT_RESPONSE_PR, NULL, NULL},
                                     (AUTH_SP_ATTR){PACKET_AUTH_VECTOR_ATTR, NT_CHALLENGE_PR, NULL, NULL},
                                     (AUTH_SP_ATTR){CHAP_CHALLENGE_ATTR, NT_CHALLENGE_PR, NULL, NULL} };
    static AUTH_SP_ATTR_LIST proc_list = {procs, sizeof(procs)/sizeof(procs[0])};
    static AUTH_INFO auth_info = {&proc_list,"60036","60037","60035"};

	int result = NULL;
	VALUE_PAIR *answer = NULL;

	request_set_auth_subtype(request, "CHAP");

    result = portnox_auth(request,
    					  CHAP_AUTH_METHOD,
    					  &auth_info,
    					  &answer,
    					  NULL, 0);

	if (result != OPERATION_SUCCESS) {
		radlog(L_ERR, "portnox_chap_auth failed");
		result = RLM_MODULE_FAIL;
	}
	else {
		result = RLM_MODULE_OK;
	}

	/* Move the answer over to the request reply */
	if (request->reply) pairmove(&request->reply->vps, &answer);

	pairfree(&answer);

	return result;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_portnox_chap = {
	RLM_MODULE_INIT,
	"portnox_chap",					/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	NULL,							/* instantiation */
	NULL,							/* detach */
	{
		portnox_chap_auth,			/* authentication */
		NULL,	        			/* authorization */
		NULL,						/* pre-accounting */
		NULL,						/* accounting */
		NULL,						/* check simul */
		NULL,						/* pre-proxy */
		NULL,						/* post-proxy */
		NULL						/* post-auth */
#ifdef WITH_COA
		, NULL,
		NULL
#endif
	},
};
