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

static void plain_pwd_processor(dstr* value);

/*
 *  do pap authentication
 */
static int portnox_pap_auth(void *instance, REQUEST *request)
{
    static auth_attr_proc_t procs[1] = { (auth_attr_proc_t){USER_PWD_ATTR, PLAIN_PWD_PR, NULL} };
    static auth_attr_proc_list_t proc_list = {procs, sizeof(procs)};

	int result = NULL;
	VALUE_PAIR *answer = NULL;

    result = portnox_auth(request, 1, &proc_list, &answer);

	if (result != OPERATION_SUCCESS) {
		radlog(L_ERR, "portnox_pap_auth failed");
		return RLM_MODULE_FAIL;
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
module_t rlm_portnox_pap = {
	RLM_MODULE_INIT,
	"portnox_pap",					/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	NULL,							/* instantiation */
	NULL,							/* detach */
	{
		portnox_pap_auth,			/* authentication */
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
