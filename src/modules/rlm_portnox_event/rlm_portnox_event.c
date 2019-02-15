/*
 * rlm_portnox_event.c
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
#include <freeradius-devel/portnox/attrs_helper.h>

/* Define a structure for our module configuration. */
typedef struct rlm_portnox_event_t {
	int				type_idx;
	char			*type_name;
	char			*packet_type;
	unsigned int	packet_code;
} rlm_portnox_event_t;

static int event_processing(rlm_portnox_event_t *inst, REQUEST *request);
static int acct_processing(rlm_portnox_event_t *inst, REQUEST *request);

#define ACCEPT_IDX	0
#define REJECT_IDX	1
#define ACCT_IDX	2
#define IDX_SIZE	3

static char *type_map[IDX_SIZE] = { "ACCEPT", "REJECT", "ACCT"}

/* A mapping of configuration file names to internal variables. */
static const CONF_PARSER module_config[] = {
	{ "type",  PW_TYPE_INTEGER,
	  offsetof(rlm_exec_t,type_idx), NULL, Stringify(0) },
	{ "packet_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_exec_t,packet_type), NULL, NULL },
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/* Detach an instance and free it's data. */
static int portnox_event_detach(void *instance)
{
	rlm_portnox_event_t	*inst = NULL;

	inst = instance;

	free(inst);
	return 0;
}

/* Do any per-module initialization */
static int portnox_event_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_portnox_event_t	*inst;

	/* Set up a storage area for instance data */

	inst = rad_malloc(sizeof(rlm_portnox_event_t));
	if (!inst)
		return -1;
	memset(inst, 0, sizeof(rlm_portnox_event_t));

	/* If the configuration parameters can't be parsed, then fail. */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		radlog(L_ERR, "rlm_portnox_event: Failed parsing the configuration");
		exec_detach(inst);
		return -1;
	}

	/* process type */
	if (inst->type_idx < IDX_SIZE) inst->type_name = type_map[inst->type_idx];

	/* Get the packet type on which to execute */
	if (!inst->packet_type) {
		inst->packet_code = 0;
	} else {
		DICT_VALUE	*dval;

		dval = dict_valbyname(PW_PACKET_TYPE, inst->packet_type);
		if (!dval) {
			radlog(L_ERR, "rlm_portnox_event: Unknown packet type %s: See list of VALUEs for Packet-Type in share/dictionary", inst->packet_type);
			exec_detach(inst);
			return -1;
		}
		inst->packet_code = dval->value;
	}

	*instance = inst;

	return 0;
}

/* do event processing */
static int event_processing(void *instance, REQUEST *request)
{
	int result = 0;
	rlm_portnox_event_t	*inst = NULL;
	
	inst = instance;

	/* See if we're supposed to execute it now. */
	if (!((inst->packet_code == 0) ||
	      (request->packet->code == inst->packet_code) ||
	      (request->reply->code == inst->packet_code) ||
	      (request->proxy &&
	       (request->proxy->code == inst->packet_code)) ||
	      (request->proxy_reply &&
	       (request->proxy_reply->code == inst->packet_code)))) {
		RDEBUG2("Packet type is not %s. Not executing.", inst->packet_type);
		return RLM_MODULE_NOOP;
	}

	switch (inst->type_idx) {
		case ACCEPT_IDX:
		case REJECT_IDX:
			event_processing(inst, request);
			result = RLM_MODULE_OK;
			break;
		case ACCT_IDX:
			acct_processing(inst, request);
			result = RLM_MODULE_OK;
			break;
		default:
			RDEBUG2("Event type is not %s. Not executing.", inst->type_idx);
			result = RLM_MODULE_NOOP;
			break;
	}

	return result;
}

/* ACCEPT/REJECT processing */
static int event_processing(rlm_portnox_event_t *inst, REQUEST *request) {
	int result = 0;

	return result;
}

/* ACCT processing */
static int acct_processing(rlm_portnox_event_t *inst, REQUEST *request) {
	int result = 0;

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
module_t rlm_portnox_event = {
	RLM_MODULE_INIT,
	"portnox_event",				/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	portnox_event_instantiate,		/* instantiation */
	portnox_event_detach,			/* detach */
	{
		event_processing,			/* authentication */
		event_processing,	        /* authorization */
		event_processing,			/* pre-accounting */
		event_processing,			/* accounting */
		event_processing,			/* check simul */
		event_processing,			/* pre-proxy */
		event_processing,			/* post-proxy */
		event_processing			/* post-auth */
#ifdef WITH_COA
		, event_processing,
		NULL
#endif
	},
};
