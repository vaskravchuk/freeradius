/*
 * eap_logger.c    logger of eap session.
 */

#include <freeradius-devel/ident.h>

#include "rlm_eap.h"

extern int allow_portnox_request_log;

void radlog_eaphandler_portnox(EAP_HANDLER *handler, int full_info, const char *msg, ...) 
{
	if (!allow_portnox_request_log) {
		return;
	}
	
	char namebuf[64];
	char buffer[256];
	const char *eaptype_name;
	size_t len = 0;
	REQUEST *request = NULL;

	memset(namebuf, 0, sizeof(namebuf));
	memset(buffer, 0, sizeof(buffer));

	request = (handler->request != NULL) ? handler->request : handler->cached_request;

	va_list ap;
	va_start(ap, msg);
	vsnprintf(buffer + len, sizeof(buffer) - len, msg, ap);
	va_end(ap);

	if (request) {
		eaptype_name = eaptype_type2name(handler->eap_type, namebuf, sizeof(namebuf));
		logs_set_eaptype(request, eaptype_name);
		logs_set_trips(request, handler->trips);
	
		log_request(request, full_info, buffer);
	}
	else {
		radlog(L_ERR, buffer);
	}
}