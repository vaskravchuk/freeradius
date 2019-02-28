/*
 * redis_dal.h	main redis dal operations.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#ifndef REDIS_DAL_H
#define REDIS_DAL_H

#include <freeradius-devel/radiusd.h>

/* shared secret redis dal */
/* WARNING. 'val' is dynamic allocated string, should be freed. */
int get_shared_secret_for_client(const char *client, char **val);
int set_shared_secret_for_client(const char *client, const char *val);
/* WARNING. 'val' is dynamic allocated string, should be freed. */
int get_shared_secret_for_port(const int port, char **val);
int set_shared_secret_for_port(const int port, const char *val);
/* WARNING. 'val' is dynamic allocated string, should be freed. */
int get_response_for_data(const char* username, const char* mac, const char* port, const char* nas_type, char **val);
int set_response_for_data(const char* username, const char* mac, const char* port, const char* nas_type, const char *val);

/* organization id redis dal */
/* WARNING. 'val' is dynamic allocated string, should be freed. */
int get_org_id_for_client(const char *client, char **val);
int set_org_id_for_client(const char *client, const char *val);
/* WARNING. 'val' is dynamic allocated string, should be freed. */
int get_org_id_for_port(const int port, char **val);
int set_org_id_for_port(const int port, const char *val);

/* Return string which describes redis Error */
const char* redis_error_descr(int error);

#endif //REDIS_DAL_H
