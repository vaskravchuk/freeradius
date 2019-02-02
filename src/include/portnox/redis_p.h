/*
 * redis_p.h	Execute redis commands.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#ifndef REDIS_P_H
#define REDIS_P_H

/*
 * !!!WARNING!!!!
 * Do not update 'credis' code or do it very carefully, 
 * a lot of custom changes.
 */

/* SET redis command */
int redis_set(const char *key, const char *val);
/* SETEX redis command with ttl */
int redis_setex(const char *key, const char *val, int ttl);
/*
 * GET redis command.
 * WARNING. 'val' is dynamic allocated string, should be freed.
 */
int redis_get(const char *key, char **val);
/* DEL redis command */
int redis_del(const char *key);

/* Return string which describes redis Error */
const char* redis_error_descr(int error);

#endif //REDIS_P_H
