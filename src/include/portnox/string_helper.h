/*
 * string_helper.h  string helper methods.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSIDH(string_helper_h, "$Id$")

int json_escape(char* str, char* out, int outlen);
int replace_char(char *str, char orig, char rep);
void lower(char *str);