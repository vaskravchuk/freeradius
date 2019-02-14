/*
 * string_helper.h  string helper methods.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSIDH(string_helper_h, "$Id$")

#define n_str(S) ((S) ? (S) : ("(null)"))

int is_contains(char **arr, int size, char* str);
int json_escape(char* str, char* out, int outlen);
int replace_char(char *str, char orig, char rep);
void lower(char *str);
char* str_replace(char* string, const char* substr, const char* replacement);
char* trim_to_string(char* string, char* substr);
char* bytes_to_hex(const unsigned char* data, size_t datalen);