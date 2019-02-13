/*
 * string_helper.c	string helper methods.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

int json_escape(char* str, char* out, int outlen) {
    int offset = 0;
    char* rep = NULL;
    int i = 0;
    char chr = 0;

    for(;(chr = str[i]) && (i < outlen); i++) {
        switch (chr) {
            case '\\': rep = "\\\\"; break;
            case '"': rep = "\\\""; break;
            case '/': rep = "\\/"; break;
            case '\b': rep = "\\b"; break;
            case '\f': rep = "\\f"; break;
            case '\n': rep = "\\n"; break;
            case '\r': rep = "\\r"; break;
            case '\t': rep = "\\t"; break;
            default: rep = NULL; break;
        }

        if (rep != NULL) {
            offset += str_format(out + offset, outlen - offset, "%s", rep);
        }
        else {
            out[offset++] = chr;
        }
    }

    return offset;
}

int replace_char(char *str, char orig, char rep) {
    char *ix = str;
    int n = 0;
    while((ix = strchr(ix, orig)) != NULL) {
        *ix++ = rep;
        n++;
    }
    return n;
}

void lower(char *str) {
    for(int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}