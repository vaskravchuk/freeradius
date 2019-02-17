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
#include <freeradius-devel/portnox/string_helper.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

int is_contains(char **arr, int size, char* str) {
    int found = 0;
    for (int i = 0; i < size; ++i) {
        char* item = arr[i];
        if (strcmp(item, str) == 0) {
            found = 1;
            break;
        }
    }

    return found;
}

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
    while((ix = strchr(ix, orig))) {
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

/* fork from https://github.com/irl/la-cucina/blob/master/str_replace.c */
char* str_replace(char* string, const char* substr, const char* replacement) {
    char* tok = NULL;
    char* newstr = NULL;
    char* oldstr = NULL;
    int   oldstr_len = 0;
    int   substr_len = 0;
    int   replacement_len = 0;

    newstr = strdup(string);
    substr_len = strlen(substr);
    replacement_len = strlen(replacement);

    if (substr == NULL || replacement == NULL) {
        return newstr;
    }

    while ((tok = strstr(newstr, substr))) {
        oldstr = newstr;
        oldstr_len = strlen(oldstr);
        newstr = (char*)malloc(sizeof(char) * (oldstr_len - substr_len + replacement_len + 1));

        if (newstr == NULL) {
            free(oldstr);
            return NULL;
        }

        memcpy(newstr, oldstr, tok - oldstr);
        memcpy(newstr + (tok - oldstr), replacement, replacement_len);
        memcpy(newstr + (tok - oldstr) + replacement_len, tok + substr_len, oldstr_len - substr_len - (tok - oldstr));
        memset(newstr + oldstr_len - substr_len + replacement_len, 0, 1);

        free(oldstr);
    }

    return newstr;
}

char* trim_to_string(char* string, char* substr) {
    char* tok = NULL;
    char* newstr = NULL;
    int   oldstr_len = 0;
    int   substr_len = 0;
    int   size = 0;

    oldstr_len = strlen(string);
    substr_len = strlen(substr);

    if (substr == NULL) {
        return strdup(string);
    }

    tok = strstr(string, substr);
    if (tok) {
        size = oldstr_len - substr_len - (tok - string) + 1;
        newstr = (char*)malloc(sizeof(char) * size);

        if (newstr == NULL) {
            return NULL;
        }

        memcpy(newstr, tok + substr_len, size - 1);
        newstr[size - 1] = 0;
    } else {
        return strdup(string);
    }

    return newstr;
}

char* bytes_to_hex (const unsigned char* data, size_t datalen) {
    size_t final_len = 0;
    char* chrs = NULL;
    unsigned int j = 0;
    
    final_len = datalen * 2;
    chrs = malloc((final_len + 1) * sizeof(char));

    for(j = 0; j<datalen; j++) {
        chrs[2*j] = (data[j]>>4)+48;
        chrs[2*j+1] = (data[j]&15)+48;
        if (chrs[2*j]>57) chrs[2*j]+=7;
        if (chrs[2*j+1]>57) chrs[2*j+1]+=7;
    }
    chrs[2*j]='\0';
    lower(chrs);
    return chrs;
}

int vstr_format(char * s, int n, const char *format, va_list ap) {
    int len = 0;

    len = vsnprintf(s, n, format, ap);
    len = MIN(len, n-1);
    len = len < 0 ? 0 : len;

    return len;
}

int str_format(char * s, int n, const char *format, ...) {
    int len = 0;

    va_list ap;
    va_start(ap, format);
    len = vstr_format(s, n, format, ap);
    va_end(ap);

    return len;
}