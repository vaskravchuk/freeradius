/*
 * dstr.c	Dynamic string.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */


#include <freeradius-devel/portnox/dstr.h>

#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>

static void dstr_resize(dstr *s, size_t size);

size_t dstr_size(dstr *s) {
    if (is_nas(s)) return 0;
    return s->size;
}

dstr dstr_create(size_t size) {
    if (size < 16) size = 16;
    return (dstr) {malloc(size), 0, size};
}

void dstr_destroy(dstr *s) {
    if (!is_nas(s)) {
        free(s->s);
        *s = NaS;
    }
}

static void dstr_resize(dstr *s, size_t size) {
    char *buf;
    size_t bsize;

    /* Are we not a string? */
    if (is_nas(s)) return;

    bsize = s->b_size;

    /* Keep at least 16 bytes */
    if (size < 16) size = 16;

    /* Nothing to do? */
    if ((4 * size > 3 * bsize) && (size <= bsize)) return;

    /* Try to double size instead of using a small increment */
    if ((size > bsize) && (size < bsize * 2)) size = bsize * 2;

    /* Keep at least 16 bytes */
    if (size < 16) size = 16;

    buf = realloc(s->s, size);

    if (!buf) {
        /* Failed, go to NaS state */
        free(s->s);
        *s = NaS;
    }
    else {
        s->s = buf;
        s->b_size = size;
    }
}

dstr dstr_cstr_n(char *c, size_t len) {
    dstr s;

    s = dstr_create(len + 1);
    memcpy(s.s, c, len);
    s.size = len;

    return s;
}

/* A struct string based on a C string, stored in whatever c points to */
dstr dstr_cstr(char *c) {
    size_t len = strlen(c);
    return dstr_cstr_n(c, len);
}

/* Return escaped dstr for json or redis. */
dstr dstr_escaped(const char *str) {
    char* rep = NULL;
    int i = 0;
    char chr = 0;
    dstr s;

    /* Are we not a string? */
    if (!str || *str) NaS;

    /* create new string */
    size_t len = strlen(str);
    s = dstr_create(len+1);

    /* iterate throw all chars */
    for(;(chr = str[i]) && (i < len); i++) {
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
            /* copy with escaping */
            dstr_cat_cstr(&s, rep);
        }
        else {
            dstr_cat_char(&s, chr);
        }
    }

    return s;
}

dstr dstr_from_fmt(const char* fmt, ...) {
    char *buf;
    int size;
    va_list v;
    dstr s;

    va_start(v, fmt);

    size = vasprintf(&buf, fmt, v);
    /* problems occurred? */
    if (size < 0) {
        va_end(v);
        return;
    }

    s = dstr_create(size+1);
    dstr_cat_cstr_n(&s, size, buf);

    va_end(v);
    free(buf);

    return s;
}

/* Create a new string as a copy of an old one */
dstr dstr_dup_dstr(dstr *s) {
    dstr s2;

    /* Not a string? */
    if (is_nas(s)) return NaS;

    s2 = dstr_create(s->size);
    s2.size = s->size;
    memcpy(s2.s, s->s, s->size);

    return s2;
}

/* Copy the memory from the source string into the dest string */
void dstr_cpy_dstr(dstr *dest, dstr *src) {
    /* Are we no a string */
    if (is_nas(src)) return;

    dstr_resize(dest, src->size);

    if (is_nas(dest)) return;
    dest->size = src->size;
    memcpy(dest->s, src->s, src->size);
}

char *dstr_to_cstr(dstr *s) {
    /* Are we not a string? */
    if (is_nas(s)) return NULL;

    if (s->size == s->b_size) {
        /* Increase buffer size */
        dstr_resize(s, s->b_size + 1);

        /* Are we no longer a string? */
        if (is_nas(s)) return NULL;
    }

    /* Tack a zero on the end */
    s->s[s->size] = 0;

    /* Don't update the size */

    /* Can use this buffer as long as you don't append anything else */
    return s->s;
}

void dstr_cat_cstr_n(dstr *s, size_t len, const char *str) {
    /* Are we not a string? */
    if (is_nas(s)) return;

    /* Nothing to do? */
    if (!str || !len) return;

    if (s->size + len >= s->b_size) {
        dstr_resize(s, s->size + len);

        /* Are we no longer a string? */
        if (is_nas(s)) return;
    }

    memcpy(&s->s[s->size], str, len);
    s->size += len;
}

void dstr_cat_fmt(dstr *s, const char* fmt, ...) {
    char *buf;
    int size;
    va_list v;

    /* Are we not a string? */
    if (is_nas(s)) return;

    va_start(v, fmt);

    size = vasprintf(&buf, fmt, v);
    /* problems occurred? */
    if (size < 0) {
        va_end(v);
        return;
    }

    dstr_cat_cstr_n(s, size, buf);

    va_end(v);
    free(buf);
}

void dstr_cat_char(dstr *s, char chr) {
    /* Are we not a string? */
    if (is_nas(s)) return;

    if (s->size + 1 >= s->b_size) {
        dstr_resize(s, s->size + 1);

        /* Are we no longer a string? */
        if (is_nas(s)) return;
    }

    s->s[s->size++] = chr;
}

void dstr_cat_cstr(dstr *s, const char *str) {
    if (str) dstr_cat_cstr_n(s, strlen(str), str);
}

void dstr_cat_dstr(dstr *s, const dstr *s2) {
    dstr_cat_cstr_n(s, s2->size, s2->s);
}

void dstr_cat_cstrs(dstr *s, ...) {
    const char *str;
    va_list v;

    /* Are we not a string? */
    if (is_nas(s)) return;

    va_start(v, s);

    for (str = va_arg(v, const char *); str; str = va_arg(v, const char *)) {
        dstr_cat_cstr_n(s, strlen(str), str);
    }

    va_end(v);
}

void dstr_cat_dstrs(dstr *s1, ...) {
    const dstr *s2;
    va_list v;

    /* Are we not a string? */
    if (is_nas(s1)) return;

    va_start(v, s1);

    for (s2 = va_arg(v, const dstr *); s2; s2 = va_arg(v, const dstr *)) {
        dstr_cat_cstr_n(s1, s2->size, s2->s);
    }

    va_end(v);
}

int dstr_replace_chars(dstr *str, char orig, char rep) {
    char *ix = NULL;
    int n = 0;
    /* Are we not a string? */
    if (is_nas(str)) return;

    *ix = str->s;
    while((ix = strchr(ix, orig)) != NULL && n < str->size) {
        *ix++ = rep;
        n++;
    }
    return n;
}

void dstr_to_lower(dstr *str) {
    int i = 0;

    /* Are we not a string? */
    if (is_nas(str)) return;

    for(; str->s[i] && i < str->size; i++) {
        str->s[i] = tolower(str->s[i]);
    }
}