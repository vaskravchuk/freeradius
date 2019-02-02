/*
 * dstr.h	Dynamic string.
 *
 * Version:	$Id$t
 *
 * Created by Vasiliy Kravchuk on 1/24/19.
 */

#ifndef DSTR_H
#define DSTR_H

#include <stdio.h>

/*
 * If memory allocation fails, then a dynamic string goes
 * into the "NaS" or "Not a String" state.
 * Any operation on a NaS will maintain that status.
 */
#define NaS ((dstr) {NULL, 0, 0})
#define is_nas(S) (!(S)->s)

/* String struct */
typedef struct dstr {
    /* Buffer */
    char *s;
    /* String length */
    size_t size;
    /* Buffer size */
    size_t b_size;
} dstr;

/* Get string size */
size_t dstr_size(dstr *s);

/*
 * Creating
 * All string allocated in method stack. Because of most of the time,
 * strings are local to a function and
 * allocating on the stack is quite convenient
 * but even in stack you should call dstr_destroy() to clean underground buffer.
 */
dstr dstr_create(size_t size);
void dstr_destroy(dstr *s);

/* Converting */
/* Create new dstr from cstring. Cstring will be copied into internal buffer. */
dstr dstr_cstr_n(char *c, size_t len);
/*
 * Create new dstr from cstring. Cstring will be copied into internal buffer.
 * This method not so optimized as dstr_cstr_n(), because of strlen() calling
 */
dstr dstr_cstr(char *c);
/*
 * Be careful with "dstr_to_cstr" and dstr_destroy().
 * dstr_destroy() freeing buffer, so result of "dstr_to_cstr" will be freed
 */
char *dstr_to_cstr(dstr *s);
/* Return string with escaped chars */
dstr dstr_escaped(const char *str);

/* Copy */
dstr dstr_dup_dstr(dstr *s);
void dstr_cpy_dstr(dstr *dest, dstr *src);

/* Concat */
void dstr_cat_cstr_n(dstr *s, size_t len, const char *str);
void dstr_cat_fmt(dstr *s, const char* fmt, ...);
void dstr_cat_char(dstr *s, char chr);
void dstr_cat_cstr(dstr *s, const char *str);
void dstr_cat_dstr(dstr *s, const dstr *s2);
/* Should be finished with "0" value */
void dstr_cat_cstrs(dstr *s, ...);
void dstr_cat_dstrs(dstr *s1, ...);


#endif //DSTR_H
