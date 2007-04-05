/*

Copyright (c) 1988  X Consortium

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
X CONSORTIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the X Consortium shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from the X Consortium.

*/
/*  Modified for stand-alone compiling by
 *  Peter 'Luna' Runestig <peter@runestig.com>
 */

#ifndef _Xauth_h
#define _Xauth_h

typedef struct xauth {
    unsigned short   family;
    unsigned short   address_length;
    char    	    *address;
    unsigned short   number_length;
    char    	    *number;
    unsigned short   name_length;
    char    	    *name;
    unsigned short   data_length;
    char   	    *data;
} Xauth;

# include   <stdio.h>

/* from X.h */
#define FamilyInternet		0
#define FamilyDECnet		1
#define FamilyChaos		2

# define FamilyLocal (256)	/* not part of X standard (i.e. X.h) */
# define FamilyWild  (65535)
# define FamilyNetname    (254)   /* not part of X standard */
# define FamilyKrb5Principal (253) /* Kerberos 5 principal name */
# define FamilyLocalHost (252)	/* for local non-net authentication */

char *XauFileName();

Xauth *XauReadAuth(
FILE*	/* auth_file */
);

int XauWriteAuth(
FILE*		/* auth_file */,
Xauth*		/* auth */
);

Xauth *XauGetAuthByName(
const char*	/* display_name */
);

Xauth *XauGetAuthByAddr(
unsigned int	/* family */,
unsigned int	/* address_length */,
const char*	/* address */,
unsigned int	/* number_length */,
const char*	/* number */,
unsigned int	/* name_length */,
const char*	/* name */
);

void XauDisposeAuth(
Xauth*		/* auth */
);

#ifdef K5AUTH
#include <krb5/krb5.h>
/* 9/93: krb5.h leaks some symbols */
#undef BITS32
#undef xfree

int XauKrb5Encode(
#if NeedFunctionPrototypes
     krb5_principal	/* princ */,
     krb5_data *	/* outbuf */
#endif
);

int XauKrb5Decode(
#if NeedFunctionPrototypes
     krb5_data		/* inbuf */,
     krb5_principal *	/* princ */
#endif
);
#endif /* K5AUTH */

#endif /* _Xauth_h */
