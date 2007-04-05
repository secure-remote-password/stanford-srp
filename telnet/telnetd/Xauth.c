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

/*
 * Incorporated into the SRP Telnet distribution 10/19/2000 by
 * Tom Wu <tjw@cs.stanford.edu>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef FWD_X

#include "Xauth.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#define Time_t time_t

#ifndef X_NOT_POSIX
#include <unistd.h>
#else
#ifndef WIN32
extern unsigned	sleep ();
#else
#define link rename
#endif
#endif
#ifdef __EMX__
#define link rename
#endif


void
XauDisposeAuth (auth)
Xauth	*auth;
{
    if (auth) {
	if (auth->address) (void) free (auth->address);
	if (auth->number) (void) free (auth->number);
	if (auth->name) (void) free (auth->name);
	if (auth->data) {
	    (void) bzero (auth->data, auth->data_length);
	    (void) free (auth->data);
	}
	free ((char *) auth);
    }
    return;
}

char *
XauFileName ()
{
    char *slashDotXauthority = "/.Xauthority";
    char    *name;
    static char	*buf;
    static int	bsize;
#ifdef WIN32
    char    dir[128];
#endif
    int	    size;

    if (name = getenv ("XAUTHORITY"))
	return name;
    name = getenv ("HOME");
    if (!name) {
#ifdef WIN32
	(void) strcpy (dir, "/users/");
	if (name = getenv("USERNAME")) {
	    (void) strcat (dir, name);
	    name = dir;
	}
	if (!name)
#endif
	return 0;
    }
    size = strlen (name) + strlen(&slashDotXauthority[1]) + 2;
    if (size > bsize) {
	if (buf)
	    free (buf);
	buf = malloc ((unsigned) size);
	if (!buf)
	    return 0;
	bsize = size;
    }
    strcpy (buf, name);
    strcat (buf, slashDotXauthority + (name[1] == '\0' ? 1 : 0));
    return buf;
}

static int
binaryEqual (a, b, len)
register char	*a, *b;
register int	len;
{
    while (len--)
	if (*a++ != *b++)
	    return 0;
    return 1;
}

Xauth *
XauGetAuthByAddr (family, address_length, address,
			  number_length, number,
			  name_length, name)
unsigned int	family;
unsigned int	address_length;
const char	*address;
unsigned int	number_length;
const char	*number;
unsigned int	name_length;
const char	*name;
{
    FILE    *auth_file;
    char    *auth_name;
    Xauth   *entry;

    auth_name = XauFileName ();
    if (!auth_name)
	return 0;
    if (access (auth_name, R_OK) != 0)		/* checks REAL id */
	return 0;
    auth_file = fopen (auth_name, "rb");
    if (!auth_file)
	return 0;
    for (;;) {
	entry = XauReadAuth (auth_file);
	if (!entry)
	    break;
	/*
	 * Match when:
	 *   either family or entry->family are FamilyWild or
	 *    family and entry->family are the same
	 *  and
	 *   either address or entry->address are empty or
	 *    address and entry->address are the same
	 *  and
	 *   either number or entry->number are empty or
	 *    number and entry->number are the same
	 *  and
	 *   either name or entry->name are empty or
	 *    name and entry->name are the same
	 */

/*	if ((family == FamilyWild || entry->family == FamilyWild ||
	     (entry->family == family &&
	      address_length == entry->address_length &&
	      binaryEqual (entry->address, address, (int)address_length))) &&
	    (number_length == 0 || entry->number_length == 0 ||
	     (number_length == entry->number_length &&
	      binaryEqual (entry->number, number, (int)number_length))) &&
	    (name_length == 0 || entry->name_length == 0 ||
	     (entry->name_length == name_length &&
 	      binaryEqual (entry->name, name, (int)name_length)))) */
	/* the original matching code above doesn't seem to meet the matching
	 * algorithm, it doesn't check if "address_length == 0 ||
	 * entry->address_length == 0". / Luna 2000-02-09
	 */
	if ((family == FamilyWild || entry->family == FamilyWild ||
	      entry->family == family) &&
	    (address_length == 0 || entry->address_length == 0 ||
	      (address_length == entry->address_length &&
	      binaryEqual (entry->address, address, (int)address_length))) &&
	    (number_length == 0 || entry->number_length == 0 ||
	     (number_length == entry->number_length &&
	      binaryEqual (entry->number, number, (int)number_length))) &&
	    (name_length == 0 || entry->name_length == 0 ||
	     (entry->name_length == name_length &&
 	      binaryEqual (entry->name, name, (int)name_length))))
	    break;
	XauDisposeAuth (entry);
    }
    (void) fclose (auth_file);
    return entry;
}

static int
read_short (shortp, file)
unsigned short	*shortp;
FILE		*file;
{
    unsigned char   file_short[2];

    if (fread ((char *) file_short, (int) sizeof (file_short), 1, file) != 1)
	return 0;
    *shortp = file_short[0] * 256 + file_short[1];
    return 1;
}

static int
read_counted_string (countp, stringp, file)
unsigned short	*countp;
char	**stringp;
FILE	*file;
{
    unsigned short  len;
    char	    *data;

    if (read_short (&len, file) == 0)
	return 0;
    if (len == 0) {
	data = 0;
    } else {
    	data = malloc ((unsigned) len);
    	if (!data)
	    return 0;
    	if (fread (data, (int) sizeof (char), (int) len, file) != len) {
	    bzero (data, len);
	    free (data);
	    return 0;
    	}
    }
    *stringp = data;
    *countp = len;
    return 1;
}

Xauth *
XauReadAuth (auth_file)
FILE	*auth_file;
{
    Xauth   local;
    Xauth   *ret;

    if (read_short (&local.family, auth_file) == 0)
	return 0;
    if (read_counted_string (&local.address_length, &local.address, auth_file) == 0)
	return 0;
    if (read_counted_string (&local.number_length, &local.number, auth_file) == 0) {
	if (local.address) free (local.address);
	return 0;
    }
    if (read_counted_string (&local.name_length, &local.name, auth_file) == 0) {
	if (local.address) free (local.address);
	if (local.number) free (local.number);
	return 0;
    }
    if (read_counted_string (&local.data_length, &local.data, auth_file) == 0) {
	if (local.address) free (local.address);
	if (local.number) free (local.number);
	if (local.name) free (local.name);
	return 0;
    }
    ret = (Xauth *) malloc (sizeof (Xauth));
    if (!ret) {
	if (local.address) free (local.address);
	if (local.number) free (local.number);
	if (local.name) free (local.name);
	if (local.data) {
	    bzero (local.data, local.data_length);
	    free (local.data);
	}
	return 0;
    }
    *ret = local;
    return ret;
}

static int
write_short (s, file)
unsigned short	s;
FILE		*file;
{
    unsigned char   file_short[2];

    file_short[0] = (s & (unsigned)0xff00) >> 8;
    file_short[1] = s & 0xff;
    if (fwrite ((char *) file_short, (int) sizeof (file_short), 1, file) != 1)
	return 0;
    return 1;
}

static int
write_counted_string (count, string, file)
unsigned short	count;
char	*string;
FILE	*file;
{
    if (write_short (count, file) == 0)
	return 0;
    if (fwrite (string, (int) sizeof (char), (int) count, file) != count)
	return 0;
    return 1;
}

int
XauWriteAuth (auth_file, auth)
FILE	*auth_file;
Xauth	*auth;
{
    if (write_short (auth->family, auth_file) == 0)
	return 0;
    if (write_counted_string (auth->address_length, auth->address, auth_file) == 0)
	return 0;
    if (write_counted_string (auth->number_length, auth->number, auth_file) == 0)
	return 0;
    if (write_counted_string (auth->name_length, auth->name, auth_file) == 0)
	return 0;
    if (write_counted_string (auth->data_length, auth->data, auth_file) == 0)
	return 0;
    return 1;
}

/*
 * functions to encode/decode Kerberos V5 principals
 * into something that can be reasonable spewed over
 * the wire
 *
 * Author: Tom Yu <tlyu@MIT.EDU>
 *
 * Still needs to be fixed up wrt signed/unsigned lengths, but we'll worry
 * about that later.
 */

#ifdef K5AUTH
#include <krb5/krb5.h>
/* 9/93: krb5.h leaks some symbols */
#undef BITS32
#undef xfree

/*
#include <X11/X.h>
#include <X11/Xos.h>
#include <X11/Xmd.h>
#include <X11/Xfuncs.h>
*/

/*
 * XauKrb5Encode
 *
 * this function encodes the principal passed to it in a format that can
 * easily be dealt with by stuffing it into an X packet.  Encoding is as
 * follows:
 *   length count of the realm name
 *   realm
 *   component count
 *   length of component
 *   actual principal component
 *   etc....
 *
 * Note that this function allocates a hunk of memory, which must be
 * freed to avoid nasty memory leak type things.  All counts are
 * byte-swapped if needed. (except for the total length returned)
 *
 * nevermind.... stuffing the encoded packet in net byte order just to
 * always do the right thing.  Don't have to frob with alignment that way.
 */
int
XauKrb5Encode(princ, outbuf)
    krb5_principal princ;	/* principal to encode */
    krb5_data *outbuf;		/* output buffer */
{
    CARD16 i, numparts, totlen = 0, plen, rlen;
    char *cp, *pdata;

    rlen = krb5_princ_realm(princ)->length;
    numparts = krb5_princ_size(princ);
    totlen = 2 + rlen + 2;	/* include room for realm length
				   and component count */
    for (i = 0; i < numparts; i++)
	totlen += krb5_princ_component(princ, i)->length + 2;
    /* add 2 bytes each time for length */
    if ((outbuf->data = (char *)malloc(totlen)) == NULL)
	return -1;
    cp = outbuf->data;
    *cp++ = (char)((int)(0xff00 & rlen) >> 8);
    *cp++ = (char)(0x00ff & rlen);
    memcpy(cp, krb5_princ_realm(princ)->data, rlen);
    cp += rlen;
    *cp++ = (char)((int)(0xff00 & numparts) >> 8);
    *cp++ = (char)(0x00ff & numparts);
    for (i = 0; i < numparts; i++)
    {
	plen = krb5_princ_component(princ, i)->length;
	pdata = krb5_princ_component(princ, i)->data;
	*cp++ = (char)((int)(0xff00 & plen) >> 8);
	*cp++ = (char)(0x00ff & plen);
	memcpy(cp, pdata, plen);
	cp += plen;
    }
    outbuf->length = totlen;
    return 0;
}

/*
 * XauKrb5Decode
 *
 * This function essentially reverses what XauKrb5Encode does.
 * return value: 0 if okay, -1 if malloc fails, -2 if inbuf format bad
 */
int
XauKrb5Decode(inbuf, princ)
    krb5_data inbuf;
    krb5_principal *princ;
{
    CARD16 i, numparts, plen, rlen;
    CARD8 *cp, *pdata;
    
    if (inbuf.length < 4)
    {
	return -2;
    }
    *princ = (krb5_principal)malloc(sizeof (krb5_principal_data));
    if (*princ == NULL)
	return -1;
    bzero(*princ, sizeof (krb5_principal_data));
    cp = (CARD8 *)inbuf.data;
    rlen = *cp++ << 8;
    rlen |= *cp++;
    if (inbuf.length < 4 + (int)rlen + 2)
    {
	krb5_free_principal(*princ);
	return -2;
    }
    krb5_princ_realm(*princ)->data = (char *)malloc(rlen);
    if (krb5_princ_realm(*princ)->data == NULL)
    {
	krb5_free_principal(*princ);
	return -1;
    }
    krb5_princ_realm(*princ)->length = rlen;
    memcpy(krb5_princ_realm(*princ)->data, cp, rlen);
    cp += rlen;
    numparts = *cp++ << 8;
    numparts |= *cp++;
    krb5_princ_name(*princ) =
	(krb5_data *)malloc(numparts * sizeof (krb5_data));
    if (krb5_princ_name(*princ) == NULL)
    {
	krb5_free_principal(*princ);
	return -1;
    }
    krb5_princ_size(*princ) = 0;
    for (i = 0; i < numparts; i++)
    {
	if (cp + 2 > (CARD8 *)inbuf.data + inbuf.length)
	{
	    krb5_free_principal(*princ);
	    return -2;
	}
	plen = *cp++ << 8;
	plen |= *cp++;
	if (cp + plen > (CARD8 *)inbuf.data + inbuf.length)
	{
	    krb5_free_principal(*princ);
	    return -2;
	}
	pdata = (CARD8 *)malloc(plen);
	if (pdata == NULL)
	{
	    krb5_free_principal(*princ);
	    return -1;
	}
	krb5_princ_component(*princ, i)->data = (char *)pdata;
	krb5_princ_component(*princ, i)->length = plen;
	memcpy(pdata, cp, plen);
	cp += plen;
	krb5_princ_size(*princ)++;
    }
    return 0;
}
#endif /* K5AUTH */

#endif /* FWD_X */
