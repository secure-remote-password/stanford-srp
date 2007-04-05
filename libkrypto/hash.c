/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |   Author: Eugene Jhong                                                     |
 |                                                                            |
 +----------------------------------------------------------------------------*/

/*
 * Copyright (c) 1997 Stanford University
 *
 * Permission to use, copy, modify, distribute, and sell this software and
 * its documentation for any purpose is hereby granted without fee, provided
 * that the above copyright notices and this permission notice appear in
 * all copies of the software and related documentation.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL STANFORD BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "krypto.h"
#include "krypto_locl.h"

#ifdef HASH_MD5
extern hash_desc MD5desc;
#endif
#ifdef HASH_SHA
extern hash_desc SHAdesc;
#endif

static hash_desc *allHashs [] =
{
#ifdef HASH_SHA
  &SHAdesc,
#endif
#ifdef HASH_MD5
  &MD5desc,
#endif
  0
};

#define NHASHS (sizeof (allHashs) / sizeof (hash_desc *))
static unsigned char hashlist[NHASHS] = "";


unsigned char *
hash_getlist()
{
  hash_desc **descp;
  unsigned char *s;

  if(*hashlist == '\0') {
    for(s = hashlist, descp = allHashs; *descp; ++descp, ++s)
      *s = (*descp)->id;
    *s = '\0';
  }
  return hashlist;
}

hash_desc *
hash_getdescbyname (str)
  char *str;
{
  hash_desc **descp;

  for (descp = allHashs; *descp; ++descp)
    if(strcasecmp ((*descp)->name, str) == 0) return *descp;
  return 0;
}

hash_desc *
hash_getdescbyid (id)
  unsigned char id;
{
  hash_desc **descp;

  for (descp = allHashs; *descp; ++descp)
    if ((*descp)->id == id) return *descp;
  return 0;
}

int 
hash_supported (list, id)
  unsigned char *list;
  unsigned char id;
{
  int i;
  
  for (i = 0; i < strlen (list); i++)
    if (list[i] == id) return 1;

  return 0;
}

hash *
hash_new (hd)
  hash_desc *hd;
{
  hash *newhash;

  if ((newhash = (hash *) malloc (sizeof (hash))) == 0) return 0;

  newhash->hash = hd;
  newhash->context = (hd->new) ();

  return newhash;
}

void
hash_delete (h)
  hash *h;
{
  (h->hash->delete) (h->context);
  free (h);
}

unsigned
hash_getoutlen (h)
  hash *h;
{
  return h->hash->outlen;
}

void
hash_init (h)
  hash *h;
{
  h->hash->init (h->context);
}

void
hash_update (h, data, len)
  hash *h;
  unsigned char *data;
  unsigned len;
{
  h->hash->update (h->context, data, len);
}

void
hash_final (h, out)
  hash *h;
  unsigned char *out;
{
  h->hash->final (h->context, out);
}
