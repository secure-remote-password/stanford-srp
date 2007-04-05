/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |   Authors: Thomas Wu and Eugene Jhong                                      |
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

extern void cipher_crypt_ecb ();
extern void cipher_crypt_cbc ();
extern void cipher_crypt_cfb ();
extern void cipher_crypt_ofb ();

extern cipher_desc NONEdesc;

#ifndef NOENCRYPTION

#ifdef CIPHER_ARCFOUR
extern cipher_desc ARCFOURdesc;
#endif
#ifdef CIPHER_BLOWFISH
extern cipher_desc BF_ECBdesc;
extern cipher_desc BF_CBCdesc;
extern cipher_desc BF_CFB64desc;
extern cipher_desc BF_OFB64desc;
#endif
#ifdef CIPHER_DES
extern cipher_desc DES_ECBdesc;
extern cipher_desc DES_CBCdesc;
extern cipher_desc DES_CFB64desc;
extern cipher_desc DES_OFB64desc;
extern cipher_desc DES3_ECBdesc;
extern cipher_desc DES3_CBCdesc;
extern cipher_desc DES3_CFB64desc;
extern cipher_desc DES3_OFB64desc;
#endif
#ifdef CIPHER_IDEA
extern cipher_desc IDEA_ECBdesc;
extern cipher_desc IDEA_CBCdesc;
extern cipher_desc IDEA_CFB64desc;
extern cipher_desc IDEA_OFB64desc;
#endif
#ifdef CIPHER_CAST5
extern cipher_desc CAST5_ECBdesc;
extern cipher_desc CAST5_CBCdesc;
extern cipher_desc CAST5_CFB64desc;
extern cipher_desc CAST5_OFB64desc;
#endif

#endif

static cipher_desc *allCiphers[] =
{
#ifndef NOENCRYPTION

#ifdef CIPHER_CAST5
  &CAST5_CBCdesc, &CAST5_CFB64desc, &CAST5_OFB64desc, &CAST5_ECBdesc,
#endif
#ifdef CIPHER_DES
  &DES3_CBCdesc, &DES3_CFB64desc, &DES3_OFB64desc, &DES3_ECBdesc,
  &DES_CBCdesc, &DES_CFB64desc, &DES_OFB64desc, &DES_ECBdesc,
#endif
#ifdef CIPHER_BLOWFISH
  &BF_CBCdesc, &BF_CFB64desc, &BF_OFB64desc, &BF_ECBdesc,
#endif
#ifdef CIPHER_IDEA
  &IDEA_CBCdesc, &IDEA_CFB64desc, &IDEA_OFB64desc, &IDEA_ECBdesc,
#endif
#ifdef CIPHER_ARCFOUR
  &ARCFOURdesc,
#endif

#endif

  &NONEdesc,

  0
};


#define NCIPHERS (sizeof (allCiphers) / sizeof (cipher_desc *))
static unsigned char cipherlist[NCIPHERS] = "";


unsigned char *
cipher_getlist()
{
  cipher_desc **descp;
  unsigned char *s;

  if(*cipherlist == '\0') {
    for(s = cipherlist, descp = allCiphers; *descp; ++descp, ++s)
      *s = (*descp)->id;
    *s = '\0';
  }
  return cipherlist;
}

cipher_desc *
cipher_getdescbyname (str)
  char *str;
{
  cipher_desc **descp;

  for (descp = allCiphers; *descp; ++descp)
    if(strcasecmp ((*descp)->name, str) == 0) return *descp;
  return 0;
}

cipher_desc *
cipher_getdescbyid (id)
  unsigned char id;
{
  cipher_desc **descp;

  for (descp = allCiphers; *descp; ++descp)
    if ((*descp)->id == id) return *descp;
  return 0;
}

int
cipher_supported (list, id)
  unsigned char *list;
  unsigned char id;
{
  int i;
  
  for (i = 0; i < strlen (list); i++)
    if (list[i] == id) return 1;

  return 0;
}

cipher *
cipher_new (cd)
  cipher_desc *cd;
{
  cipher *newcipher;

  if ((newcipher = (cipher *) malloc (sizeof (cipher))) == 0)
    return 0;

  if ((newcipher->iv = (unsigned char *) malloc (cd->blklen)) == 0)
    return 0;

  newcipher->cipher = cd;
  newcipher->context = 0;

  return newcipher;
}

void
cipher_delete (c)
  cipher *c;
{
  (c->cipher->delete) (c->context);
  memset (c->iv, 0, c->cipher->blklen);
  free (c->iv);
  free (c);
}

unsigned
cipher_getminkeylen (c)
  cipher *c;
{
  return c->cipher->keylen;
}

unsigned
cipher_getblklen (c)
  cipher *c;
{
  return c->cipher->blklen;
}

unsigned long
cipher_getoutlen (c, inlen)
  cipher *c;
  unsigned long inlen;
{
  return ((inlen + c->cipher->inblklen - 1) / c->cipher->inblklen) *
    c->cipher->inblklen;
}

int
cipher_setiv (c, iv, len)
  cipher *c;
  unsigned char *iv;
  unsigned len;
{
  if (len != c->cipher->blklen) return -1;
  memcpy (c->iv, iv, len);
  return 0;
}

int
cipher_initencrypt (c, key, klen)
  cipher *c;
  unsigned char *key;
  unsigned klen;
{
  if (c->context != 0) (c->cipher->delete) (c->context);

  c->state = CIPHER_STATE_ENCRYPT;
  c->num = 0;
  memset (c->iv, 0, c->cipher->blklen);

  c->context = (c->cipher->new) (key, klen);
  if (c->context == NULL) return -1;
  else return 0;
}

int
cipher_initdecrypt (c, key, klen)
  cipher *c;
  unsigned char *key;
  unsigned klen;
{
  if (c->context != 0) (c->cipher->delete) (c->context);

  c->state = CIPHER_STATE_DECRYPT;
  c->num = 0;
  memset (c->iv, 0, c->cipher->blklen);

  c->context = (c->cipher->new) (key, klen);  
  if (c->context == NULL) return -1;
  else return 0;
}

void
cipher_crypt (c, in, out, len)
  cipher *c;
  unsigned char *in;
  unsigned char *out;
  unsigned long len;
{
  switch (c->cipher->type)
  {
  case CIPHER_TYPE_STREAM:
   
    memcpy (out, in, len);
    c->cipher->crypt (c->context, out, len, c->state);
    break;

  case CIPHER_TYPE_BLOCK:

    switch (c->cipher->mode)
    {
    case CIPHER_MODE_ECB: cipher_crypt_ecb (c, in, out, len); break;
    case CIPHER_MODE_CBC: cipher_crypt_cbc (c, in, out, len); break;
    case CIPHER_MODE_CFB64: cipher_crypt_cfb (c, in, out, len); break;
    case CIPHER_MODE_OFB64: cipher_crypt_ofb (c, in, out, len); break;
    }
    break;

  default:

    break;
  }
}
