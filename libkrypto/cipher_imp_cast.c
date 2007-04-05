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

#ifndef NOENCRYPTION
#ifdef CIPHER_CAST5

#include "krypto.h"
#include "cipher_imp_cast.h"

#include "../cast/cast.c"

/* GLUE ROUTINES */

static void *
cipher_imp_cast_init (key, klen)
  unsigned char *key;
  unsigned klen;
{
  CastKeySched *ctxt;

  ctxt = (CastKeySched *) malloc (sizeof (CastKeySched));
  if (ctxt == 0) return 0;

  /* Hmm, I think we wired this in a bit close to the metal... */
#ifdef OPENSSL_CAST
  CAST_set_key(ctxt, klen, key);
#elif defined(TOMCRYPT_CAST)
  cast5_setup(key, klen > 16 ? 16 : klen, klen > 10 ? 16 : 12, ctxt);
#else /* OPENSSL_CAST */
  ctxt->ksize = klen > 16 ? 16 : klen;
  cast5_key_sched (ctxt, key, ctxt->ksize);
#endif /* OPENSSL_CAST */
  return (void *) ctxt;
}

static void
cipher_imp_cast_finish (c)
  void *c;
{
  if (c)
  {
    CastKeySched *ctxt = (CastKeySched *) c;
    memset (ctxt, 0, sizeof (CastKeySched));
    free (c);
  }
}

static void
cipher_imp_cast_crypt (ctxt, data, len, mode)
     CastKeySched *ctxt;
     unsigned char * data;
     unsigned len;
     unsigned mode;
{
  if (mode == CIPHER_STATE_ENCRYPT)
    cast_ecb_crypt ((uint32p) data, ctxt, 0);
  else
    cast_ecb_crypt ((uint32p) data, ctxt, 1);
}


cipher_desc CAST5_ECBdesc =
{
  CIPHER_ID_CAST5_ECB,
  "CAST5_ECB",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_ECB,
  8,
  5,
  8,
  cipher_imp_cast_init,
  cipher_imp_cast_crypt,
  cipher_imp_cast_finish
};

cipher_desc CAST5_CBCdesc =
{
  CIPHER_ID_CAST5_CBC,
  "CAST5_CBC",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CBC,
  8,
  5,
  8,
  cipher_imp_cast_init,
  cipher_imp_cast_crypt,
  cipher_imp_cast_finish
};

cipher_desc CAST5_CFB64desc =
{
  CIPHER_ID_CAST5_CFB64,
  "CAST5_CFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CFB64,
  8,
  5,
  1,
  cipher_imp_cast_init,
  cipher_imp_cast_crypt,
  cipher_imp_cast_finish
};

cipher_desc CAST5_OFB64desc =
{
  CIPHER_ID_CAST5_OFB64,
  "CAST5_OFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_OFB64,
  8,
  5,
  1,
  cipher_imp_cast_init,
  cipher_imp_cast_crypt,
  cipher_imp_cast_finish
};

#endif
#endif
