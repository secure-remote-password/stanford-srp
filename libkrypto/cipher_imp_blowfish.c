/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |                                                                            |
 |      This code is based on code in Eric Young's blowfish implementation    |
 |   and was slightly modified to conform with libkrypto's interface.         |
 |   See copyright notice below.                                              |
 |                                                                            |
 +----------------------------------------------------------------------------*/

/* This is now just an interface to underlying Blowfish implementations */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef NOENCRYPTION
#ifdef CIPHER_BLOWFISH

#include <stdio.h>
#include "krypto.h"
#include "cipher_imp_blowfish.h"

static void *
cipher_imp_blowfish_init (key, klen)
  unsigned char *key;
  unsigned klen;
{
  BF_KEY *bf_key;

  if (klen > 56) klen = 56;

  bf_key = (BF_KEY *) malloc (sizeof (BF_KEY));
  if (bf_key == 0) return 0;

  BF_set_key (bf_key, klen, key);
  return (void *) bf_key;
}

static void
cipher_imp_blowfish_finish (c)
  void *c;
{
  if (c)
  {
    BF_KEY *bf_key = (BF_KEY *) c;
    memset (bf_key, 0, sizeof (BF_KEY));
    free (c);
  }
}

static void
cipher_imp_blowfish_crypt (bf_key, data, len, mode)
     BF_KEY *bf_key;
     unsigned char * data;
     unsigned len;
     unsigned mode;
{
  if(mode)
    BF_encrypt((BF_LONG *) data, bf_key);
  else
    BF_decrypt((BF_LONG *) data, bf_key);
}

cipher_desc BF_ECBdesc =
{
  CIPHER_ID_BLOWFISH_ECB,
  "BLOWFISH_ECB",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_ECB,
  BF_BLOCK,
  1,
  BF_BLOCK,
  cipher_imp_blowfish_init,
  cipher_imp_blowfish_crypt,
  cipher_imp_blowfish_finish
};

cipher_desc BF_CBCdesc =
{
  CIPHER_ID_BLOWFISH_CBC,
  "BLOWFISH_CBC",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CBC,
  BF_BLOCK,
  1,
  BF_BLOCK,
  cipher_imp_blowfish_init,
  cipher_imp_blowfish_crypt,
  cipher_imp_blowfish_finish
};

cipher_desc BF_CFB64desc =
{
  CIPHER_ID_BLOWFISH_CFB64,
  "BLOWFISH_CFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CFB64,
  BF_BLOCK,
  1,
  1,
  cipher_imp_blowfish_init,
  cipher_imp_blowfish_crypt,
  cipher_imp_blowfish_finish
};

cipher_desc BF_OFB64desc =
{
  CIPHER_ID_BLOWFISH_OFB64,
  "BLOWFISH_OFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_OFB64,
  BF_BLOCK,
  1,
  1,
  cipher_imp_blowfish_init,
  cipher_imp_blowfish_crypt,
  cipher_imp_blowfish_finish
};

#endif
#endif
