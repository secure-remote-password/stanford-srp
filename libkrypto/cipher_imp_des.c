/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |                                                                            |
 |      This code is based on code in Eric Young's libdes-4.01 code           |
 |   and was slightly modified to conform with libkrypto's interface.         |
 |   See copyright notice below.                                              |
 |                                                                            |
 +----------------------------------------------------------------------------*/

/* This now interfaces with various crypto library DES implementations */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef NOENCRYPTION
#ifdef CIPHER_DES

#include "krypto.h"
#include "cipher_imp_des.h"

/* GLUE ROUTINES */

static void *
cipher_imp_des_init (key, klen)
  unsigned char *key;
  unsigned klen;
{
  des_key_schedule *des_key;

  if (klen < 8) return 0;

  des_key = (des_key_schedule *) malloc (sizeof (des_key_schedule));
  if (des_key == 0) return 0;

  des_key_sched((des_cblock *) key, *des_key);
  return (void *) des_key;
}

static void
cipher_imp_des_finish (c)
  void *c;
{
  if (c)
  {
    des_key_schedule *des_key = (des_key_schedule *) c;
    memset (des_key, 0, sizeof (des_key_schedule));
    free (c);
  }
}

static void
cipher_imp_des_crypt (des_key, data, len, state)
     des_key_schedule *des_key;
     unsigned char * data;
     unsigned len;
     unsigned state;
{
  unsigned char tmp[8], *c;
  DES_LONG l[2];

  /* change to characters loaded little endian */

  l[0] = ((DES_LONG *) data)[0];
  l[1] = ((DES_LONG *) data)[1];

  c = tmp;
  l2n (l[0], c);
  l2n (l[1], c);

#ifdef CRYPTOLIB_DES
  block_cipher(*des_key, tmp, !state);
#else /* libdes || OPENSSL_DES */
  des_ecb_encrypt(tmp, tmp, *des_key, state);
#endif

  /* change back */
  c = tmp;
  n2l (c, l[0]);
  n2l (c, l[1]);

  ((DES_LONG *) data)[0] = l[0];
  ((DES_LONG *) data)[1] = l[1];
}


cipher_desc DES_ECBdesc =
{
  CIPHER_ID_DES_ECB,
  "DES_ECB",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_ECB,
  8,
  8,
  8,
  cipher_imp_des_init,
  cipher_imp_des_crypt,
  cipher_imp_des_finish
};

cipher_desc DES_CBCdesc =
{
  CIPHER_ID_DES_CBC,
  "DES_CBC",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CBC,
  8,
  8,
  8,
  cipher_imp_des_init,
  cipher_imp_des_crypt,
  cipher_imp_des_finish
};

cipher_desc DES_CFB64desc =
{
  CIPHER_ID_DES_CFB64,
  "DES_CFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CFB64,
  8,
  8,
  1,
  cipher_imp_des_init,
  cipher_imp_des_crypt,
  cipher_imp_des_finish
};

cipher_desc DES_OFB64desc =
{
  CIPHER_ID_DES_OFB64,
  "DES_OFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_OFB64,
  8,
  8,
  1,
  cipher_imp_des_init,
  cipher_imp_des_crypt,
  cipher_imp_des_finish
};

typedef des_key_schedule DES3_CTX[3];
typedef DES3_CTX *DES3_CTXP;

#define KEY1(P) ((*P)[0])
#define KEY2(P) ((*P)[1])
#define KEY3(P) ((*P)[2])

static void *
cipher_imp_des3_init (key, klen)
  unsigned char *key;
  unsigned klen;
{
  DES3_CTXP ctxt;

  if (klen < 16) return 0;

  ctxt = (DES3_CTXP) malloc (sizeof (DES3_CTX));
  if (ctxt == (DES3_CTXP) 0) return (void *) ctxt;

  des_key_sched((des_cblock *) key, KEY1(ctxt));
  des_key_sched((des_cblock *) (key+8), KEY2(ctxt));
  if (klen >= 24)
    des_key_sched((des_cblock *) (key+16), KEY3(ctxt));
  else
    des_key_sched((des_cblock *) key, KEY3(ctxt));

  return (void *) ctxt;
}

static void
cipher_imp_des3_finish (c)
  void *c;
{
  if (c)
  {
    DES3_CTXP ctxt = (DES3_CTXP) c;
    memset (ctxt, 0, sizeof (DES3_CTX));
    free (c);
  }
}

static void
cipher_imp_des3_crypt (ctxt, data, len, state)
     DES3_CTXP ctxt;
     unsigned char * data;
     unsigned len;
     unsigned state;
{
  unsigned char tmp[8], *c;
  DES_LONG l[2];

  /* change to characters loaded little endian */

  l[0] = ((DES_LONG *) data)[0];
  l[1] = ((DES_LONG *) data)[1];

  c = tmp;
  l2n (l[0], c);
  l2n (l[1], c);

#ifdef OPENSSL_DES
  des_ecb3_encrypt(tmp, tmp, KEY1(ctxt), KEY2(ctxt), KEY3(ctxt), state);
#elif defined(CRYPTOLIB_DES)
  /* Urg - CryptoLib's triple_block_cipher does EEE mode.
     We'll do DES_EDE3 ourselves. */
  if (state == CIPHER_STATE_ENCRYPT) {
    block_cipher(KEY1(ctxt), tmp, 0);
    block_cipher(KEY2(ctxt), tmp, 1);
    block_cipher(KEY3(ctxt), tmp, 0);
  }
  else {
    block_cipher(KEY3(ctxt), tmp, 1);
    block_cipher(KEY2(ctxt), tmp, 0);
    block_cipher(KEY1(ctxt), tmp, 1);
  }
#else /* libdes */
  /* Ack - libdes seems to have only 2-key 3DES, if at all.
     We'll do DES_EDE3 ourselves. */
  if (state == CIPHER_STATE_ENCRYPT) {
    des_ecb_encrypt(tmp, tmp, KEY1(ctxt), 1);
    des_ecb_encrypt(tmp, tmp, KEY2(ctxt), 0);
    des_ecb_encrypt(tmp, tmp, KEY3(ctxt), 1);
  }
  else {
    des_ecb_encrypt(tmp, tmp, KEY3(ctxt), 0);
    des_ecb_encrypt(tmp, tmp, KEY2(ctxt), 1);
    des_ecb_encrypt(tmp, tmp, KEY1(ctxt), 0);
  }
#endif

  /* change back */
  c = tmp;
  n2l (c, l[0]);
  n2l (c, l[1]);

  ((DES_LONG *) data)[0] = l[0];
  ((DES_LONG *) data)[1] = l[1];
}


cipher_desc DES3_ECBdesc =
{
  CIPHER_ID_DES3_ECB,
  "DES3_ECB",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_ECB,
  8,
  16,
  8,
  cipher_imp_des3_init,
  cipher_imp_des3_crypt,
  cipher_imp_des3_finish
};

cipher_desc DES3_CBCdesc =
{
  CIPHER_ID_DES3_CBC,
  "DES3_CBC",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CBC,
  8,
  16,
  8,
  cipher_imp_des3_init,
  cipher_imp_des3_crypt,
  cipher_imp_des3_finish
};

cipher_desc DES3_CFB64desc =
{
  CIPHER_ID_DES3_CFB64,
  "DES3_CFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_CFB64,
  8,
  16,
  1,
  cipher_imp_des3_init,
  cipher_imp_des3_crypt,
  cipher_imp_des3_finish
};

cipher_desc DES3_OFB64desc =
{
  CIPHER_ID_DES3_OFB64,
  "DES3_OFB64",
  CIPHER_TYPE_BLOCK,
  CIPHER_MODE_OFB64,
  8,
  16,
  1,
  cipher_imp_des3_init,
  cipher_imp_des3_crypt,
  cipher_imp_des3_finish
};

#endif
#endif
