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

/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |   Authors: Eugene Jhong and Thomas Wu                                      |
 |                                                                            |
 +----------------------------------------------------------------------------*/

#ifndef KRYPTO_H
#define KRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#if     !defined(_PROTO)
#ifdef  __STDC__
#define _PROTO(x)    x
#else
#define _PROTO(x)    ()
#endif
#endif

#if defined(WIN32) && defined(_USRDLL) && defined(KRYPTO_EXPORTS)
#define EXTERN extern _declspec(dllexport)
#else /* WIN32 && _USRDLL */
#define EXTERN extern
#endif /* WIN32 && _USRDLL */

/*-----------------+
 | CIPHER ROUTINES |
 +-----------------*/

#define CIPHER_TYPE_BLOCK	1
#define CIPHER_TYPE_STREAM	2

#define CIPHER_MODE_DEFAULT	1
#define CIPHER_MODE_ECB		2
#define CIPHER_MODE_CBC		3
#define CIPHER_MODE_CFB64	4
#define CIPHER_MODE_OFB64	5

#define CIPHER_STATE_ENCRYPT	1
#define CIPHER_STATE_DECRYPT	0

#define CIPHER_ID_NONE			1
#define CIPHER_ID_BLOWFISH_ECB		2
#define CIPHER_ID_BLOWFISH_CBC		3
#define CIPHER_ID_BLOWFISH_CFB64	4
#define CIPHER_ID_BLOWFISH_OFB64	5
#define CIPHER_ID_CAST5_ECB		6
#define CIPHER_ID_CAST5_CBC		7
#define CIPHER_ID_CAST5_CFB64		8
#define CIPHER_ID_CAST5_OFB64		9
#define CIPHER_ID_DES_ECB		10
#define CIPHER_ID_DES_CBC		11
#define CIPHER_ID_DES_CFB64		12
#define CIPHER_ID_DES_OFB64		13
#define CIPHER_ID_DES3_ECB		14
#define CIPHER_ID_DES3_CBC		15
#define CIPHER_ID_DES3_CFB64		16
#define CIPHER_ID_DES3_OFB64		17
#define CIPHER_ID_IDEA_ECB		18	/* unsupported */
#define CIPHER_ID_IDEA_CBC		19	/* unsupported */
#define CIPHER_ID_IDEA_CFB64		20	/* unsupported */
#define CIPHER_ID_IDEA_OFB64		21	/* unsupported */
#define CIPHER_ID_ARCFOUR		22	/* unsupported */

typedef struct _cipher_desc
{
  unsigned id;
  char *name;
  unsigned type;
  unsigned mode;
  unsigned blklen;
  unsigned keylen;
  unsigned inblklen;
  void *(*new) _PROTO((unsigned char *, unsigned));
  void (*crypt) _PROTO((void *, unsigned char *, unsigned, unsigned));
  void (*delete) _PROTO((void *));
} cipher_desc;

typedef struct _cipher
{
  cipher_desc *cipher;
  void *context;
  unsigned state;
  unsigned char *iv;
  int num;
} cipher;

EXTERN unsigned char *cipher_getlist _PROTO(());
EXTERN cipher_desc *cipher_getdescbyid _PROTO((unsigned char));
EXTERN cipher_desc *cipher_getdescbyname _PROTO((char *));
EXTERN int cipher_supported _PROTO((unsigned char *, unsigned char));

EXTERN cipher *cipher_new _PROTO((cipher_desc *));
EXTERN void cipher_delete _PROTO((cipher *));
EXTERN unsigned cipher_getminkeylen _PROTO((cipher *));
EXTERN unsigned cipher_getblklen _PROTO((cipher *));
EXTERN unsigned long cipher_getoutlen _PROTO((cipher *, unsigned long));
EXTERN int cipher_setiv _PROTO((cipher *, unsigned char *, unsigned));
EXTERN int cipher_initencrypt _PROTO((cipher *, unsigned char *, unsigned));
EXTERN int cipher_initdecrypt _PROTO((cipher *, unsigned char *, unsigned));
EXTERN void cipher_crypt _PROTO((cipher *, unsigned char *, unsigned char *,
  unsigned long));


/*---------------+
 | HASH ROUTINES |
 +---------------*/

#define HASH_ID_MD5	1
#define HASH_ID_SHA	2

typedef struct _hash_desc
{
  unsigned id;
  char *name;
  unsigned outlen;
  void *(*new) _PROTO(());
  void (*init) _PROTO((void *));
  void (*update) _PROTO((void *, unsigned char *, unsigned));
  void (*final) _PROTO((void *, unsigned char *));
  void (*delete) _PROTO((void *));
} hash_desc;

typedef struct _hash
{
  hash_desc *hash;
  void *context;
} hash;

EXTERN unsigned char *hash_getlist();
EXTERN hash_desc *hash_getdescbyid _PROTO((unsigned char));
EXTERN hash_desc *hash_getdescbyname _PROTO((char *));
EXTERN int hash_supported _PROTO((unsigned char *, unsigned char));

EXTERN hash *hash_new _PROTO((hash_desc *));
EXTERN void hash_delete _PROTO((hash *));
EXTERN unsigned hash_getoutlen _PROTO((hash *));
EXTERN void hash_init _PROTO((hash *));
EXTERN void hash_update _PROTO((hash *, unsigned char *, unsigned));
EXTERN void hash_final _PROTO((hash *, unsigned char *));


/*------------------+
 | MESSAGE ROUTINES |
 +------------------*/

#define KRYPTO_PROT_VERSION 1

#define KRYPTO_MSG_SAFE 1
#define KRYPTO_MSG_PRIV 2

#define KRYPTO_ENCODE 1
#define KRYPTO_DECODE 0


typedef struct _krypto_context
{
  unsigned state;
  unsigned seqnum;
  unsigned char *key;
  unsigned keylen;
  cipher *c;
  hash *h;
} krypto_context;


EXTERN krypto_context *krypto_new _PROTO((unsigned cid, unsigned hid,
  unsigned char *key, unsigned keylen, unsigned char *iv, unsigned ivlen,
  unsigned char *seq, unsigned state));
EXTERN void krypto_delete _PROTO((krypto_context *cc));

EXTERN int krypto_msg_getaddlen _PROTO((krypto_context *cc));
EXTERN int krypto_msg_safe _PROTO((krypto_context *cc, unsigned char *in,
  unsigned char *out, int len));
EXTERN int krypto_msg_priv _PROTO((krypto_context *cc, unsigned char *in,
  unsigned char *out, int len));

EXTERN void krypto_random _PROTO((unsigned char *buf, int len));

#ifdef __cplusplus
}
#endif

#endif
