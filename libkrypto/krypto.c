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
 |   Author: Eugene Jhong                                                     |
 |                                                                            |
 +----------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "krypto.h"
#include "krypto_locl.h"

krypto_context *
krypto_new (cid, hid, key, keylen, iv, ivlen, seq, state)
  unsigned cid;
  unsigned hid;
  unsigned char *key;
  unsigned keylen;
  unsigned char *iv;
  unsigned ivlen;
  unsigned char *seq;
  unsigned state;
{
  krypto_context *cc;
  cipher_desc *cd;
  hash_desc *hd;

  if ((cc = (krypto_context *) malloc (sizeof (krypto_context))) == 0)
    return 0;

  if ((cc->key = (unsigned char *) malloc (keylen)) == 0)
    return 0;

  cc->keylen = keylen;
  memcpy (cc->key, key, keylen);

  cc->state = state;
  n2l (seq, cc->seqnum);

  if ((cd = cipher_getdescbyid (cid)) == 0) return 0;
  cc->c = cipher_new (cd);

  if (state) cipher_initencrypt (cc->c, key, keylen);
  else cipher_initdecrypt (cc->c, key, keylen);

  if (iv) cipher_setiv (cc->c, iv, ivlen);

  if ((hd = hash_getdescbyid (hid)) == 0) return 0;
  cc->h = hash_new (hd);

  return cc;
}

void 
krypto_delete (cc)
  krypto_context *cc;
{
  if (!cc) return;
  cipher_delete (cc->c);
  hash_delete (cc->h);
  if (cc->key) { memset (cc->key, 0, cc->keylen); free (cc->key); }
  free (cc);
}

int
krypto_msg_getaddlen (cc)
  krypto_context *cc;
{
  /* return added length of private message which is:
       pvno (4) + msgtype (4) + confounder_length + checksum_length +
       length (4) + sequence number (4) + pad (at least blklen) */

  return 24 + hash_getoutlen (cc->h) + 8 + cipher_getblklen (cc->c);
}

int
krypto_msg_safe (cc, in, out, len)
  krypto_context *cc;
  unsigned char *in;
  unsigned char *out;
  int len;
{
  uint32 pvno = KRYPTO_PROT_VERSION;
  uint32 msgtype = KRYPTO_MSG_SAFE;
  unsigned char *mark;
  unsigned hashlen = hash_getoutlen (cc->h);

  if (cc->state)
  {
    /* set protocol version and message type */

    l2n(pvno,out);
    l2n(msgtype,out);

    /* set length, user data and sequence number */

    mark = out;
    l2n(len,out);
    memcpy (out, in, len); out += len;
    l2n (cc->seqnum,out);
    cc->seqnum = (uint32) (((uint32) cc->seqnum) + 1);

    /* compute keyed inner hash of length, user data and sequence number */

    hash_init (cc->h);
    hash_update (cc->h, cc->key, cc->keylen);
    hash_update (cc->h, mark, len + 8);
    hash_final (cc->h, out);

    /* compute keyed outer hash of inner hash */

    hash_init (cc->h);
    hash_update (cc->h, cc->key, cc->keylen);
    hash_update (cc->h, out, hashlen);
    hash_final (cc->h, out);

    /* return length */

    return len + 16 + hashlen;
  }
  else
  {
    uint32 outlen;
    uint32 seqnum;
    unsigned char checksum[512];

    if (len < 16 + hashlen) return -1;

    /* get protocol version and message type */

    n2l(in,pvno);
    n2l(in,msgtype);

    if ((pvno != KRYPTO_PROT_VERSION) || (msgtype != KRYPTO_MSG_SAFE))
      return -1;

    /* get length and verify if matches packet length */

    mark = in;
    n2l(in,outlen);

    if (outlen != len - 16 - hashlen) return -1;

    /* computer inner hash, outer hash and compare  */

    hash_init (cc->h);
    hash_update (cc->h, cc->key, cc->keylen);
    hash_update (cc->h, mark, outlen + 8);
    hash_final (cc->h, checksum);

    hash_init (cc->h);
    hash_update (cc->h, cc->key, cc->keylen);
    hash_update (cc->h, checksum, hashlen);
    hash_final (cc->h, checksum);

    if (memcmp (checksum, in+outlen+4, hashlen)) return -1;

    /* get sequence number and compare */

    mark = in; in += outlen;
    n2l(in,seqnum);
    if (seqnum != (uint32) cc->seqnum) return -1;
    cc->seqnum = (uint32) (((uint32) cc->seqnum) + 1);

    /* copy message and return length */

    memcpy (out, mark, outlen);
    return outlen;
  }
}

int
krypto_msg_priv (cc, in, out, len)
  krypto_context *cc;
  unsigned char *in;
  unsigned char *out;
  int len;
{
  uint32 pvno = KRYPTO_PROT_VERSION;
  uint32 msgtype = KRYPTO_MSG_PRIV;
  unsigned char *mark;
  unsigned conflen = 8;
  unsigned hashlen = hash_getoutlen (cc->h);

  /* at least give safe encoding if no cipher */

  if (cc->c->cipher->id == CIPHER_ID_NONE)
    return (krypto_msg_safe (cc, in, out, len));

  if (cc->state)
  {
    unsigned char confounder[512];
    uint32 cryptlen = cipher_getoutlen (cc->c, len+hashlen+conflen+8);

    /* initialize confounder */

    krypto_rand_conf (confounder, conflen);

    /* set protocol version and message type */

    l2n(pvno,out);
    l2n(msgtype,out);

    /* initialize packet to all zeros */

    mark = out;
    memset (out, 0, cryptlen);

    /* set confounder, length, user data, and sequence number */
    /* leave room for checksum */

    memcpy (out, confounder, conflen); out += conflen;
    out += hashlen;
    l2n(len,out);
    memcpy (out, in, len); out += len;
    l2n (cc->seqnum,out);
    cc->seqnum = (uint32) (((uint32) cc->seqnum) + 1);

    /* set checksum on confounder, length, user data, zeroed checksum */
    /* and sequence number */

    hash_init (cc->h);
    hash_update (cc->h, mark, len+hashlen+conflen+8);
    hash_final (cc->h, mark + conflen);

    /* encrypt confounder, checksum, length, user-data and sequence number */

    cipher_crypt (cc->c, mark, mark, cryptlen);

    /* return length */

    return cryptlen + 8;
  }
  else
  {
    uint32 outlen;
    unsigned char checksum[512];
    uint32 seqnum;

    if (len < 16 + hashlen + conflen) return -1;

    /* get protocol version and message type */

    n2l(in,pvno);
    n2l(in,msgtype);

    if ((pvno != KRYPTO_PROT_VERSION) || (msgtype != KRYPTO_MSG_PRIV))
      return -1;

    len -= 8;

    /* verify that data was properly padded for this cipher */

    if (len != cipher_getoutlen (cc->c, len)) return -1;

    /* decrypt data */

    cipher_crypt (cc->c, in, in, len);

    /* get confounder, checksum, and user data length */

    mark = in;
    in += conflen;
    memcpy (checksum, in, hashlen);
    memset (in, 0, hashlen);
    in += hashlen;
    n2l(in,outlen);

    /* verify length is correct */

    if (outlen > len - 8 - conflen - hashlen) return -1;

    /* compute checksum and verify */

    hash_init (cc->h);
    hash_update (cc->h, mark, outlen+hashlen+conflen+8);
    hash_final (cc->h, mark+conflen);

    if (memcmp (checksum, mark+conflen, hashlen)) return -1;

    mark = in;
    in += outlen;

    /* get sequence number and verify */

    n2l(in,seqnum);
    if (seqnum != (uint32) cc->seqnum) return -1;
    cc->seqnum = (uint32) (((uint32) cc->seqnum) + 1);

    /* copy message and return length */

    memcpy (out, mark, outlen);
    return outlen;
  }
}
