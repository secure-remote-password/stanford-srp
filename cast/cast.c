/*
 * Copyright (c) 1997-2003  The Stanford SRP Authentication Project
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
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
 *
 * In addition, the following conditions apply:
 *
 * 1. Any software that incorporates the SRP authentication technology
 *    must display the following acknowlegment:
 *    "This product uses the 'Secure Remote Password' cryptographic
 *     authentication system developed by Tom Wu (tjw@CS.Stanford.EDU)."
 *
 * 2. Any software that incorporates all or part of the SRP distribution
 *    itself must also display the following acknowledgment:
 *    "This product includes software developed by Tom Wu and Eugene
 *     Jhong for the SRP Distribution (http://srp.stanford.edu/srp/)."
 *
 * 3. Redistributions in source or binary form must retain an intact copy
 *    of this copyright notice and list of conditions.
 */

#if defined(CAST_ENCRYPTION) || defined(CAST_EXPORT_ENCRYPTION) || defined(CIPHER_CAST5)

#include "cast.h"

#ifdef OPENSSL_CAST

/* Glue together OpenSSL's CAST with our API */
void
cast_ecb_crypt(data, sched, mode)
     CAST_LONG * data;
     CastKeySched * sched;
     int mode;
{
  if(mode == 0)
    CAST_encrypt(data, sched);
  else
    CAST_decrypt(data, sched);
}

#elif defined(TOMCRYPT_CAST)

/* Glue together LibTomCrypt's CAST5 with our API */
void
cast_ecb_crypt(data, sched, mode)
     uint32p data;
     CastKeySched * sched;
     int mode;
{
  unsigned char buf[8];
  uint32 t;

  t = data[0];
  buf[3] = t & 0xff;
  buf[2] = (t >>= 8) & 0xff;
  buf[1] = (t >>= 8) & 0xff;
  buf[0] = (t >> 8) & 0xff;
  t = data[1];
  buf[7] = t & 0xff;
  buf[6] = (t >>= 8) & 0xff;
  buf[5] = (t >>= 8) & 0xff;
  buf[4] = (t >> 8) & 0xff;

  if(mode == 0)
    cast5_ecb_encrypt(buf, buf, sched);
  else
    cast5_ecb_decrypt(buf, buf, sched);

  data[0] = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
  data[1] = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
}

void
cast_ecb_encrypt(out, in, sched, mode)
     unsigned char * out;
     unsigned char * in;
     CastKeySched * sched;
     int mode;
{
  if(mode == 0)
    cast5_ecb_encrypt(in, out, sched);
  else
    cast5_ecb_decrypt(in, out, sched);
}

#else

#error "CAST-128 implementation not included.  Please contact Tom Wu (tjw@cs.stanford.edu) for a copy."

#endif /* !TOMCRYPT_CAST && !OPENSSL_CAST */

#endif /* CAST_ENCRYPTION || CAST_EXPORT_ENCRYPTION || CIPHER_CAST5 */
