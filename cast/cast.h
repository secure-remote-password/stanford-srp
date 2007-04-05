/*
 * Copyright (c) 1997-2005  The Stanford SRP Authentication Project
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

#ifndef _CAST_H_
#define _CAST_H_

#if     !defined(P)
#ifdef  __STDC__
#define P(x)    x
#else
#define P(x)    ()
#endif
#endif

typedef unsigned int uint32;	/* Must be 32 bits */
typedef uint32 * uint32p;
typedef unsigned char uint8;
typedef uint8 * uint8p;

#ifdef OPENSSL_CAST

#include <openssl/cast.h>

/* Macros and typedefs to make calls to our CAST API go to OpenSSL */
typedef CAST_KEY CastKeySched;
#define cast5_40_key_sched(S,K) CAST_set_key(S,5,K)
#define cast5_64_key_sched(S,K) CAST_set_key(S,8,K)
#define cast5_80_key_sched(S,K) CAST_set_key(S,10,K)
#define cast128_key_sched(S,K) CAST_set_key(S,16,K)
#define cast_ecb_encrypt(O,I,S,M) CAST_ecb_encrypt(I,O,S,!(M))
/* #define cast_ecb_crypt(D,S,M) */
extern void cast_ecb_crypt P((CAST_LONG *, CastKeySched *, int));

#elif defined(TOMCRYPT_CAST)

#include "tomcrypt.h"

/* Macros and typedefs to make calls to our CAST API go to LibTomCrypt */
typedef symmetric_key CastKeySched;
#define cast5_40_key_sched(S,K) cast5_setup(K,5,12,S)
#define cast5_64_key_sched(S,K) cast5_setup(K,8,12,S)
#define cast5_80_key_sched(S,K) cast5_setup(K,10,12,S)
#define cast128_key_sched(S,K) cast5_setup(K,16,16,S)
extern void cast_ecb_encrypt P((unsigned char *, unsigned char *, CastKeySched *, int));
extern void cast_ecb_crypt P((uint32p, CastKeySched *, int));

#else /* !TOMCRYPT_CAST && !OPENSSL_CAST */

#error "CAST-128 implementation not included.  Please contact Tom Wu (tjw@cs.stanford.edu) for a copy."

#endif /* OPENSSL_CAST */

#endif /* _CAST_H_ */
