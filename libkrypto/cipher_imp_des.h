/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |                                                                            |
 |      This code is based on code in Eric Young's libdes-4.01 distribution   |
 |   and was slightly modified to conform with libkrypto's interface.         |
 |   See copyright notice below.                                              |
 |                                                                            |
 +----------------------------------------------------------------------------*/

/* This now interfaces with various crypto library DES implementations */

#ifndef NOENCRYPTION
#ifdef CIPHER_DES

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "krypto_locl.h"

#ifdef OPENSSL_DES

#include <openssl/des.h>

#elif defined(CRYPTOLIB_DES)

#include "libcrypt.h"

/* CryptoLib uses unsigned char[] for stuff */
/*typedef unsigned char des_cblock[8];*/
typedef unsigned char des_cblock;	/* Fix type errors */
typedef unsigned char des_key_schedule[128];
typedef unsigned long DES_LONG;

#define des_key_sched key_setup

#else /* libdes */

#include <des.h>

typedef unsigned long DES_LONG;

#endif

#ifdef  __cplusplus
}
#endif

#endif
#endif
