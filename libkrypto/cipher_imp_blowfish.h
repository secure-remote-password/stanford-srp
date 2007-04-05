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

#ifndef NOENCRYPTION
#ifdef CIPHER_BLOWFISH

#include "krypto_locl.h"

#ifdef OPENSSL_BLOWFISH
#include <openssl/blowfish.h>
#endif

#endif
#endif
