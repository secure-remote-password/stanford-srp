/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |   Author: Eugene Jhong                                                     |
 |                                                                            |
 +----------------------------------------------------------------------------*/

#include "krypto_locl.h"

/* Make different crypto libraries' MD5 all look uniform to libkrypto. */

#ifdef OPENSSL_MD5
# include <openssl/md5.h>
#elif defined(TOMCRYPT_MD5)
# include "tomcrypt.h"

typedef hash_state MD5_CTX;
# define MD5_Init md5_init
# define MD5_Update md5_process
# define MD5_Final(X,Y) md5_done(Y,X)
#elif defined(CRYPTOLIB_MD5)
# include "libcrypt.h"

# define MD5_Init MD5Init
# define MD5_Update MD5Update
# define MD5_Final MD5Final
#endif
