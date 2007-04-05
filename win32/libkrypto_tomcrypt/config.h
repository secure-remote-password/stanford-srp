/* config.h (tomcrypt version).  Configured by hand for MSVC++ 6.0.  */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
/* #undef TIME_WITH_SYS_TIME */

/* Define if your processor stores words with the most significant
   byte first (like Motorola and SPARC, unlike Intel and VAX).  */
/* #undef WORDS_BIGENDIAN */

/* #undef NOENCRYPTION */

/* #undef GNU_MP */

/* #undef MPI */

#define TOMCRYPT 1

#define TOMMATH 1

/* #undef CRYPTOLIB */

/* #undef OPENSSL */

#define CIPHER_CAST5 1

/* #undef OPENSSL_CAST */

#define TOMCRYPT_CAST 1

/* #undef CIPHER_BLOWFISH */

/* #undef OPENSSL_BLOWFISH */

/* #undef CIPHER_DES */

/* #undef OPENSSL_DES */

/* #undef CRYPTOLIB_DES */

#define HASH_MD5 1

/* #undef OPENSSL_MD5 */

#define TOMCRYPT_MD5 1

/* #undef CRYPTOLIB_MD5 */

#define HASH_SHA 1

/* The number of bytes in a int.  */
#define SIZEOF_INT 4

/* The number of bytes in a long.  */
#define SIZEOF_LONG 4

/* The number of bytes in a short.  */
#define SIZEOF_SHORT 2

/* Define if you have the getpid function.  */
#define HAVE_GETPID 1

/* Define if you have the srand function.  */
#define HAVE_SRAND 1

/* Define if you have the srand48 function.  */
/* #undef HAVE_SRAND48 */

/* Define if you have the srandom function.  */
#define HAVE_SRANDOM 1

/* Define if you have the <sys/time.h> header file.  */
/* #undef HAVE_SYS_TIME_H */

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <unistd.h> header file.  */
/* #undef HAVE_UNISTD_H */

/* Name of package */
#define PACKAGE "libkrypto"

/* Version number of package */
#define VERSION "2.0"

