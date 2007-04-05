AUTOMAKE_OPTIONS = foreign

include_HEADERS = krypto.h

noinst_HEADERS = \
  krypto_locl.h cipher_imp_blowfish.h \
  cipher_imp_des.h cipher_imp_cast.h \
  hash_imp_md5.h hash_imp_sha.h

lib_LIBRARIES = libkrypto.a

libkrypto_a_SOURCES = \
  krypto.c cipher.c cipher_crypt_ecb.c cipher_crypt_cbc.c \
  cipher_crypt_cfb.c cipher_crypt_ofb.c hash.c krypto_rand_conf.c \
  cipher_imp_cast.c cipher_imp_blowfish.c cipher_imp_des.c \
  cipher_imp_none.c \
  hash_imp_md5.c hash_imp_sha.c

noinst_PROGRAMS = cipher_test hash_test krypto_test cipher_bench

cipher_test_SOURCES = cipher_test.c
hash_test_SOURCES = hash_test.c
krypto_test_SOURCES = krypto_test.c
cipher_bench_SOURCES = cipher_bench.c

LDADD = libkrypto.a ../libsrp/libsrp.a

TESTS = cipher_test hash_test krypto_test

EXTRA_DIST = README
