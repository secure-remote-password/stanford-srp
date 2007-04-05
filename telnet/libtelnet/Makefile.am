AUTOMAKE_OPTIONS = foreign no-dependencies

noinst_HEADERS = auth-proto.h auth.h cast.h enc-proto.h encrypt.h \
 key-proto.h misc-proto.h misc.h err.h

noinst_LIBRARIES = libtelnet.a

libdir = ${prefix}/lib

libtelnet_a_SOURCES = auth.c encrypt.c genget.c misc.c srp.c kerberos4c.c \
 kerberos.c kerberos5.c forward.c spx.c rsaencpwd.c krb4encpwd.c \
 enc_des.c enc_des_ede3.c enc_cast.c cast.c read_password.c \
 localhost.c xmalloc.c err.c __progname.c

libtelnet_a_LIBADD = @LIBOBJS@

INCLUDES =
