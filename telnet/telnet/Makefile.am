AUTOMAKE_OPTIONS = foreign

ubindir = ${prefix}/bin

noinst_HEADERS = defines.h externs.h fdset.h general.h ring.h types.h Xauth.h fwdxutil.h tlsutil.h

ubin_PROGRAMS = telnet

telnet_SOURCES = authenc.c commands.c main.c network.c ring.c sys_bsd.c \
 telnet.c terminal.c tn3270.c utilities.c Xauth.c XdmAuth.c fwdxutil.c parsedpy.c tlsutil.c

telnet_LDADD = ../libtelnet/libtelnet.a

INCLUDES =

EXTRA_DIST = Makefile.generic Makefile.unix Makefile.4.4 \
 telnet.0.ps telnet.0.txt telnet.1
