AUTOMAKE_OPTIONS = foreign

usbindir = ${prefix}/sbin

noinst_HEADERS = defs.h ext.h pathnames.h telnetd.h Xauth.h fwdxutil.h tls_dh.h tlsutil.h

usbin_PROGRAMS = telnetd

telnetd_SOURCES = authenc.c global.c slc.c state.c sys_term.c \
 telnetd.c termstat.c utility.c Xauth.c XdmAuth.c fwdxutil.c parsedpy.c tlsutil.c x509_to_user.c

telnetd_LDADD = ../libtelnet/libtelnet.a

INCLUDES =
CPPFLAGS = @CPPFLAGS@ -DTLS_SFC_DIR=\"@TLS_SFC_DIR@\"
