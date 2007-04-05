AUTOMAKE_OPTIONS = foreign

usbindir = ${prefix}/sbin

noinst_HEADERS = pathnames.h secure.h

usbin_PROGRAMS = ftpd

ftpd_SOURCES = ftpcmd.y ftpd.c logwtmp.c pathnames.h popen.c srp.c vers.c

EXTRA_DIST = getdtablesize.c setenv.c

LDADD = ../ftp/secure.o ../ftp/glob.o ../ftp/ftppath.o ../ftp/radix.o \
  ../../libkrypto/libkrypto.a @LIBOBJS@

INCLUDES = -I../../libkrypto

EXTRA_DIST = CHANGES ftpd.M
