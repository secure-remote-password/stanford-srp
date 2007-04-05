AUTOMAKE_OPTIONS = foreign

ubindir = ${prefix}/bin

noinst_HEADERS = ftp_var.h secure.h pathnames.h

ubin_PROGRAMS = ftp

ftp_SOURCES = cmds.c cmdtab.c domacro.c getpass.c ftp.c pclose.c glob.c \
  main.c radix.c ruserpass.c secure.c srp.c ftppath.c

LDADD = ../../libkrypto/libkrypto.a
INCLUDES = -I../../libkrypto

EXTRA_DIST = ftp.M
