
AUTOMAKE_OPTIONS = foreign

noinst_HEADERS = commonio.h defines.h dialup.h faillog.h \
 getdef.h groupio.h md5.h port.h prototypes.h \
 pwauth.h pwio.h rcsid.h sgroupio.h shadowio.h tpwio.h

# These files are unneeded for some reason, listed in
# order of appearance:
#
# sources which are not really needed (are they in libc???)
# sources for dbm support (not yet used)
# sources for LIBOBJS (which are normally in libc)
# sources for CRYPTOBJS
# misc header sources

# We build libshadow for our tools.

noinst_LIBRARIES = libshadow.a

libshadow_a_SOURCES = \
	commonio.c dialchk.c dialup.c encrypt.c \
	fputsx.c getdef.c getpass.c groupio.c gshadow.c lockpw.c port.c \
	pwauth.c pwio.c rad64.c sgroupio.c shadow.c shadowio.c utent.c \
	md5.c md5crypt.c tpwio.c

EXTRA_libshadow_a_SOURCES = \
	grent.c pwent.c \
	grdbm.c gsdbm.c pwdbm.c spdbm.c \
	grpack.c gspack.c pwpack.c sppack.c \
	gshadow_.h shadow_.h lastlog_.h

libshadow_a_LIBADD = @LIBOBJS@

INCLUDES = -I$(top_srcdir)/lib -I$(top_srcdir)/../libsrp
