AUTOMAKE_OPTIONS = foreign

# Watch out; note the difference between prefix & exec_prefix.
# Normally configure sets exec_prefix to root when prefix is /usr.

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
ubindir = ${prefix}/bin
usbindir = ${prefix}/sbin

bin_PROGRAMS = login
usbin_PROGRAMS =

# id and groups are from gnu, the rest is perhaps not important
# also suid programs are installed by hand.

suidbins = su
suidubins = passwd

install-exec-local:
	$(mkinstalldirs) $(bindir)
	for i in $(suidbins); do \
	  $(INSTALL) -m 4755 $$i $(bindir); \
	done
	$(mkinstalldirs) $(ubindir)
	for i in $(suidubins); do \
	  $(INSTALL) -m 4755 $$i $(ubindir); \
	done

noinst_PROGRAMS = su passwd

LDADD=../libmisc/libmisc.a ../lib/libshadow.a -L../../libsrp -lsrp

INCLUDES= -I$(top_srcdir)/lib -I../../libsrp

# These are to trick the linker to link only libcrypt statically

STATLINK = -Wl,-Bstatic
DYNLINK = -Wl,-Bdynamic

# Some tools need libcrypt.

login_LDADD = $(LDADD) @LIBCRYPT@ @LIBMATH@ @LIBSKEY@
passwd_LDADD = $(LDADD) @LIBCRYPT@ @LIBMATH@ @LIBCRACK@ @LIBPAM@
su_LDADD = $(LDADD) @LIBCRYPT@ @LIBMATH@ @LIBSKEY@
