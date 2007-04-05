
/* Define to enable password aging.  */
#undef AGING

/* Define if struct passwd has pw_age.  */
#undef ATT_AGE

/* Define if struct passwd has pw_comment.  */
#undef ATT_COMMENT

/* Define if struct passwd has pw_quota.  */
#undef BSD_QUOTA

/* Define if struct shadow has extra fields. */
#undef SP_EXTRA

/* Define to use "old" dbm.  */
#undef DBM

/* Define to support 16-character passwords.  */
#undef DOUBLESIZE

/* Define if you want my getgrent routines.  */
#undef GETGRENT

/* Define if you want my getpwent routines.  */
#undef GETPWENT

/* Define if struct lastlog has ll_host */
#undef HAVE_LL_HOST

/* Define if utmp.h defines struct lastlog. */
#undef UTMP_LASTLOG

/* Working shadow group support in libc?  */
#undef HAVE_SHADOWGRP

/* Path for lastlog file.  */
#undef LASTLOG_FILE

/* Path for faillog file.  */
#undef FAILLOG_FILE

/* Path for sulog file.  */
#undef SULOG_FILE

/* Location of system mail spool directory.  */
#undef MAIL_SPOOL_DIR

/* Name of user's mail spool file if stored in user's home directory.  */
#undef MAIL_SPOOL_FILE

/* Define if you have secure RPC.  */
#undef DES_RPC

/* Define to support the MD5-based password hashing algorithm.  */
#undef MD5_CRYPT

/* Define to use ndbm.  */
#undef NDBM

/* Define to support OPIE one-time password logins.  */
#undef OPIE

/* Define to support Pluggable Authentication Modules.  */
#undef PAM

/* Define to support the pam_misc library.  */
#undef PAM_MISC

/* Define to indicate old-style pam_strerror.  */
#undef PAM_OLD

/* Define if login should support the -r flag for rlogind.  */
#undef RLOGIN

/* Define to the ruserok() "success" return value (0 or 1).  */
#undef RUSEROK

/* Define to support the shadow password file.  */
#undef SHADOWPWD

/* Define to support the shadow group file.  */
#undef SHADOWGRP

/* Define to support S/Key logins.  */
#undef SKEY

/* Define to support SecureWare(tm) long passwords.  */
#undef SW_CRYPT

/* Define to use syslog().  */
#undef USE_SYSLOG

/* Define if you have ut_host in struct utmp.  */
#undef UT_HOST

/* Path for utmp file.  */
#undef _UTMP_FILE

/* Define to ut_name if struct utmp has ut_name (not ut_user).  */
#undef UT_USER

/* Path for wtmp file.  */
#undef _WTMP_FILE

/* Defined if you have libcrypt.  */
#undef HAVE_LIBCRYPT

/* Defined if you have libcrack.  */
#undef HAVE_LIBCRACK

/* Cracklib dictionary path.  */
#undef CRACKLIB_DICTPATH

/* Colon sep. paths to search if CRACKLIB_DICTPATH or login.defs is wrong. */
#undef DEFAULT_CRACKLIB_DICTPATH

/* Defined if you have the ts&szs cracklib.  */
#undef HAVE_LIBCRACK_HIST

/* Defined if it includes *Pw functions.  */
#undef HAVE_LIBCRACK_PW

/* Path to chfn program.  */
#undef CHFN_PROGRAM

/* Path to chsh program.  */
#undef CHSH_PROGRAM

/* Path to gpasswd program.  */
#undef GPASSWD_PROGRAM

/* Path to passwd program.  */
#undef PASSWD_PROGRAM

/* Define to support JFH's auth. methods.  UNTESTED.  */
#undef AUTH_METHODS

/* Define to support /etc/login.access login access control.  */
#undef LOGIN_ACCESS

/* Define to support /etc/suauth su access control.  */
#undef SU_ACCESS

/* Define to support the "console groups" feature.  */
#undef CONSOLE_GROUPS

/* Package name.  */
#undef PACKAGE

/* Version.  */
#undef VERSION

/* Added these from Kerberos update_utmp */
#undef HAVE_GETUTENT

/* EJ added these */
#undef NOISY_SHELL

/* Define if you have a member ut_syslen in struct utmp or utmpx.  */
#undef HAVE_UT_SYSLEN
