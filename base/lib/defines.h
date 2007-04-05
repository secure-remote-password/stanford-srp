/* $Id: defines.h,v 1.1 2000/12/17 05:34:10 tom Exp $ */
/* some useful defines */

#ifndef _DEFINES_H_
#define _DEFINES_H_

#ifndef P_
#if __STDC__
#define P_(x) x
#else
#define P_(x) ()
#endif
#endif

#if STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#else  /* not STDC_HEADERS */
#ifndef HAVE_STRCHR
#define strchr index
#define strrchr rindex
#endif
char *strchr(), *strrchr(), *strtok();
#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy((s), (d), (n))
#endif
#endif /* not STDC_HEADERS */

#include <sys/types.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else  /* not TIME_WITH_SYS_TIME */
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif /* not TIME_WITH_SYS_TIME */

#ifndef HAVE_BZERO  /* XXX */
#define bzero(ptr, size) memset((ptr), 0, (size))
#endif

#ifdef HAVE_DIRENT_H  /* DIR_SYSV */
#include <dirent.h>
#define DIRECT dirent
#else
#ifdef HAVE_SYS_NDIR_H  /* DIR_XENIX */
#include <sys/ndir.h>
#endif
#ifdef HAVE_SYS_DIR_H  /* DIR_??? */
#include <sys/dir.h>
#endif
#ifdef HAVE_NDIR_H  /* DIR_BSD */
#include <ndir.h>
#endif
#define DIRECT direct
#endif

#ifdef SHADOWPWD
/*
 * Possible cases:
 * - /usr/include/shadow.h exists and includes the shadow group stuff.
 * - /usr/include/shadow.h exists, but we use our own gshadow.h.
 * - /usr/include/shadow.h doesn't exist, use our own shadow.h and gshadow.h.
 */
#if HAVE_SHADOW_H
#include <shadow.h>
#if defined(SHADOWGRP) && !defined(GSHADOW)
#include "gshadow_.h"
#endif
#else  /* not HAVE_SHADOW_H */
#include "shadow_.h"
#ifdef SHADOWGRP
#include "gshadow_.h"
#endif
#endif  /* not HAVE_SHADOW_H */
#endif  /* SHADOWPWD */

#include <limits.h>

#ifndef	NGROUPS_MAX
#ifdef	NGROUPS
#define	NGROUPS_MAX	NGROUPS
#else
#define	NGROUPS_MAX	64
#endif
#endif

#ifdef USE_SYSLOG
#include <syslog.h>

#ifndef LOG_WARN
#define LOG_WARN LOG_WARNING
#endif

/* cleaner than lots of #ifdefs everywhere - use this as follows:
   SYSLOG((LOG_CRIT, "user %s cracked root", user)); */
#define SYSLOG(x) syslog x

#else
#define SYSLOG(x)  /* empty */
#define openlog(a,b,c)  /* empty */
#define closelog()  /* empty */
#endif

#ifndef F_OK
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4
#endif

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#if HAVE_TERMIOS_H
#include <termios.h>
#define STTY(fd, termio) tcsetattr(fd, TCSANOW, termio)
#define GTTY(fd, termio) tcgetattr(fd, termio)
#define TERMIO struct termios
#define USE_TERMIOS
#elif HAVE_TERMIO_H
#include <sys/ioctl.h>
#include <termio.h>
#define STTY(fd, termio) ioctl(fd, TCSETA, termio)
#define GTTY(fd, termio) ioctl(fd, TCGETA, termio)
#define TEMRIO struct termio
#define USE_TERMIO
#elif HAVE_SGTTY_H
#include <sgtty.h>
#define STTY(fd, termio) stty(fd, termio)
#define GTTY(fd, termio) gtty(fd, termio)
#define TERMIO struct sgttyb
#define USE_SGTTY
#endif

#ifndef UT_USER  /* some systems have ut_name instead of ut_user */
#define UT_USER ut_user
#endif

/*
 * Password aging constants
 *
 * DAY - seconds / day
 * WEEK - seconds / week
 * SCALE - seconds / aging unit
 */

/* Solaris defines this in shadow.h */
#ifndef DAY
#define DAY (24L*3600L)
#endif

#define WEEK (7*DAY)

#ifdef ITI_AGING
#define SCALE 1
#else
#define SCALE DAY
#endif

#if !defined(MDY_DATE) && !defined(DMY_DATE) && !defined(YMD_DATE)
#define	MDY_DATE	1
#endif
#if (defined (MDY_DATE) && (defined (DMY_DATE) || defined (YMD_DATE))) || \
    (defined (DMY_DATE) && (defined (MDY_DATE) || defined (YMD_DATE)))
Error: You must only define one of MDY_DATE, DMY_DATE, or YMD_DATE
#endif

#ifdef MDY_DATE
#define DATE_FORMAT_DESCR "mm/dd/yy"
#define DATE_FORMAT_STRING "%m/%d/%y"
#endif

#ifdef DMY_DATE
#define DATE_FORMAT_DESCR "dd/mm/yy"
#define DATE_FORMAT_STRING "%d/%m/%y"
#endif

#ifdef YMD_DATE
#define DATE_FORMAT_DESCR "yy/mm/dd"
#define DATE_FORMAT_STRING "%y/%m/%d"
#endif

/* Copy string pointed by B to array A with size checking.  It was originally
   in lmain.c but is _very_ useful elsewhere.  Some setuid root programs with
   very sloppy coding used to assume that BUFSIZ will always be enough...  */

					/* danger - side effects */
#define STRFCPY(A,B) \
	(strncpy((A), (B), sizeof(A) - 1), (A)[sizeof(A) - 1] = '\0')

/* get rid of a few ugly repeated #ifdefs in pwent.c and grent.c */
#if defined(SVR4) || defined(AIX) || defined(__linux__)
#define SETXXENT_TYPE void
#define SETXXENT_RET(x) return
#define SETXXENT_TEST(x) x; if (0) /* compiler should optimize this away */
#else
#define SETXXENT_TYPE int
#define SETXXENT_RET(x) return(x)
#define SETXXENT_TEST(x) if (x)
#endif

#ifndef PASSWD_FILE
#define PASSWD_FILE "/etc/passwd"
#endif

#ifndef GROUP_FILE
#define GROUP_FILE "/etc/group"
#endif

#ifdef SHADOWPWD
#ifndef SHADOW_FILE
#define SHADOW_FILE "/etc/shadow"
#endif
#endif

#ifdef SHADOWGRP
#ifndef SGROUP_FILE
#define SGROUP_FILE "/etc/gshadow"
#endif
#endif

#define PASSWD_PAG_FILE  PASSWD_FILE ".pag"
#define GROUP_PAG_FILE   GROUP_FILE  ".pag"
#define SHADOW_PAG_FILE  SHADOW_FILE ".pag"
#define SGROUP_PAG_FILE  SGROUP_FILE ".pag"

#ifndef NULL
#define NULL ((void *) 0)
#endif

#ifdef NLS

#include <libintl.h>
#define _(String) gettext(String)
#ifdef gettext_noop
#define N_(String) gettext_noop(String)
#else
#define N_(String) (String)
#endif

#else /* !NLS */

#define _(String) (String)
#define N_(String) (String)
#define textdomain(Domain)
#define bindtextdomain(Package, Directory)

#endif /* !NLS */

#endif  /* _DEFINES_H_ */
