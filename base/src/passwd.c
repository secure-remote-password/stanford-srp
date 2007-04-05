/*
 * Copyright 1989 - 1994, Julianne Frances Haugh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Julianne F. Haugh nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JULIE HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JULIE HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: passwd.c,v 1.2 2002/11/04 07:22:20 tom Exp $")

#include "prototypes.h"
#include "defines.h"
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#ifdef  HAVE_USERSEC_H
#include <userpw.h>
#include <usersec.h>
#include <userconf.h>
# if !defined(SC_SYS_PASSWD) && defined(SEC_PASSWD)
#  define SC_SYS_PASSWD SEC_PASSWD
# endif
#endif

/* TJW: If PAM_MISC is not defined, we don't have do_pam_passwd */
#if defined(PAM) && !defined(PAM_MISC)
#undef PAM
#endif

#ifdef PAM
#include <security/pam_appl.h>
#endif

#ifndef GPASSWD_PROGRAM
#define GPASSWD_PROGRAM "/bin/gpasswd"
#endif

#ifndef CHFN_PROGRAM
#define CHFN_PROGRAM "/bin/chfn"
#endif

#ifndef CHSH_PROGRAM
#define CHSH_PROGRAM "/bin/chsh"
#endif

#include <pwd.h>
#ifndef	HAVE_USERSEC_H
#ifdef	SHADOWPWD
#ifndef	AGING
#define	AGING	0
#endif	/* !AGING */
#endif	/* SHADOWPWD */
#endif	/* !HAVE_USERSEC_H */
#include "pwauth.h"

#ifdef SHADOWPWD
#include "shadowio.h"
#endif
#include "pwio.h"
#include "getdef.h"

#ifdef  HAVE_USERSEC_H
int     minage = 0;	     /* Minimum age in weeks	       */
int     maxage = 10000;	 /* Maximum age in weeks	       */
#endif

/* EPS STUFF */

#include "t_pwd.h"
static int do_update_eps = 0;
struct t_pw * eps_passwd = NULL;

/*
 * Global variables
 */

static char *name;	/* The name of user whose password is being changed */
static char *myname;	/* The current user's name */
static char *Prog;		/* Program name */
static int amroot;		/* The real UID was 0 */

static int
	lflg = 0,		/* -l - lock account */
	uflg = 0,		/* -u - unlock account */
	dflg = 0,		/* -d - delete password */
#ifdef AGING	
	xflg = 0,		/* -x - set maximum days */
	nflg = 0,		/* -n - set minimum days */
	eflg = 0,		/* -e - force password change */
	kflg = 0,		/* -k - change only if expired */
#endif
#if defined(SHADOWPWD) && defined(SP_EXTRA)
	wflg = 0,		/* -w - set warning days */
	iflg = 0,		/* -i - set inactive days */
#endif
	tflg = 0,		/* -t - update EPS tpasswd only */
	qflg = 0,		/* -q - quiet mode */
	aflg = 0,		/* -a - show status for all users */
	Sflg = 0;		/* -S - show password status */

/*
 * set to 1 if there are any flags which require root privileges,
 * and require username to be specified
 */
static int anyflag = 0;

#ifdef AGING
static long age_min = 0;	/* Minimum days before change	*/
static long age_max = 0;	/* Maximum days until change	 */
#ifdef SHADOWPWD
static long warn = 0;		/* Warning days before change	*/
static long inact = 0;		/* Days without change before locked */
#endif
#endif

static int do_update_age = 0;

#ifndef PAM
static char crypt_passwd[128];	/* The "old-style" password, if present */
static int do_update_pwd = 0;
#endif

/*
 * External identifiers
 */

extern char *crypt_make_salt();
#if !defined(__GLIBC__)
extern char *l64a();
#endif

extern	int	optind;		/* Index into argv[] for current option */
extern	char	*optarg;	/* Pointer to current option value */

#ifndef	HAVE_USERSEC_H
#ifdef	NDBM
extern	int	sp_dbm_mode;
extern	int	pw_dbm_mode;
#endif
#endif

/*
 * #defines for messages.  This facilities foreign language conversion
 * since all messages are defined right here.
 */

#define USAGE \
	"usage: %s [ -f | -s ] [ -t ] [ name ]\n"
#define ADMUSAGE \
	"       %s [ -x max ] [ -n min ] [ -w warn ] [ -i inact ] name\n"
#define ADMUSAGE2 \
	"       %s { -l | -u | -d | -S | -e } name\n"
#define OLDPASS "Old password:"
#define NEWPASSMSG \
"Enter the new password (minimum of %d, maximum of %d characters)\n\
Please use a combination of upper and lower case letters and numbers.\n"
#define CHANGING "Changing password for %s\n"
#define NEWPASS "New password:"
#define NEWPASS2 "Re-enter new password:"
#define WRONGPWD "Incorrect password for %s.\n"
#define WRONGPWD2 "incorrect password for `%s'"
#define NOMATCH "They don't match; try again.\n"
#define CANTCHANGE "The password for %s cannot be changed.\n"
#define CANTCHANGE2 "password locked for `%s'"

#define BADPASS "Bad password:  %s.  "
#define EPSFAIL "Unable to update EPS password.\n"
#define NOEPSCONF "Warning: configuration file missing; please run 'tconf'\n"

#define TOOSOON "Sorry, the password for %s cannot be changed yet.\n"
#define TOOSOON2 "now < minimum age for `%s'"

#define EXECFAILED "%s: Cannot execute %s"
#define EXECFAILED2 "cannot execute %s"
#define WHOAREYOU "%s: Cannot determine your user name.\n"
#define UNKUSER "%s: Unknown user %s\n"
#define NOPERM "You may not change the password for %s.\n"
#define NOPERM2 "can't change pwd for `%s'"
#define UNCHANGED "The password for %s is unchanged.\n"

#define PWDBUSY "Cannot lock the password file; try again later.\n"
#define OPNERROR "Cannot open the password file.\n"
#define UPDERROR "Error updating the password entry.\n"
#define CLSERROR "Cannot commit password file changes.\n"
#define DBMERROR "Error updating the DBM password entry.\n"

#define PWDBUSY2 "can't lock password file"
#define OPNERROR2 "can't open password file"
#define UPDERROR2 "error updating password entry"
#define CLSERROR2 "can't rewrite password file"
#define DBMERROR2 "error updaring dbm password entry"

#define NOTROOT "Cannot change ID to root.\n"
#define NOTROOT2 "can't setuid(0)"
#define TRYAGAIN "Try again.\n"
#define PASSWARN \
	"\nWarning: weak password (enter it again to use it anyway).\n"
#define CHANGED "Password changed.\n"
#define CHGPASSWD "password for `%s' changed by user `%s'"
#define NOCHGPASSWD "did not change password for `%s'"

/*
 * usage - print command usage and exit
 */

static void
usage(status)
	int status;
{
	fprintf(stderr, USAGE, Prog);
	if (amroot) {
		fprintf(stderr, ADMUSAGE, Prog);
		fprintf(stderr, ADMUSAGE2, Prog);
	}
	exit(status);
}

#ifndef PAM
#ifdef AUTH_METHODS
/*
 * get_password - locate encrypted password in authentication list
 */

static char *
get_password(list)
	const char *list;
{
	char	*cp, *end;
	static	char	buf[257];

	STRFCPY(buf, list);
	for (cp = buf;cp;cp = end) {
		if ((end = strchr (cp, ';')))
			*end++ = 0;

		if (cp[0] == '@')
			continue;

		return cp;
	}
	return (char *) 0;
}

/*
 * uses_default_method - determine if "old-style" password present
 *
 *	uses_default_method determines if a "old-style" password is present
 *	in the authentication string, and if one is present it extracts it.
 */

static int
uses_default_method(methods)
	const char *methods;
{
	char	*cp;

	if ((cp = get_password (methods))) {
		STRFCPY(crypt_passwd, cp);
		return 1;
	}
	return 0;
}
#endif /* AUTH_METHODS */

static int
reuse(pass, pw)
	const char *pass;
	const struct passwd *pw;
{
#ifdef HAVE_LIBCRACK_HIST
	const char *reason;
#ifdef HAVE_LIBCRACK_PW
	const char *FascistHistoryPw P_((const char *,const struct passwd *));
	reason = FascistHistory(pass, pw);
#else
	const char *FascistHistory P_((const char *, int));
	reason = FascistHistory(pass, pw->pw_uid);
#endif
	if (reason) {
		printf(BADPASS, reason);
		return 1;
	}
#endif
	return 0;
}
#endif /* !PAM */

/*
 * new_password - validate old password and replace with new
 * (both old and new in global "char crypt_passwd[128]")
 */

/*ARGSUSED*/
static int
new_password(pw)
	const struct passwd *pw;
{
	char	clear[128];		/* Pointer to clear text */
	char	*cipher;	/* Pointer to cipher text */
	char	*cp;		/* Pointer to getpass() response */
	char	orig[128];	/* Original password */
	char	pass[128];	/* New password */
	int	i;		/* Counter for retries */
	int	warned;
	int	pass_max_len;
#ifdef HAVE_LIBCRACK_HIST
	int HistUpdate P_((const char *, const char *));
#endif

	/*
	 * Authenticate the user.  The user will be prompted for their
	 * own password.
	 */

#ifdef MD5_CRYPT
	if (getdef_bool("MD5_CRYPT_ENAB", 0))
		pass_max_len = getdef_num("PASS_MAX_LEN", 127);
	else
#endif
		pass_max_len = getdef_num("PASS_MAX_LEN", 8);

	if (! amroot
#ifndef PAM
	    && crypt_passwd[0]
#endif
	    ) {

		/* EPS STUFF */

		int retval;

		cipher = NULL;

		if (t_getpass (clear, 128, OLDPASS) < 0) return -1;

		if ((retval = t_verifypw (pw->pw_name, clear)) > -1)
		{
		  if (retval == 0) retval = 1; else retval = 0;
		}
#ifndef PAM
		else if(!tflg)
		{
		  if (strlen (clear) > pass_max_len)
		  {
		    bzero (clear+pass_max_len, strlen (clear+pass_max_len));
		    clear[pass_max_len] = '\0';
		  }

		  cipher = pw_encrypt (clear, crypt_passwd);
		  retval = strcmp (cipher, crypt_passwd);
		}
#endif /* PAM */

		if (retval != 0)
		{
		  SYSLOG((LOG_WARN, WRONGPWD2, pw->pw_name));
		  sleep(1);
		  fprintf(stderr, WRONGPWD, pw->pw_name);
		  return -1;
		}
		else
		{
		  STRFCPY(orig, clear);
		  bzero(clear, strlen (clear));
		  if (cipher) bzero(cipher, strlen (cipher));
		}
	} else {
		orig[0] = '\0';
	}

	/*
	 * Get the new password.  The user is prompted for the new password
	 * and has five tries to get it right.  The password will be tested
	 * for strength, unless it is the root user.  This provides an escape
	 * for initial login passwords.
	 */

	if (!qflg)
	printf(NEWPASSMSG, getdef_num("PASS_MIN_LEN", 5), 127);

	warned = 0;
	for (i = getdef_num("PASS_CHANGE_TRIES", 5); i > 0; i--) {
		t_getpass (clear, 128, NEWPASS);
		cp = clear;
		if (!cp) {
			bzero (orig, sizeof orig);
			return -1;
		}
		if (warned && strcmp(pass, cp) != 0)
			warned = 0;
		STRFCPY(pass, cp);
		bzero(cp, strlen(cp));

		if (!amroot && getdef_bool("PASS_STRICT", 0) &&
		    (!obscure(orig, pass, pw)
#ifndef PAM
		     || reuse(pass, pw)
#endif
		     )) {
			printf (TRYAGAIN);
			continue;
		}
		/*
		 * If enabled, warn about weak passwords even if you are root
		 * (enter this password again to use it anyway).  --marekm
		 */
		if ((amroot || !getdef_bool("PASS_STRICT", 0)) && !warned &&
		    getdef_bool("PASS_ALWAYS_WARN", 1)
		    && (!obscure(orig, pass, pw)
#ifndef PAM
			|| reuse(pass, pw)
#endif
			)) {
			printf(PASSWARN);
			warned++;
			continue;
		}
		if (! (cp = getpass (NEWPASS2))) {
			bzero (orig, sizeof orig);
			return -1;
		}
		if (strcmp (cp, pass))
			fprintf (stderr, NOMATCH);
		else {
			bzero (cp, strlen (cp));
			break;
		}
	}
	bzero (orig, sizeof orig);

	if (i == 0) {
		bzero (pass, sizeof pass);
		return -1;
	}

	/*
	 * Encrypt the password, then wipe the cleartext password.
	 */

	/* EPS STUFF */
	{
	  struct t_conf *tc;
	  struct t_confent *tcent;

	  if ((tc = t_openconf(NULL)) == NULL ||
	      (tcent = t_getconflast(tc)) == NULL)
	  {
	    fprintf(stderr, NOEPSCONF);
	    do_update_eps = 0;
	  }
	  else
	  {
	    do_update_eps = 1;
	    if(eps_passwd == NULL)
	      eps_passwd = t_newpw();
	    t_makepwent (eps_passwd, name, pass, NULL, tcent);
	  }

	  if (tc) t_closeconf (tc);
	  pass[pass_max_len] = '\0';
	}

	cp = pw_encrypt (pass, crypt_make_salt());
	bzero (pass, sizeof pass);

#ifdef HAVE_LIBCRACK_HIST
	HistUpdate(pw->pw_name, crypt_passwd);
#endif
#ifndef PAM
	STRFCPY(crypt_passwd, cp);
#endif

	return 0;
}

#ifndef PAM
/*
 * check_password - test a password to see if it can be changed
 *
 *	check_password() sees if the invoker has permission to change the
 *	password for the given user.
 */

/*ARGSUSED*/
static void
#ifdef SHADOWPWD
check_password(pw, sp)
	const struct passwd *pw;
	const struct spwd *sp;
#else
check_password(pw)
	const struct passwd *pw;
#endif
{
	time_t now, last, ok;
	int exp_status;
#ifdef HAVE_USERSEC_H
	struct userpw *pu;
#endif

#ifdef SHADOWPWD
	exp_status = isexpired(pw, sp);
#else
	exp_status = isexpired(pw);
#endif

	/*
	 * If not expired and the "change only if expired" option
	 * (idea from PAM) was specified, do nothing...  --marekm
	 */
	if (kflg && exp_status == 0)
		exit(0);

	/*
	 * Root can change any password any time.
	 */

	if (amroot)
		return;

	time(&now);

#ifdef SHADOWPWD
	/*
	 * Expired accounts cannot be changed ever.  Passwords
	 * which are locked may not be changed.  Passwords where
	 * min > max may not be changed.  Passwords which have
	 * been inactive too long cannot be changed.
	 */

	if (sp->sp_pwdp[0] == '!' || exp_status > 1 ||
	    (sp->sp_max >= 0 && sp->sp_min > sp->sp_max)) {
		fprintf (stderr, CANTCHANGE, sp->sp_namp);
		SYSLOG((LOG_WARN, CANTCHANGE2, sp->sp_namp));
		closelog();
		exit (1);
	}

	/*
	 * Passwords may only be changed after sp_min time is up.
	 */

	last = sp->sp_lstchg * SCALE;
	ok = last + (sp->sp_min > 0 ? sp->sp_min * SCALE : 0);

#else /* !SHADOWPWD */
	if (pw->pw_passwd[0] == '!' || exp_status > 1) {
		fprintf (stderr, CANTCHANGE, pw->pw_name);
		SYSLOG((LOG_WARN, CANTCHANGE2, pw->pw_name));
		closelog();
		exit (1);
	}
#ifdef ATT_AGE
	/*
	 * Can always be changed if there is no age info
	 */

	if (! pw->pw_age[0])
		return;

	last = a64l (pw->pw_age + 2) * WEEK;
	ok = last + c64i (pw->pw_age[1]) * WEEK;
#else	/* !ATT_AGE */
#ifdef HAVE_USERSEC_H
	pu = getuserpw(pw->pw_name);
	last = pu ? pu->upw_lastupdate : 0L;
	ok = last + (minage > 0 ? minage * WEEK : 0);
#else
	last = 0;
	ok = 0;
#endif
#endif /* !ATT_AGE */
#endif /* !SHADOWPWD */
	if (now < ok) {
		fprintf (stderr, TOOSOON, pw->pw_name);
		SYSLOG((LOG_WARN, TOOSOON2, pw->pw_name));
		closelog();
		exit (1);
	}
}

/*
 * insert_crypt_passwd - add an "old-style" password to authentication string
 * result now malloced to avoid overflow, just in case.  --marekm
 */
static char *
insert_crypt_passwd(string, passwd)
	const char *string;
	const char *passwd;
{
#ifdef AUTH_METHODS
	if (string && *string) {
		char *cp, *result;

		result = xmalloc(strlen(string) + strlen(passwd) + 1);
		cp = result;
		while (*string) {
			if (string[0] == ';') {
				*cp++ = *string++;
			} else if (string[0] == '@') {
				while (*string && *string != ';')
					*cp++ = *string++;
			} else {
				while (*passwd)
					*cp++ = *passwd++;

				while (*string && *string != ';')
					string++;
			}
		}
		*cp = '\0';
		return result;
	}
#endif
	return xstrdup(passwd);
}
#endif /* !PAM */

static char *
date_to_str(t)
	time_t t;
{
	static char buf[80];
	struct tm *tm;

	tm = gmtime(&t);
#ifdef HAVE_STRFTIME
	strftime(buf, sizeof buf, "%m/%d/%y", tm);
#else
	sprintf(buf, "%02d/%02d/%02d",
		tm->tm_mon + 1, tm->tm_mday, tm->tm_year % 100);
#endif
	return buf;
}

static const char *
pw_status(pass)
	const char *pass;
{
	if (*pass == '*' || *pass == '!')
		return "L";
	if (*pass == '\0')
		return "NP";
	return "P";
}

/*
 * print_status - print current password status
 */

static void
print_status(pw)
	const struct passwd *pw;
{
#ifdef SHADOWPWD
	struct spwd *sp;
#endif
#ifdef HAVE_USERSEC_H
	struct userpw *pu;
#endif

#ifdef SHADOWPWD
	sp = getspnam(pw->pw_name);
	if (sp) {
		printf("%s %s %s %ld %ld %ld %ld\n",
			pw->pw_name,
			pw_status(sp->sp_pwdp),
			date_to_str(sp->sp_lstchg * SCALE),
			(sp->sp_min * SCALE) / DAY,
			(sp->sp_max * SCALE) / DAY,
#ifdef SP_EXTRA
		        (sp->sp_warn * SCALE) / DAY,
			(sp->sp_inact * SCALE) / DAY
#else
		        0, 0
#endif /* SP_EXTRA */
		       );
	} else
#endif
	{
#ifdef HAVE_USERSEC_H
		pu = getuserpw(name);
		printf("%s %s %s %d %d\n",
			pw->pw_name,
			pw_status(pw->pw_passwd),
			date_to_str(pu ? pu->upw_lastupdate : 0L),
			minage > 0 ? minage * 7 : 0,
			maxage > 0 ? maxage * 7 : 10000);
#else /* !HAVE_USERSEC_H */
#ifdef ATT_AGE
		printf("%s %s %s %d %d\n",
			pw->pw_name,
			pw_status(pw->pw_passwd),
			date_to_str(strlen(pw->pw_age) > 2 ?
				a64l(pw->pw_age + 2) * WEEK : 0L),
			pw->pw_age[0] ? c64i(pw->pw_age[1]) * 7 : 0,
			pw->pw_age[0] ? c64i(pw->pw_age[0]) * 7 : 10000);
#else
		printf("%s %s\n", pw->pw_name, pw_status(pw->pw_passwd));
#endif
#endif /* !HAVE_USERSEC_H */
	}
}


static void
fail_exit(status)
	int status;
{
	pw_unlock();
#ifdef SHADOWPWD
	spw_unlock();
#endif
	tpw_unlock();
	commonio_unlock_all();

	exit(status);
}

static void
oom()
{
	fprintf(stderr, "%s: out of memory\n", Prog);
	fail_exit(3);
}

static char *
update_crypt_pw(cp)
	char *cp;
{
#ifndef PAM
	if (do_update_pwd)
		cp = insert_crypt_passwd(cp, crypt_passwd);
#endif

	if (dflg)
		cp = "";

	if (uflg && *cp == '!')
		cp++;

	if (lflg && *cp != '!') {
		char *newpw = xmalloc(strlen(cp) + 2);

		strcpy(newpw, "!");
		strcat(newpw, cp);
		cp = newpw;
	}
	return cp;
}

static void
update_noshadow()
{
	const struct passwd *pw;
	struct passwd *npw;
#ifdef ATT_AGE
	char age[5];
	long week = time((time_t *) 0) / WEEK;
	char *cp;
#endif

	if (!pw_lock()) {
		fprintf(stderr, PWDBUSY);
		SYSLOG((LOG_WARN, PWDBUSY2));
		fail_exit(5);
	}
	if (!pw_open(O_RDWR)) {
		fprintf(stderr, OPNERROR);
		SYSLOG((LOG_ERR, OPNERROR2));
		fail_exit(3);
	}
	pw = pw_locate(name);
	if (!pw) {
#if 0
		fprintf(stderr, "%s: user %s not found in /etc/passwd\n",
			Prog, name);
		fail_exit(1);
#else
		fprintf(stderr, "%s: warning: user %s not found in /etc/passwd\n",
			Prog, name);
		pw_close();
		pw_unlock();
		return;
#endif
	}
	npw = __pw_dup(pw);
	if (!npw)
		oom();
	npw->pw_passwd = update_crypt_pw(npw->pw_passwd);
#ifdef ATT_AGE
	bzero(age, sizeof(age));
	STRFCPY(age, npw->pw_age);

	/*
	 * Just changing the password - update the last change date
	 * if there is one, otherwise the age just disappears.
	 */
	if (do_update_age) {
		if (strlen(age) > 2) {
			cp = l64a(week);
			age[2] = cp[0];
			age[3] = cp[1];
		} else {
			age[0] = '\0';
		}
	}

	if (xflg) {
		if (age_max > 0)
			age[0] = i64c((age_max + 6) / 7);
		else
			age[0] = '.';

		if (age[1] == '\0')
			age[1] = '.';
	}
	if (nflg) {
		if (age[0] == '\0')
			age[0] = 'z';

		if (age_min > 0)
			age[1] = i64c((age_min + 6) / 7);
		else
			age[1] = '.';
	}
	/*
	 * The last change date is added by -n or -x if it's
	 * not already there.
	 */
	if ((nflg || xflg) && strlen(age) <= 2) {
		cp = l64a(week);
		age[2] = cp[0];
		age[3] = cp[1];
	}

	/*
	 * Force password change - if last change date is
	 * present, it will be set to (today - max - 1 week).
	 * Otherwise, just set min = max = 0 (will disappear
	 * when password is changed).
	 */
	if (eflg) {
		if (strlen(age) > 2) {
			cp = l64a(week - c64i(age[0]) - 1);
			age[2] = cp[0];
			age[3] = cp[1];
		} else {
			strcpy(age, "..");
		}
	}

	npw->pw_age = age;
#endif
	if (!pw_update(npw)) {
		fprintf(stderr, UPDERROR);
		SYSLOG((LOG_ERR, UPDERROR2));
		fail_exit(3);
	}
#ifdef NDBM
	if (pw_dbm_present() && !pw_dbm_update(npw)) {
		fprintf(stderr, DBMERROR);
		SYSLOG((LOG_ERR, DBMERROR2));
		fail_exit(3);
	}
	endpwent();
#endif
	if (!pw_close()) {
		fprintf(stderr, CLSERROR);
		SYSLOG((LOG_ERR, CLSERROR2));
		fail_exit(3);
	}
	pw_unlock();
}

#ifdef SHADOWPWD
static void
update_shadow()
{
	const struct spwd *sp;
	struct spwd *nsp;

	if (!spw_lock()) {
		fprintf(stderr, PWDBUSY);
		SYSLOG((LOG_WARN, PWDBUSY2));
		fail_exit(5);
	}
	if (!spw_open(O_RDWR)) {
		fprintf(stderr, OPNERROR);
		SYSLOG((LOG_ERR, OPNERROR2));
		fail_exit(3);
	}
	sp = spw_locate(name);
	if (!sp) {
#if 0
		fprintf(stderr, "%s: user %s not found in /etc/shadow\n",
			Prog, name);
		fail_exit(1);
#else
		/* Try to update the password in /etc/passwd instead.  */
		spw_unlock();
		update_noshadow();
		return;
#endif
	}
	nsp = __spw_dup(sp);
	if (!nsp)
		oom();
	nsp->sp_pwdp = update_crypt_pw(nsp->sp_pwdp);
	if (xflg)
		nsp->sp_max = (age_max * DAY) / SCALE;
	if (nflg)
		nsp->sp_min = (age_min * DAY) / SCALE;
#ifdef SP_EXTRA
	if (wflg)
		nsp->sp_warn = (warn * DAY) / SCALE;
	if (iflg)
		nsp->sp_inact = (inact * DAY) / SCALE;
#endif /* SP_EXTRA */
	if (do_update_age)
		nsp->sp_lstchg = time((time_t *) 0) / SCALE;
	/*
	 * Force change on next login, like SunOS 4.x passwd -e or
	 * Solaris 2.x passwd -f.  Solaris 2.x seems to do the same
	 * thing (set sp_lstchg to 0).
	 */
	if (eflg)
		nsp->sp_lstchg = 0;

	if (!spw_update(nsp)) {
		fprintf(stderr, UPDERROR);
		SYSLOG((LOG_ERR, UPDERROR2));
		fail_exit(3);
	}
#ifdef NDBM
	if (sp_dbm_present() && !sp_dbm_update(nsp)) {
		fprintf(stderr, DBMERROR);
		SYSLOG((LOG_ERR, DBMERROR2));
		fail_exit(3);
	}
	endspent();
#endif
	if (!spw_close()) {
		fprintf(stderr, CLSERROR);
		SYSLOG((LOG_ERR, CLSERROR2));
		fail_exit(3);
	}
	spw_unlock();
}
#endif  /* SHADOWPWD */

#ifdef HAVE_USERSEC_H
static void
update_userpw(cp)
	char *cp;
{
	struct userpw userpw;

	/*
	 * AIX very conveniently has its own mechanism for updating
	 * passwords.  Use it instead ...
	 */

	strcpy(userpw.upw_name, name);
	userpw.upw_passwd = update_crypt_pw(cp);
	userpw.upw_lastupdate = time (0);
	userpw.upw_flags = 0;

	setpwdb(S_WRITE);

	if (putuserpw(&userpw)) {
		fprintf(stderr, UPDERROR);
		SYSLOG((LOG_ERR, UPDERROR2));
		closelog();
		exit(3);
	}
	endpwdb();
}
#endif

static long
getnumber(str)
	const char *str;
{
	long val;
	char *cp;

	val = strtol(str, &cp, 10);
	if (*cp)
		usage(6);
	return val;
}

/*
 * passwd - change a user's password file information
 *
 *	This command controls the password file and commands which are
 * 	used to modify it.
 *
 *	The valid options are
 *
 *	-l	lock the named account (*)
 *	-u	unlock the named account (*)
 *	-d	delete the password for the named account (*)
 *	-e	expire the password for the named account (*)
 *	-x #	set sp_max to # days (*)
 *	-n #	set sp_min to # days (*)
 *	-w #	set sp_warn to # days (*)
 *	-i #	set sp_inact to # days (*)
 *	-S	show password status of named account
 *	-g	execute gpasswd command to interpret flags
 *	-f	execute chfn command to interpret flags
 *	-s	execute chsh command to interpret flags
 *	-k	change password only if expired
 *	-t	update EPS tpasswd only
 *
 *	(*) requires root permission to execute.
 *
 *	All of the time fields are entered in days and converted to the
 * 	appropriate internal format.  For finer resolute the chage
 *	command must be used.
 *
 *	Exit status:
 *	0 - success
 *	1 - permission denied
 *	2 - invalid combination of options
 *	3 - unexpected failure, password file unchanged
 *	5 - password file busy, try again later
 *	6 - invalid argument to option
 */

int
main(argc, argv)
	int argc;
	char **argv;
{
	char	*cp;			/* Miscellaneous character pointing  */
	int	flag;			/* Current option to process	 */
	const struct passwd *pw;	/* Password file entry for user      */
#ifdef SHADOWPWD
	const struct spwd *sp;		/* Shadow file entry for user	*/
#endif

	/*
	 * The program behaves differently when executed by root
	 * than when executed by a normal user.
	 */

	amroot = (getuid () == 0);

	/*
	 * Get the program name.  The program name is used as a
	 * prefix to most error messages.
	 */

	Prog = Basename(argv[0]);

#ifdef __ultrix
	openlog("passwd", LOG_PID);
#else
	openlog("passwd", LOG_PID|LOG_CONS|LOG_NOWAIT, LOG_AUTH);
#endif

	/*
	 * Start with the flags which cause another command to be
	 * executed.  The effective UID will be set back to the
	 * real UID and the new command executed with the flags
	 *
	 * These flags are deprecated, may change in a future
	 * release.  Please run these programs directly.  --marekm
	 */

	if (argc > 1 && argv[1][0] == '-' && strchr ("gfs", argv[1][1])) {
		char buf[BUFSIZ];

		setuid (getuid ());
		switch (argv[1][1]) {
			case 'g':
				argv[1] = GPASSWD_PROGRAM;
				execv(argv[1], &argv[1]);
				break;
			case 'f':
				argv[1] = CHFN_PROGRAM;
				execv(argv[1], &argv[1]);
				break;
			case 's':
				argv[1] = CHSH_PROGRAM;
				execv(argv[1], &argv[1]);
				break;
			default:
				usage(6);
		}
		sprintf (buf, EXECFAILED, Prog, argv[1]);
		perror (buf);
		SYSLOG((LOG_ERR, EXECFAILED2, argv[1]));
		closelog();
		exit(3);
	}

	/* 
	 * The remaining arguments will be processed one by one and
	 * executed by this command.  The name is the last argument
	 * if it does not begin with a "-", otherwise the name is
	 * determined from the environment and must agree with the
	 * real UID.  Also, the UID will be checked for any commands
	 * which are restricted to root only.
	 */

#ifdef SHADOWPWD
#define FLAGS "adlqtuSekn:x:i:w:"
#else
#ifdef AGING
#define FLAGS "adlqtuSekn:x:"
#else
#define FLAGS "adlqtuS"
#endif
#endif
	while ((flag = getopt(argc, argv, FLAGS)) != EOF) {
#undef FLAGS
		switch (flag) {
#ifdef	AGING
		case 'x':
			age_max = getnumber(optarg);
			xflg++;
			anyflag = 1;
			break;
		case 'n':
			age_min = getnumber(optarg);
			nflg++;
			anyflag = 1;
			break;
#if defined(SHADOWPWD) && defined(SP_EXTRA)
		case 'w':
			warn = getnumber(optarg);
			if (warn >= -1)
				wflg++;
			anyflag = 1;
			break;
		case 'i':
			inact = getnumber(optarg);
			if (inact >= -1)
				iflg++;
			anyflag = 1;
			break;
#endif	/* SHADOWPWD && SP_EXTRA */
		case 'e':
			eflg++;
			anyflag = 1;
			break;
		case 'k':
			/* change only if expired, like Linux-PAM passwd -k.  */
			kflg++;  /* ok for users */
			break;
#endif	/* AGING */
		case 'a':
			aflg++;
			break;
		case 't':
			tflg++;  /* ok for users */
			break;
		case 'q':
			qflg++;  /* ok for users */
			break;
		case 'S':
			Sflg++;  /* ok for users */
			break;
		case 'd':
			dflg++;
			anyflag = 1;
			break;
		case 'l':
			lflg++;
			anyflag = 1;
			break;
		case 'u':
			uflg++;
			anyflag = 1;
			break;
		default:
			usage(6);
		}
	}

#ifdef  HAVE_USERSEC_H
	/*
	 * The aging information lives someplace else.  Get it from the
	 * login.cfg file
	 */

	if (getconfattr(SC_SYS_PASSWD, SC_MINAGE, &minage, SEC_INT))
		minage = -1;

	if (getconfattr(SC_SYS_PASSWD, SC_MAXAGE, &maxage, SEC_INT))
		maxage = -1;
#endif	/* HAVE_USERSEC_H */

	/*
	 * Now I have to get the user name.  The name will be gotten 
	 * from the command line if possible.  Otherwise it is figured
	 * out from the environment.
	 */

	pw = get_my_pwent();
	if (!pw) {
		fprintf(stderr, WHOAREYOU, Prog);
		exit(1);
	}
	myname = xstrdup(pw->pw_name);
	if (optind < argc)
		name = argv[optind];
	else
		name = myname;

	/*
	 * The -a flag requires -S, no other flags, no username, and
	 * you must be root.  --marekm
	 */

	if (aflg) {
		if (anyflag || !Sflg || (optind < argc))
			usage(2);
		if (!amroot) {
			fprintf(stderr, "%s: Permission denied.\n", Prog);
			exit(1);
		}
		setpwent();
		while ((pw = getpwent()))
			print_status(pw);
		exit(0);
	}

#if 0
	/*
	 * Allow certain users (administrators) to change passwords of
	 * certain users.  Not implemented yet...  --marekm
	 */
	if (may_change_passwd(myname, name))
		amroot = 1;
#endif

	/*
	 * If any of the flags were given, a user name must be supplied
	 * on the command line.  Only an unadorned command line doesn't
	 * require the user's name be given.  Also, -x, -n, -w, -i, -e, -d,
	 * -l, -u may appear with each other.  -S, -k must appear alone.
	 */

	/*
	 * -S now ok for normal users (check status of my own account),
	 * and doesn't require username.  --marekm
	 */

	if (anyflag && optind >= argc)
		usage(2);

	if (anyflag + Sflg + kflg > 1)
		usage(2);

	if (anyflag && !amroot) {
		fprintf(stderr, "%s: Permission denied\n", Prog);
		exit(1);
	}

#ifdef NDBM
	endpwent();
	pw_dbm_mode = O_RDWR;
#ifdef SHADOWPWD
	sp_dbm_mode = O_RDWR;
#endif
#endif

	pw = getpwnam(name);
	if (!pw) {
		fprintf(stderr, UNKUSER, Prog, name);
		exit(1);
	}

	/*
	 * Now I have a name, let's see if the UID for the name
	 * matches the current real UID.
	 */

	if (!amroot && pw->pw_uid != getuid ()) {
		fprintf(stderr, NOPERM, name);
		SYSLOG((LOG_WARN, NOPERM2, name));
		closelog();
		exit(1);
	}

	if (Sflg) {
		print_status(pw);
		exit(0);
	}

#ifdef PAM
	if(tflg) {
#endif /* PAM */
#ifdef SHADOWPWD
	/*
	 * The user name is valid, so let's get the shadow file
	 * entry.
	 */

	sp = getspnam(name);
	if (!sp)
		sp = pwd_to_spwd(pw);

	cp = sp->sp_pwdp;
#else
	cp = pw->pw_passwd;
#endif

	/*
	 * If there are no other flags, just change the password.
	 */

	if (!anyflag) {
#ifndef PAM
		if(!tflg) {
#ifdef AUTH_METHODS
		if (strchr(cp, '@')) {
			if (pw_auth(cp, name, PW_CHANGE, (char *)0)) {
				SYSLOG((LOG_INFO, NOCHGPASSWD, name));
				closelog();
				exit (1);
			} else if (! uses_default_method(cp)) {
				do_update_age = 1;
				goto done;
			}
		} else
#endif
			STRFCPY(crypt_passwd, cp);

		/*
		 * See if the user is permitted to change the password.
		 * Otherwise, go ahead and set a new password.
		 */

#ifdef SHADOWPWD
		check_password(pw, sp);
#else
		check_password(pw);
#endif
		}
#endif /* !PAM */
		/*
		 * Let the user know whose password is being changed.
		 */
		if (!qflg)
			printf(CHANGING, name);

		if (new_password(pw)) {
			fprintf(stderr, UNCHANGED, name);
			closelog();
			exit(1);
		}
#ifndef PAM
		do_update_pwd = 1;
#endif
		do_update_age = 1;
	}

#ifdef PAM
	}
#endif /* PAM */
#ifdef AUTH_METHODS
done:
#endif
	/*
	 * Before going any further, raise the ulimit to prevent
	 * colliding into a lowered ulimit, and set the real UID
	 * to root to protect against unexpected signals.  Any
	 * keyboard signals are set to be ignored.
	 */

	set_filesize_limit(30000);
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
	umask(077);  /* just to be safe */
	/*
	 * Don't set the real UID for PAM...
	 */
#ifdef PAM
	if (!anyflag && !tflg) {
		int flags = 0;

		if (kflg)
			flags |= PAM_CHANGE_EXPIRED_AUTHTOK;

		if (qflg)
			flags |= PAM_SILENT;

		do_pam_passwd(name, flags);
		exit(0);
	}
#endif /* PAM */
	if (setuid (0)) {
		fprintf(stderr, NOTROOT);
		SYSLOG((LOG_ERR, NOTROOT2));
		closelog();
		exit(1);
	}
#ifdef  HAVE_USERSEC_H
	if(!tflg) {
	update_userpw(pw->pw_passwd);
	}
#else  /* !HAVE_USERSEC_H */

	if (!commonio_lock_all()) {
		fprintf(stderr, PWDBUSY);
		SYSLOG((LOG_WARN, PWDBUSY2));
		exit(5);
	}

	if(!tflg) {
#ifdef SHADOWPWD
	if (access(SHADOW_FILE, 0) == 0)
		update_shadow();
	else
#endif
		update_noshadow();
	}

#endif /* !HAVE_USERSEC_H */

/* EPS STUFF */

        if (do_update_eps)
	{
	  FILE *passfp;

	  /* try and see if the file is there, else create it */

	  if ((passfp = fopen (DEFAULT_PASSWD, "r+")) == NULL)
             creat (DEFAULT_PASSWD, 0400);
          else fclose (passfp);

	  /* lock the file */

	  if (!tpw_lock())
          {
	    fprintf (stderr, PWDBUSY);
	    SYSLOG ((LOG_WARN, PWDBUSY2));
	    fail_exit (5);
	  }

          /* change the password */

	  if (t_changepw (NULL, &(eps_passwd->pebuf)) < 0)
            fprintf (stderr, EPSFAIL);

	  t_closepw(eps_passwd);
	  eps_passwd = NULL;

	  /* unlock the file */

	  tpw_unlock ();
	}
        else fprintf (stderr, EPSFAIL);

	commonio_unlock_all ();

	SYSLOG((LOG_INFO, CHGPASSWD, name, myname));
	closelog();
	if (!qflg)
		printf(CHANGED);
	exit(0);
	/*NOTREACHED*/
}
