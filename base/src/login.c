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
RCSID("$Id: login.c,v 1.2 2002/11/04 07:20:35 tom Exp $")

#include "prototypes.h"
#include "defines.h"
#include <sys/stat.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#if HAVE_UTMPX_H
#include <utmpx.h>
#endif
#include <signal.h>

#if HAVE_LASTLOG_H
#include <lastlog.h>
#else
#ifdef UTMP_LASTLOG
#include <utmp.h>
#else
#include "lastlog_.h"
#endif
#endif

#include "faillog.h"
#include "pwauth.h"
#include "getdef.h"

#include "t_pwd.h"

#ifdef SVR4_SI86_EUA
#include <sys/proc.h>
#include <sys/sysi86.h>
#endif

#ifdef RADIUS
/*
 * Support for RADIUS authentication based on a hacked util-linux login
 * source sent to me by Jon Lewis.  Not tested.  You need to link login
 * with the radauth.c file (not included here - it doesn't have a clear
 * copyright statement, and I don't want to have problems with Debian
 * putting the whole package in non-free because of this).  --marekm
 */
#include "radlogin.h"
#endif

/*
 * Needed for MkLinux DR1/2/2.1 - J.
 */
#ifndef LASTLOG_FILE
#define LASTLOG_FILE "/var/log/lastlog"
#endif

char *host = "";

struct	passwd	pwent;
#if HAVE_UTMPX_H
struct	utmpx	utxent, failent;
struct	utmp	utent;
#else
struct	utmp	utent, failent;
#endif
struct	lastlog	lastlog;
static int pflg = 0;
static int fflg = 0;
#ifdef RLOGIN
static int rflg = 0;
#else
#define rflg 0
#endif
static int hflg = 0;
static int preauth_flag = 0;

/*
 * Global variables.
 */

static char *Prog;
static int amroot;

/*
 * External identifiers.
 */

extern char **newenvp;
extern size_t newenvc;

extern	char	*tz();
extern	void	subsystem();
extern void dolastlog P_((struct lastlog *, const struct passwd *, const char *, const char *));
extern	void	motd();
extern	void	mailcheck();

extern	int	optind;
extern	char	*optarg;
extern	char	**environ;

extern	int	login_access();
extern	void	login_fbtab();

#ifndef	ALARM
#define	ALARM	60
#endif

#ifndef	RETRIES
#define	RETRIES	3
#endif

#ifndef LOGIN_PROMPT
#ifdef __linux__  /* hostname login: - like in util-linux login */
#define LOGIN_PROMPT "\n%s login: "
#else
#define LOGIN_PROMPT "login: "
#endif
#endif

static struct faillog faillog;

#define	NEW_PASS	"Your password has expired."
#define	NO_TPASSWD_FILE "cannot open /etc/tpasswd file\n"
#define	NO_SHADOW	"no shadow password for `%s'%s\n"
#define	BAD_PASSWD	"invalid password for `%s'%s\n"
#define	BAD_DIALUP	"invalid dialup password for `%s' on `%s'\n"
#define	BAD_TIME	"invalid login time for `%s'%s\n"
#define	BAD_ROOT_LOGIN	"ILLEGAL ROOT LOGIN%s\n"
#define	ROOT_LOGIN	"ROOT LOGIN%s\n"
#define	FAILURE_CNT	"exceeded failure limit for `%s'%s\n"
#define REG_LOGIN	"`%s' logged in%s\n"
#define LOGIN_REFUSED	"LOGIN `%s' REFUSED%s\n"
#define REENABLED \
	"Warning: login re-enabled after temporary lockout.\n"
#define REENABLED2 \
	"login `%s' re-enabled after temporary lockout (%d failures).\n"
#define MANY_FAILS	"REPEATED login failures%s\n"

/*
 * usage - print login command usage and exit
 *
 * login [ name ]
 * login -r hostname	(for rlogind)
 * login -h hostname	(for telnetd, etc.)
 * login -f name	(for pre-authenticated login: datakit, xterm, etc.)
 */

static void
usage()
{
	fprintf(stderr, "usage: %s [-p] [name]\n", Prog);
	if (!amroot)
		exit(1);
	fprintf(stderr, "       %s [-p] [-h host] [-f name]\n", Prog);
#ifdef RLOGIN
	fprintf(stderr, "       %s [-p] -r host\n", Prog);
#endif
	exit(1);
}


static void
setup_tty()
{
	TERMIO termio;

	GTTY(0, &termio);		/* get terminal characteristics */

	/*
	 * Add your favorite terminal modes here ...
	 */

#ifndef	USE_SGTTY
	termio.c_lflag |= ISIG|ICANON|ECHO|ECHOE;
	termio.c_iflag |= ICRNL;

#if defined(ECHOKE) && defined(ECHOCTL)
	termio.c_lflag |= ECHOKE|ECHOCTL;
#endif
#if defined(ECHOPRT) && defined(NOFLSH) && defined(TOSTOP)
	termio.c_lflag &= ~(ECHOPRT|NOFLSH|TOSTOP);
#endif
#ifdef	ONLCR
	termio.c_oflag |= ONLCR;
#endif

#ifdef	SUN4

	/*
	 * Terminal setup for SunOS 4.1 courtesy of Steve Allen
	 * at UCO/Lick.
	 */

	termio.c_cc[VEOF] = '\04';
	termio.c_cflag &= ~CSIZE;
	termio.c_cflag |= (PARENB|CS7);
	termio.c_lflag |= (ISIG|ICANON|ECHO|IEXTEN);
	termio.c_iflag |= (BRKINT|IGNPAR|ISTRIP|IMAXBEL|ICRNL|IXON);
	termio.c_iflag &= ~IXANY;
	termio.c_oflag |= (XTABS|OPOST|ONLCR);
#endif
	termio.c_cc[VERASE] = getdef_num("ERASECHAR", '\b');
	termio.c_cc[VKILL] = getdef_num("KILLCHAR", '\025');

	/*
	 * ttymon invocation prefers this, but these settings won't come into
	 * effect after the first username login 
	 */

#else
#endif	/* !BSD */
	STTY(0, &termio);
}


/*
 * Tell the user that this is not the right time to login at this tty
 */
static void
bad_time_notify()
{
	char *mesg = "Invalid login time\r\n";
#ifdef HUP_MESG_FILE
	FILE *mfp;

	if ((mfp = fopen(HUP_MESG_FILE, "r")) != NULL) {
		int c;

		while ((c = fgetc(mfp)) != EOF) {
        		if (c == '\n')
                		putchar('\r');
        		putchar(c);
		}
		fclose(mfp);
	} else
#endif
		printf(mesg);
	fflush(stdout);
}


static void
check_flags(argc, argv)
	int argc;
	char * const *argv;
{
	int arg;

	/*
	 * Check the flags for proper form.  Every argument starting with
	 * "-" must be exactly two characters long.  This closes all the
	 * clever rlogin, telnet, and getty holes.
	 */
	for (arg = 1; arg < argc; arg++) {
		if (argv[arg][0] == '-' && strlen(argv[arg]) > 2)
			usage();
	}
}


/*
 * login - create a new login session for a user
 *
 *	login is typically called by getty as the second step of a
 *	new user session.  getty is responsible for setting the line
 *	characteristics to a reasonable set of values and getting
 *	the name of the user to be logged in.  login may also be
 *	called to create a new user session on a pty for a variety
 *	of reasons, such as X servers or network logins.
 *
 *	the flags which login supports are
 *	
 *	-p - preserve the environment
 *	-r - perform autologin protocol for rlogin
 *	-f - do not perform authentication, user is preauthenticated
 *	-h - the name of the remote host
 */

int
main(argc, argv)
	int argc;
	char **argv;
{
	char	name[32];
	char	tty[BUFSIZ];
#ifdef RLOGIN
	char	term[128] = "";
#endif
	int	reason = PW_LOGIN;
	int	delay;
	int	retries;
	int	failed;
	int	flag;
	int	subroot = 0;
	int	is_console;
	char	*fname;
	char	*cp;
	char	*tmp;
	char	fromhost[512];
	struct	passwd	*pwd;
	char	**envp = environ;
#ifdef	SHADOWPWD
	struct	spwd	*spwd=NULL;
#endif
#ifdef RADIUS
	RAD_USER_DATA rad_user_data;
	int is_rad_login;
#endif
#if defined(RADIUS) || defined(DES_RPC) || defined(KERBEROS)
	/* from pwauth.c */
	extern char *clear_pass;
	extern int wipe_clear_pass;

	/*
	 * We may need the password later, don't want pw_auth() to wipe it
	 * (we do it ourselves when it is no longer needed).  --marekm
	 */
	wipe_clear_pass = 0;
#endif

	/*
	 * Some quick initialization.
	 */

	initenv();
	name[0] = '\0';
	amroot = (getuid() == 0);
	Prog = Basename(argv[0]);

	check_flags(argc, argv);

	while ((flag = getopt(argc, argv, "d:f:h:pr:")) != EOF) {
		switch (flag) {
		case 'p':
			pflg++;
			break;
		case 'f':
			/*
			 * username must be a separate token
			 * (-f root, *not* -froot).  --marekm
			 */
			if (optarg != argv[optind - 1])
				usage();
			fflg++;
			STRFCPY(name, optarg);
			break;
#ifdef	RLOGIN
		case 'r':
			rflg++;
			host = optarg;
			reason = PW_RLOGIN;
			break;
#endif
		case 'h':
			hflg++;
			host = optarg;
			reason = PW_TELNET;

                        if ((argc-optind > 0) &&
                            !(strncmp (*(argv+optind), "TERM=", 5)))
                        {
                          strncpy (term, *(argv+optind)+5, sizeof(term)-1);
                          term[sizeof(term)-1] = '\0';
                          optind++;
                        }

			break;
		case 'd':
			/* "-d device" ignored for compatibility */
			break;
		default:
			usage();
		}
	}

#ifdef RLOGIN
	/*
	 * Neither -h nor -f should be combined with -r.
	 */

	if (rflg && (hflg || fflg))
		usage();
#endif

	/*
	 * Allow authentication bypass only if real UID is zero.
	 */

	if ((rflg || fflg || hflg) && !amroot) {
		fprintf(stderr, "%s: permission denied\n", Prog);
		exit(1);
	}

	if (!isatty(0) || !isatty(1) || !isatty(2))
		exit(1);		/* must be a terminal */

#if 0
	/*
	 * Get the utmp file entry and get the tty name from it.  The
	 * current process ID must match the process ID in the utmp
	 * file if there are no additional flags on the command line.
	 */
	checkutmp(!rflg && !fflg && !hflg);
#else
	/*
	 * Be picky if run by normal users (possible if installed setuid
	 * root), but not if run by root.  This way it still allows logins
	 * even if your getty is broken, or if something corrupts utmp,
	 * but users must "exec login" which will use the existing utmp
	 * entry (will not overwrite remote hostname).  --marekm
	 */
	checkutmp(!amroot);
#endif
	STRFCPY(tty, utent.ut_line);
	is_console = console(tty);

	if (rflg || hflg) {
#ifdef	UT_HOST
		strncpy(utent.ut_host, host, sizeof(utent.ut_host));
#endif
#if HAVE_UTMPX_H
		strncpy(utxent.ut_host, host, sizeof(utxent.ut_host));
#endif
	}
/* workaround for init/getty leaving junk in ut_host at least in some
   version of RedHat.  --marekm */
#ifdef __linux__ 
	else if (amroot)
		bzero(utent.ut_host, sizeof utent.ut_host);
#endif
	if (hflg && fflg) {
		reason = PW_RLOGIN;
		preauth_flag++;
	}
#ifdef RLOGIN
	if (rflg && r_login(host, name, sizeof name, term, sizeof term))
		preauth_flag++;
#endif

#ifdef __ultrix
	openlog("login", LOG_PID);
#else
	openlog("login", LOG_PID|LOG_CONS|LOG_NOWAIT, LOG_AUTH);
#endif

	setup_tty();

	umask(getdef_num("UMASK", 077));

	{
		/* 
		 * Use the ULIMIT in the login.defs file, and if
		 * there isn't one, use the default value.  The
		 * user may have one for themselves, but otherwise,
		 * just take what you get.
		 */

		long limit = getdef_long("ULIMIT", -1L);

		if (limit != -1)
			set_filesize_limit(limit);
	}

	/*
	 * The entire environment will be preserved if the -p flag
	 * is used.
	 */

	if (pflg)
		while (*envp)		/* add inherited environment, */
			addenv(*envp++, NULL); /* some variables change later */

#ifdef RLOGIN
	if (term[0] != '\0')
		addenv("TERM", term);
	else
#endif
	/* preserve TERM from getty */
	if (!pflg && (tmp = getenv("TERM")))
		addenv("TERM", tmp);

	/*
	 * Add the timezone environmental variable so that time functions
	 * work correctly.
	 */

	if ((tmp = getenv("TZ"))) {
		addenv("TZ", tmp);
	} else if ((cp = getdef_str("ENV_TZ", NULL)))
		addenv(*cp == '/' ? tz(cp) : cp, NULL);

	/* 
	 * Add the clock frequency so that profiling commands work
	 * correctly.
	 */

	if ((tmp = getenv("HZ"))) {
		addenv("HZ", tmp);
	} else if ((cp = getdef_str("ENV_HZ", NULL)))
		addenv(cp, NULL);

	if (optind < argc) {		/* get the user name */
		if (rflg || fflg)
			usage();

		/*
		 * The "-h" option can't be used with a command-line username,
		 * because telnetd invokes us as: login -h host TERM=...
		 */
/*
#ifdef SVR4
		if (! hflg)
#endif
*/
		{
			STRFCPY(name, argv[optind]);
			++optind;
		}
	}
/* #ifdef SVR4 */
	/*
	 * check whether ttymon has done the prompt for us already
	 */

	{
	    char *ttymon_prompt;
	    if ((ttymon_prompt = getenv("TTYPROMPT")) != NULL &&
		    (*ttymon_prompt != 0)) {
		/* read name, without prompt */
		login_prompt((char *)0, name, sizeof name);
	    }
	}
/* #endif */ /* SVR4 */
	if (optind < argc)		/* now set command line variables */
		    set_env(argc - optind, &argv[optind]);

	if (rflg || hflg)
		cp = host;
	else
#ifdef	UT_HOST
	if (utent.ut_host[0])
		cp = utent.ut_host;
	else
#endif
#if HAVE_UTMPX_H
	if (utxent.ut_host[0])
		cp = utxent.ut_host;
	else
#endif
		cp = "";

	if (*cp)
		sprintf(fromhost, " on `%.100s' from `%.200s'", tty, cp);
	else
		sprintf(fromhost, " on `%.100s'", tty);

top:
	/* only allow ALARM sec. for login */
	alarm(getdef_num("LOGIN_TIMEOUT", ALARM));

	environ = newenvp;		/* make new environment active */
	delay = getdef_num("FAIL_DELAY", 1);
	retries = getdef_num("LOGIN_RETRIES", RETRIES);
	while (1) {	/* repeatedly get login/password pairs */
		failed = 0;		/* haven't failed authentication yet */
#ifdef RADIUS
		is_rad_login = 0;
#endif
		if (! name[0]) {	/* need to get a login id */
			if (subroot) {
				closelog ();
				exit (1);
			}
			preauth_flag = 0;
			login_prompt(LOGIN_PROMPT, name, sizeof name);
			continue;
		}
		if (! (pwd = getpwnam (name))) {
			pwent.pw_name = name;
			pwent.pw_passwd = "!";
			pwent.pw_shell = "/bin/sh";

			preauth_flag = 0;
			failed = 1;
		} else {
			pwent = *pwd;
		}

#ifdef	SHADOWPWD
		spwd = NULL;
		if (pwd && strcmp(pwd->pw_passwd, "x") == 0) {
			spwd = getspnam(name);
			if (spwd)
				pwent.pw_passwd = spwd->sp_pwdp;
			else
				SYSLOG((LOG_WARN, NO_SHADOW, name, fromhost));
		}
#endif	/* SHADOWPWD */

		/*
		 * If the encrypted password begins with a "!", the account
		 * is locked and the user cannot login, even if they have
		 * been "pre-authenticated."
		 */

		if (pwent.pw_passwd[0] == '!' || pwent.pw_passwd[0] == '*')
			failed = 1;

		/*
		 * The -r and -f flags provide a name which has already
		 * been authenticated by some server.
		 */

		if (preauth_flag)
			goto auth_ok;

#if 1
		/*
		 * Hack for passwordless accounts - not authenticated, but
		 * if login is denied for some reason (securetty etc.), the
		 * (dummy) password prompt will still appear (the bad guys
		 * won't know about the passwordless account).  --marekm
		 */
		if (pwent.pw_passwd[0] == '\0')
			goto auth_ok;
#endif

		if (pw_auth(pwent.pw_passwd, name, reason, (char *) 0) == 0)
			goto auth_ok;

#ifdef RADIUS
		/*
		 * If normal passwd authentication didn't work, try radius.
		 */
		
		if (failed) {
			pwd = rad_authenticate(&rad_user_data, name,
					       clear_pass ? clear_pass : "");
			if (pwd) {
				is_rad_login = 1;
				pwent = *pwd;
				failed = 0;
				goto auth_ok;
			}
		}
#endif /* RADIUS */

		/*
		 * Don't log unknown usernames - I mistyped the password for
		 * username at least once...  Should probably use LOG_AUTHPRIV
		 * for those who really want to log them.  --marekm
		 */
		SYSLOG((LOG_WARN, BAD_PASSWD,
			(pwd || getdef_bool("LOG_UNKFAIL_ENAB", 0)) ?
			name : "UNKNOWN", fromhost));
		failed = 1;

auth_ok:
		/*
		 * This is the point where all authenticated users
		 * wind up.  If you reach this far, your password has
		 * been authenticated and so on.
		 */

#if defined(RADIUS) && !(defined(DES_RPC) || defined(KERBEROS))
		if (clear_pass) {
			bzero(clear_pass, strlen(clear_pass));
			clear_pass = NULL;
		}
#endif

		if (getdef_bool("DIALUPS_CHECK_ENAB", 0)) {
			alarm (30);

			if (! dialcheck (tty, pwent.pw_shell[0] ?
					pwent.pw_shell:"/bin/sh")) {
				SYSLOG((LOG_WARN, BAD_DIALUP, name, tty));
				failed = 1;
			}
		}
#if 0  /* now done after the authentication.  --marekm */
		if (getdef_bool("PORTTIME_CHECKS_ENAB", 0) &&
		    !isttytime(pwent.pw_name, tty, time ((time_t *) 0))) {
			SYSLOG((LOG_WARN, BAD_TIME, name, fromhost));
			failed = 1;
		}
#endif
		if (! failed && pwent.pw_name && pwent.pw_uid == 0 &&
				! is_console) {
			SYSLOG((LOG_CRIT, BAD_ROOT_LOGIN, fromhost));
			failed = 1;
		}
#ifdef LOGIN_ACCESS
		if (!failed && !login_access(name, *host ? host : tty)) {
			SYSLOG((LOG_WARN, LOGIN_REFUSED, name, fromhost));
			failed = 1;
		}
#endif

		if (pwd && getdef_bool("FAILLOG_ENAB", 0) &&
				! failcheck (pwent.pw_uid, &faillog, failed)) {
			SYSLOG((LOG_CRIT, FAILURE_CNT, name, fromhost));
			failed = 1;
		}
		if (! failed)
			break;

		/* don't log non-existent users */
		if (pwd && getdef_bool("FAILLOG_ENAB", 0))
			failure (pwent.pw_uid, tty, &faillog);
		if (getdef_str("FTMP_FILE", NULL) != NULL) {
#if HAVE_UTMPX_H
			failent = utxent;
#else
			failent = utent;
#endif

			if (pwd)
				strncpy(failent.UT_USER, pwent.pw_name,
					sizeof(failent.UT_USER));
			else
				if (getdef_bool("LOG_UNKFAIL_ENAB", 0))
					strncpy(failent.UT_USER, name,
						sizeof(failent.UT_USER));
				else
					strncpy(failent.UT_USER, "UNKNOWN",
						sizeof(failent.UT_USER));
#if HAVE_UTMPX_H
			gettimeofday(&(failent.ut_tv), NULL);
#else
			time(&failent.ut_time);
#endif
#ifdef USER_PROCESS
			failent.ut_type = USER_PROCESS;
#endif
			failtmp(&failent);
		}
		bzero(name, sizeof name);

		if (--retries <= 0)
			SYSLOG((LOG_CRIT, MANY_FAILS, fromhost));
#if 1
		/*
		 * If this was a passwordless account and we get here,
		 * login was denied (securetty, faillog, etc.).  There
		 * was no password prompt, so do it now (will always
		 * fail - the bad guys won't see that the passwordless
		 * account exists at all).  --marekm
		 */

		if (pwent.pw_passwd[0] == '\0')
			pw_auth("!", name, reason, (char *) 0);
#endif
		/*
		 * Wait a while (a la SVR4 /usr/bin/login) before attempting
		 * to login the user again.  If the earlier alarm occurs
		 * before the sleep() below completes, login will exit.
		 */

		if (delay > 0)
			sleep(delay);

		puts ("Login incorrect");

		/* allow only one attempt with -r or -f */
		if (rflg || fflg || retries <= 0) {
			closelog();
			exit(1);
		}
	}
	(void) alarm (0);		/* turn off alarm clock */
#if 1
	/*
	 * porttime checks moved here, after the user has been
	 * authenticated.  now prints a message, as suggested
	 * by Ivan Nejgebauer <ian@unsux.ns.ac.yu>.  --marekm
	 */
	if (getdef_bool("PORTTIME_CHECKS_ENAB", 0) &&
	    !isttytime(pwent.pw_name, tty, time ((time_t *) 0))) {
		SYSLOG((LOG_WARN, BAD_TIME, name, fromhost));
		closelog();
		bad_time_notify();
		exit(1);
	}
#endif

	/*
	 * Check to see if system is turned off for non-root users.
	 * This would be useful to prevent users from logging in
	 * during system maintenance.  We make sure the message comes
	 * out for root so she knows to remove the file if she's
	 * forgotten about it ...
	 */

	fname = getdef_str("NOLOGINS_FILE", NULL);
	if (fname != NULL && access (fname, 0) == 0) {
		FILE	*nlfp;
		int	c;

		/*
		 * Cat the file if it can be opened, otherwise just
		 * print a default message
		 */

		if ((nlfp = fopen (fname, "r"))) {
			while ((c = getc (nlfp)) != EOF) {
				if (c == '\n')
					putchar ('\r');

				putchar (c);
			}
			fflush (stdout);
			fclose (nlfp);
		} else
			printf ("\r\nSystem closed for routine maintenance\r\n");
		/*
		 * Non-root users must exit.  Root gets the message, but
		 * gets to login.
		 */

		if (pwent.pw_uid != 0) {
			closelog();
			exit(0);
		}
		printf ("\r\n[Disconnect bypassed -- root login allowed.]\r\n");
	}
	if (getenv("IFS"))		/* don't export user IFS ... */
		addenv("IFS= \t\n", NULL);  /* ... instead, set a safe IFS */

	setutmp(name, tty);		/* make entry in utmp & wtmp files */
	if (pwent.pw_shell[0] == '*') {	/* subsystem root */
		subsystem (&pwent);	/* figure out what to execute */
		subroot++;		/* say i was here again */
		endpwent ();		/* close all of the file which were */
		endgrent ();		/* open in the original rooted file */
#ifdef	SHADOWPWD
		endspent ();		/* system.  they will be re-opened */
#endif
#ifdef	SHADOWGRP
		endsgent ();		/* in the new rooted file system */
#endif
		goto top;		/* go do all this all over again */
	}
	if (getdef_bool("LASTLOG_ENAB", 1)) /* give last login and log this one */
		dolastlog(&lastlog, &pwent, utent.ut_line, host);

#ifdef SVR4_SI86_EUA
	sysi86(SI86LIMUSER, EUA_ADD_USER);	/* how do we test for fail? */
#endif

#ifdef LOGIN_FBTAB
	/*
	 * XXX - not supported yet.  Change permissions and ownerships of
	 * devices like floppy/audio/mouse etc. for console logins, based
	 * on /etc/fbtab or /etc/logindevperm configuration files (Suns do
	 * this with their framebuffer devices).  Problems:
	 *
	 * - most systems (except BSD) don't have that nice revoke() system
	 * call to ensure the previous user didn't leave a process holding
	 * one of these devices open or mmap'ed.  Any volunteers to do it
	 * in Linux?
	 *
	 * - what to do with different users logged in on different virtual
	 * consoles?  Maybe permissions should be changed only on user's
	 * request, by running a separate (setuid root) program?
	 *
	 * - init/telnetd/rlogind/whatever should restore permissions after
	 * the user logs out.
	 *
	 * Try the new CONSOLE_GROUPS feature instead.  It adds specified
	 * groups (like "floppy") to the group set if the user is logged in
	 * on the console.  This still has the first problem (users leaving
	 * processes with these devices open), but doesn't need to change
	 * any permissions, just make them 0660 root.floppy etc.  --marekm
	 */
	login_fbtab(tty, pwent.pw_uid, pwent.pw_gid);
#endif

	login_fbtab(tty, pwent.pw_uid, pwent.pw_gid);

#ifdef	AGING
	/*
	 * Have to do this while we still have root privileges, otherwise
	 * we don't have access to /etc/shadow.  expire() closes password
	 * files, and changes to the user in the child before executing
	 * the passwd program.  --marekm
	 */
#ifdef	SHADOWPWD
	if (spwd) {			/* check for age of password */
		if (expire (&pwent, spwd)) {
			pwd = getpwnam(name);
			spwd = getspnam(name);
			if (pwd)
				pwent = *pwd;
		}
	}
#else
#ifdef	ATT_AGE
	if (pwent.pw_age && pwent.pw_age[0]) {
		if (expire (&pwent)) {
			pwd = getpwnam (name);
			if (pwd)
				pwent = *pwd;
		}
	}
#endif	/* ATT_AGE */
#endif /* SHADOWPWD */
#endif	/* AGING */

	/* CHECK IF RESET PASSWORD DUE TO NO TPASSWD */
        {
/*
		struct t_pw *tpw = t_openpw (NULL);

                if (tpw == NULL)
                {
                  creat (DEFAULT_PASSWD, 0400);
                  tpw = t_openpw (NULL);
                }

		if (tpw == NULL) SYSLOG ((LOG_WARN, NO_TPASSWD_FILE));
		else if (t_getpwbyname (tpw, name) == NULL)
*/
		if(gettpnam(name) == NULL)
		{
		  printf (NEW_PASS);
		  run_passwd (&pwent);
		}

/*
		if (tpw != NULL) t_closepw (tpw);
*/
	}

#ifdef RADIUS
	if (is_rad_login) {
		char whofilename[128];
		FILE *whofile;

		sprintf(whofilename, "/var/log/radacct/%.20s", tty);
		whofile = fopen(whofilename, "w");
		if (whofile) {
			fprintf(whofile, "%s\n", name);
			fclose(whofile);
		}
	}
#endif
	setup_limits(&pwent);  /* nice, ulimit etc. */
	chown_tty(tty, &pwent);
	if(setup_uid_gid(&pwent, is_console))
		exit(1);
#ifdef KERBEROS
	if (clear_pass)
		login_kerberos(name, clear_pass);
#endif
#ifdef DES_RPC
	if (clear_pass)
		login_desrpc(clear_pass);
#endif
#if defined(DES_RPC) || defined(KERBEROS)
	if (clear_pass)
		bzero(clear_pass, strlen(clear_pass));
#endif

	setup_env(&pwent);  /* set env vars, cd to the home dir */

	if (! hushed (&pwent)) {
		addenv("HUSHLOGIN=FALSE", NULL);
		motd ();		/* print the message of the day */
		if (getdef_bool("FAILLOG_ENAB", 0) && faillog.fail_cnt != 0) {
			failprint(&faillog);
			/* Reset the lockout times if logged in */
			if (faillog.fail_max &&
			    faillog.fail_cnt >= faillog.fail_max) {
				puts(REENABLED);
				SYSLOG((LOG_WARN, REENABLED2, name,
					(int) faillog.fail_cnt));
			}
		}
		if (getdef_bool("LASTLOG_ENAB", 1) && lastlog.ll_time != 0) {
			printf ("Last login: %.19s on %s",
				ctime(&lastlog.ll_time), lastlog.ll_line);
#ifdef HAVE_LL_HOST  /* SVR4 || __linux__ || SUN4 */
			if (lastlog.ll_host[0])
				printf(" from %.*s",
				       (int) sizeof lastlog.ll_host,
				       lastlog.ll_host);
#endif
			printf(".\n");
		}
#ifdef	AGING
#ifdef	SHADOWPWD
		agecheck (&pwent, spwd);
#else
		agecheck (&pwent);
#endif
#endif	/* AGING */
		mailcheck ();	/* report on the status of mail */
	} else
		addenv("HUSHLOGIN=TRUE", NULL);

	if (getdef_str("TTYTYPE_FILE", NULL) != NULL && getenv("TERM") == NULL)
  		ttytype (tty);

	signal (SIGINT, SIG_DFL);	/* default interrupt signal */
	signal (SIGQUIT, SIG_DFL);	/* default quit signal */
	signal (SIGTERM, SIG_DFL);	/* default terminate signal */
	signal (SIGALRM, SIG_DFL);	/* default alarm signal */
	signal (SIGHUP, SIG_DFL);	/* added this.  --marekm */

	endpwent ();			/* stop access to password file */
	endgrent ();			/* stop access to group file */
#ifdef	SHADOWPWD
	endspent ();			/* stop access to shadow passwd file */
#endif
#ifdef	SHADOWGRP
	endsgent ();			/* stop access to shadow group file */
#endif
	if (pwent.pw_uid == 0)
		SYSLOG((LOG_NOTICE, ROOT_LOGIN, fromhost));
	else if (getdef_bool("LOG_OK_LOGINS", 0))
		SYSLOG((LOG_INFO, REG_LOGIN, name, fromhost));
	closelog ();
#ifdef RADIUS
	if (is_rad_login) {
		printf("Starting rad_login\n");
		rad_login(&rad_user_data);
		exit(0);
	}
#endif
	shell (pwent.pw_shell, (char *) 0); /* exec the shell finally. */
	/*NOTREACHED*/
	return (0);
}
