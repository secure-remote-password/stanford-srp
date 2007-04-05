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
RCSID("$Id: su.c,v 1.1 2000/12/17 05:34:12 tom Exp $")

#include <sys/types.h>
#include <stdio.h>

#include "prototypes.h"
#include "defines.h"

#include <grp.h>
#include <signal.h>
#include <pwd.h>
#include "pwauth.h"
#include "getdef.h"

static	char	*NOT_WHEEL = "You are not authorized to su %s\n";

/*
 * Assorted #defines to control su's behavior
 */

/*
 * Global variables
 */

/* needed by sulog.c */
char	name[BUFSIZ];
char	oldname[BUFSIZ];

static char *Prog;

struct	passwd	pwent;

/*
 * External identifiers
 */

extern char **newenvp;
extern size_t newenvc;

extern	void	sulog();
extern	void	subsystem();
extern	void	setup();
extern	void	motd();
extern	void	mailcheck();
extern	char	*tz();
extern int check_su_auth();
extern	char	**environ;

/*
 * die - set or reset termio modes.
 *
 *	die() is called before processing begins.  signal() is then
 *	called with die() as the signal handler.  If signal later
 *	calls die() with a signal number, the terminal modes are
 *	then reset.
 */

static RETSIGTYPE
die (killed)
	int killed;
{
	static TERMIO sgtty;

	if (killed)
		STTY(0, &sgtty);
	else
		GTTY(0, &sgtty);

	if (killed) {
		closelog();
		exit(killed);
	}
}

static int
iswheel(name)
	const char *name;
{
	struct group *grp;

	grp = getgrgid(0);
	if (!grp || !grp->gr_mem)
		return 0;
	return is_on_list(grp->gr_mem, name);
}

/*
 * su - switch user id
 *
 *	su changes the user's ids to the values for the specified user.
 *	if no new user name is specified, "root" is used by default.
 *
 *	The only valid option is a "-" character, which is interpreted
 *	as requiring a new login session to be simulated.
 *
 *	Any additional arguments are passed to the user's shell.  In
 *	particular, the argument "-c" will cause the next argument to
 *	be interpreted as a command by the common shell programs.
 */

int
main(argc, argv)
	int argc;
	char **argv;
{
	RETSIGTYPE	(*oldsig)();
	char	*cp;
	char	*tty = 0;		/* Name of tty SU is run from        */
	int	doshell = 0;
	int	fakelogin = 0;
	int	amroot = 0;
	int	my_uid;
	int	is_console = 0;
	struct	passwd	*pw = 0;
	char	**envp = environ;
#ifdef	SHADOWPWD
	struct	spwd	*spwd = 0;
#endif
#ifdef SU_ACCESS
	char *oldpass;
#endif
	/*
	 * Get the program name.  The program name is used as a
	 * prefix to most error messages.
	 */

	Prog = Basename(argv[0]);

#ifdef __ultrix
	openlog("su", LOG_PID);
#else
	openlog("su", LOG_PID|LOG_CONS|LOG_NOWAIT, LOG_AUTH);
#endif

	initenv();

	/*
	 * Get the tty name.  Entries will be logged indicating that
	 * the user tried to change to the named new user from the
	 * current terminal.
	 */

	if (isatty (0) && (cp = ttyname (0))) {
		if (strncmp (cp, "/dev/", 5) == 0)
			tty = cp + 5;
		else
			tty = cp;
		is_console = console(tty);
	} else
		tty = "???";

	/*
	 * Process the command line arguments. 
	 */

	argc--; argv++;			/* shift out command name */

	if (argc > 0 && argv[0][0] == '-' && argv[0][1] == '\0') {
		fakelogin = 1;
		argc--; argv++;		/* shift ... */
	}

	/*
	 * If a new login is being set up, the old environment will
	 * be ignored and a new one created later on.
	 */

	if (! fakelogin)
		while (*envp)
			addenv(*envp++, NULL);

	if (fakelogin && (cp=getdef_str("ENV_TZ", NULL)))
		addenv(*cp == '/' ? tz(cp) : cp, NULL);

	/*
	 * The clock frequency will be reset to the login value if required
	 */

	if (fakelogin && (cp=getdef_str("ENV_HZ", NULL)) )
		addenv(cp, NULL);	/* set the default $HZ, if one */

	/*
	 * The terminal type will be left alone if it is present in the
	 * environment already.
	 */

	if (fakelogin && (cp = getenv ("TERM")))
		addenv("TERM", cp);

	/*
	 * The next argument must be either a user ID, or some flag to
	 * a subshell.  Pretty sticky since you can't have an argument
	 * which doesn't start with a "-" unless you specify the new user
	 * name.  Any remaining arguments will be passed to the user's
	 * login shell.
	 */

	if (argc > 0 && argv[0][0] != '-') {
		STRFCPY(name, argv[0]);	/* use this login id */
		argc--; argv++;		/* shift ... */
	}
	if (! name[0]) 			/* use default user ID */
		(void) strcpy (name, "root");

	doshell = argc == 0;		/* any arguments remaining? */

	/*
	 * Get the user's real name.  The current UID is used to determine
	 * who has executed su.  That user ID must exist.
	 */

	my_uid = getuid();
	amroot = (my_uid == 0);

	pw = get_my_pwent();
	if (!pw) {
		SYSLOG((LOG_CRIT, "Unknown UID: %d\n", my_uid));
		goto failure;
	}
	STRFCPY(oldname, pw->pw_name);

#ifdef SU_ACCESS
	/*
	 * Sort out the password of user calling su, in case needed later
	 * -- chris
	 */
#ifdef SHADOWPWD
	if ((spwd = getspnam(oldname)))
		pw->pw_passwd = spwd->sp_pwdp;
#endif
	oldpass = xstrdup(pw->pw_passwd);
#endif  /* SU_ACCESS */

top:
	/*
	 * This is the common point for validating a user whose name
	 * is known.  It will be reached either by normal processing,
	 * or if the user is to be logged into a subsystem root.
	 *
	 * The password file entries for the user is gotten and the
	 * account validated.
	 */

	if (!(pw = getpwnam(name))) {
		(void) fprintf (stderr, "Unknown id: %s\n", name);
		closelog();
		exit(1);
	}

#ifdef SHADOWPWD
	spwd = NULL;
	if (strcmp(pw->pw_passwd, "x") == 0 && (spwd = getspnam(name)))
		pw->pw_passwd = spwd->sp_pwdp;
#endif
	pwent = *pw;

	/*
	 * BSD systems only allow "wheel" to SU to root.  USG systems
	 * don't, so we make this a configurable option.
	 */

	/* The original Shadow 3.3.2 did this differently.  Do it like BSD:

	   - check for uid 0 instead of name "root" - there are systems
	   with several root accounts under different names,

	   - check the contents of /etc/group instead of the current group
	   set (you must be listed as a member, GID 0 is not sufficient).

	   In addition to this traditional feature, we now have complete
	   su access control (allow, deny, no password, own password).
	   Thanks to Chris Evans <lady0110@sable.ox.ac.uk>.  */

	if (!amroot) {
		if (pwent.pw_uid == 0 && getdef_bool("SU_WHEEL_ONLY", 0)
		    && !iswheel(oldname)) {
			fprintf(stderr, NOT_WHEEL, name);
			exit(1);
		}
#ifdef SU_ACCESS
		switch (check_su_auth(oldname, name)) {
		case 0:  /* normal su, require target user's password */
			break;
		case 1:  /* require no password */
			pwent.pw_passwd = "";
			break;
		case 2:  /* require own password */
			puts("(Enter your own password.)");
			pwent.pw_passwd = oldpass;
			break;
		default:  /* access denied (-1) or unexpected value */
			fprintf(stderr, NOT_WHEEL, name);
			exit(1);
		}
#endif  /* SU_ACCESS */
	}
	/*
	 * Set the default shell.
	 */

	if (pwent.pw_shell[0] == '\0')
		pwent.pw_shell = "/bin/sh";

	/*
	 * Set up a signal handler in case the user types QUIT.
	 */

	die (0);
	oldsig = signal (SIGQUIT, die);

	/*
	 * See if the system defined authentication method is being used.
	 * The first character of an administrator defined method is an
	 * '@' character.
	 */

	if (! amroot && pw_auth (pwent.pw_passwd, name, PW_SU, (char *) 0)) {
		SYSLOG((pwent.pw_uid ? LOG_NOTICE:LOG_WARN,
			"Authentication failed for %s\n", name));
failure:
		sulog (tty, 0);		/* log failed attempt */
#ifdef USE_SYSLOG
		if (getdef_bool("SYSLOG_SU_ENAB", 0))
			SYSLOG((pwent.pw_uid ? LOG_INFO:LOG_NOTICE,
				"- %s %s-%s\n", tty,
				oldname[0] ? oldname:"???",
				name[0] ? name:"???"));
		closelog();
#endif
		puts ("Sorry.");
		exit (1);
	}

	(void) signal (SIGQUIT, oldsig);

	/*
	 * Check to see if the account is expired.  root gets to
	 * ignore any expired accounts, but normal users can't become
	 * a user with an expired password.
	 */

	if (! amroot) {
#ifdef	SHADOWPWD
		if (!spwd)
			spwd = pwd_to_spwd(&pwent);

		if (isexpired(&pwent, spwd)) {
			SYSLOG((pwent.pw_uid ? LOG_WARN : LOG_CRIT,
				"Expired account %s\n", name));
			goto failure;
		}
#else
#if defined(ATT_AGE) && defined(AGING)
		else if (pwent.pw_age[0] &&
				isexpired (&pwent)) {
			SYSLOG((pwent.pw_uid ? LOG_WARN:LOG_CRIT,
				"Expired account %s\n", name));
			goto failure;
		}
#endif	/* ATT_AGE */
#endif
	}

	/*
	 * Check to see if the account permits "su".  root gets to
	 * ignore any restricted accounts, but normal users can't become
	 * a user if there is a "SU" entry in the /etc/porttime file
	 * denying access to the account.
	 */

	if (! amroot) {
		if (! isttytime (pwent.pw_name, "SU", time ((time_t *) 0))) {
			SYSLOG((pwent.pw_uid ? LOG_WARN : LOG_CRIT,
				"SU by %s to restricted account %s\n",
					oldname, name));
			goto failure;
		}
	}

	cp = getdef_str(pwent.pw_uid == 0 ? "ENV_SUPATH" : "ENV_PATH", NULL);
	addenv(cp ? cp : "PATH=/bin:/usr/bin", NULL);

	environ = newenvp;		/* make new environment active */

	if (getenv ("IFS"))		/* don't export user IFS ... */
		addenv("IFS= \t\n", NULL);	/* ... instead, set a safe IFS */

	if (pwent.pw_shell[0] == '*') { /* subsystem root required */
		subsystem (&pwent);	/* figure out what to execute */
		endpwent ();
#ifdef SHADOWPWD
		endspent ();
#endif
		goto top;
	}

	sulog (tty, 1);			/* save SU information */
	endpwent ();
#ifdef SHADOWPWD
	endspent ();
#endif
#ifdef USE_SYSLOG
	if (getdef_bool("SYSLOG_SU_ENAB", 0))
		SYSLOG((LOG_INFO, "+ %s %s-%s\n", tty,
			oldname[0] ? oldname:"???", name[0] ? name:"???"));
#endif
	if (!amroot)  /* no limits if su from root */
		setup_limits(&pwent);

	if (setup_uid_gid(&pwent, is_console))
		exit(1);

	if (fakelogin)
		setup_env(&pwent);
#if 1  /* Suggested by Joey Hess.  */
	else
		addenv("HOME", pwent.pw_dir);
#endif

	/*
	 * This is a workaround for Linux libc bug/feature (?) - the
	 * /dev/log file descriptor is open without the close-on-exec
	 * flag and used to be passed to the new shell.  There is
	 * "fcntl(LogFile, F_SETFD, 1)" in libc/misc/syslog.c, but is
	 * commented out (at least in 4.6.27).  Why?  --marekm
	 */
	closelog();

	/*
	 * See if the user has extra arguments on the command line.  In
	 * that case they will be provided to the new user's shell as
	 * arguments.
	 */

	if (! doshell) {

		/*
		 * Use new user's shell from /etc/passwd and create an
		 * argv with the rest of the command line included.
		 */

		argv[-1] = pwent.pw_shell;
		(void) execv (pwent.pw_shell, &argv[-1]);
		(void) fprintf (stderr, "No shell\n");
		SYSLOG((LOG_WARN, "Cannot execute %s\n", pwent.pw_shell));
		closelog();
		exit (1);
	}
	if (fakelogin) {
		char *arg0;

#if 0  /* XXX - GNU su doesn't do this.  --marekm */
		if (! hushed (&pwent)) {
			motd ();
			mailcheck ();
		}
#endif
		cp = getdef_str("SU_NAME", NULL);
		if (!cp)
			cp = Basename(pwent.pw_shell);

		arg0 = xmalloc(strlen(cp) + 2);
		arg0[0] = '-';
		strcpy(arg0 + 1, cp);
		cp = arg0;
	} else
		cp = Basename(pwent.pw_shell);

	shell (pwent.pw_shell, cp);
	/*NOTREACHED*/
	return 1;
}
