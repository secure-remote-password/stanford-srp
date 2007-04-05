/*
 * $Id: eps_chkpwd.c,v 1.1 2000/12/17 05:34:11 tom Exp $
 *
 * This program is designed to run setuid(root) or with sufficient
 * privilege to read all of the unix password databases. It is designed
 * to provide a mechanism for the current user (defined by this
 * process' uid) to verify their own password.
 *
 * The password is read from the standard input. The exit status of
 * this program indicates whether the user is authenticated or not.
 *
 * Copyright information is located at the end of the file.
 *
 *  This program has been shamelessly plagarized and adapted
 *  for the needs of srp-1.5.1 pam_eps_auth by Hugh McDonald
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif /* HAVE_SHADOW_H */
#include <signal.h>

#define MAXPASS		200	/* the maximum length of a password */

#define UNIX_PASSED	0
#define UNIX_FAILED	1

/* syslogging function for errors and other information */

static void _log_err(int err, const char *format,...)
{
	va_list args;

	va_start(args, format);
	openlog("eps_chkpwd", LOG_CONS | LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

static void su_sighandler(int sig)
{
	if (sig > 0) {
		_log_err(LOG_NOTICE, "caught signal %d.", sig);
		exit(sig);
	}
}

static void setup_signals(void)
{
	struct sigaction action;	/* posix signal structure */

	/*
	 * Setup signal handlers
	 */
	(void) memset((void *) &action, 0, sizeof(action));
	action.sa_handler = su_sighandler;
	action.sa_flags = SA_RESETHAND;
	(void) sigaction(SIGILL, &action, NULL);
	(void) sigaction(SIGTRAP, &action, NULL);
	(void) sigaction(SIGBUS, &action, NULL);
	(void) sigaction(SIGSEGV, &action, NULL);
	action.sa_handler = SIG_IGN;
	action.sa_flags = 0;
	(void) sigaction(SIGTERM, &action, NULL);
	(void) sigaction(SIGHUP, &action, NULL);
	(void) sigaction(SIGINT, &action, NULL);
	(void) sigaction(SIGQUIT, &action, NULL);
}

static char *getuidname(uid_t uid)
{
	struct passwd *pw;
	static char username[32];

	pw = getpwuid(uid);
	if (pw == NULL)
		return NULL;

	memset(username, 0, 32);
	strncpy(username, pw->pw_name, 32);
	username[31] = '\0';
	
	return username;
}

int main(int argc, char *argv[])
{
	char pass[MAXPASS + 1];
	char option[8];
	int npass, opt;
	int retval = UNIX_FAILED;
	char *user;

	/*
	 * Catch or ignore as many signal as possible.
	 */
	setup_signals();

	/*
	 * we establish that this program is running with non-tty stdin.
	 * this is to discourage casual use. It does *NOT* prevent an
	 * intruder from repeatadly running this program to determine the
	 * password of the current user (brute force attack, but one for
	 * which the attacker must already have gained access to the user's
	 * account).
	 */

	if (isatty(STDIN_FILENO)) {

		_log_err(LOG_NOTICE
		      ,"inappropriate use of eps_chkpwd [UID=%d]"
			 ,getuid());
		fprintf(stderr
		 ,"This binary is not designed for running in this way\n"
		      "-- the system administrator has been informed\n");
		sleep(10);	/* this should discourage/annoy the user */
		return UNIX_FAILED;
	}
	/*
	 * determine the current user's name is
	 * 1. supplied as a environment variable as LOGNAME
	 * 2. the uid has to match the one associated with the LOGNAME.
	 */
	user = getuidname(getuid());

	/* read the nollok/nonull option */

	npass = read(STDIN_FILENO, option, 2);

	if ((npass < 0) || (strncmp ("1:", option, 2) != 0)) {
		_log_err(LOG_DEBUG, "no option supplied");
		return UNIX_FAILED;
	};

	/* read the password from stdin (a pipe from the pam_unix module) */

	npass = read(STDIN_FILENO, pass, MAXPASS);

	if (npass < 0) {	/* is it a valid password? */

		_log_err(LOG_DEBUG, "no password supplied");

	} else if (npass >= MAXPASS) {

		_log_err(LOG_DEBUG, "password too long");

	} else {
		pass[npass]= (char)NULL;
		retval = t_verifypw(user, pass);
	}

	memset(pass, '\0', MAXPASS);	/* clear memory of the password */

	/* return pass or fail */

	return retval;
}

/*
 * Copyright (c) Andrew G. Morgan, 1996. All rights reserved
 *
 * (pam_eps_auth hacks Copyright (c) Hugh McDonald, 2000.  All rights reserved)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
