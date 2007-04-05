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

/*
 * Separated from setup.c.  --marekm
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: setupenv.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>

#include "prototypes.h"
#include "defines.h"
#include <pwd.h>
#include "getdef.h"

static void
addenv_mail(maildir, mailfile)
	const char *maildir;
	const char *mailfile;
{
	char *buf;

	buf = xmalloc(strlen(maildir) + strlen(mailfile) + 2);
	sprintf(buf, "%s/%s", maildir, mailfile);
	addenv("MAIL", buf);
	free(buf);
}

static void
addenv_qmail(maildir, mailfile)
	const char *maildir;
	const char *mailfile;
{
	char *buf;

	buf = xmalloc(strlen(maildir) + strlen(mailfile) + 2);
	sprintf(buf, "%s/%s", maildir, mailfile);
	addenv("MAILDIR", buf);
	free(buf);
}

/*
 *	change to the user's home directory
 *	set the HOME, SHELL, MAIL, PATH, and LOGNAME or USER environmental
 *	variables.
 */

void
setup_env(info)
	struct passwd *info;
{
	char *cp, *envf;
	char buf[1024];
	FILE *fp;

	/*
	 * Change the current working directory to be the home directory
	 * of the user.  It is a fatal error for this process to be unable
	 * to change to that directory.  There is no "default" home
	 * directory.
	 *
	 * We no longer do it as root - should work better on NFS-mounted
	 * home directories.  Some systems default to HOME=/, so we make
	 * this a configurable option.  --marekm
	 */

	if (chdir(info->pw_dir) == -1) {
		if (!getdef_bool("DEFAULT_HOME", 0) || chdir("/") == -1) {
			fprintf(stderr, "Unable to cd to \"%s\"",
				info->pw_dir);
			SYSLOG((LOG_WARN,
				"unable to cd to `%s' for user `%s'\n",
				info->pw_dir, info->pw_name));
			closelog();
			exit (1);
		}
		puts("No directory, logging in with HOME=/");
		info->pw_dir = "/";
	}

	/*
	 * Create the HOME environmental variable and export it.
	 */

	addenv("HOME", info->pw_dir);

	/*
	 * Create the SHELL environmental variable and export it.
	 */

	if (info->pw_shell == (char *) 0 || ! *info->pw_shell)
		info->pw_shell = "/bin/sh";

	addenv("SHELL", info->pw_shell);

	/*
	 * Create the PATH environmental variable and export it.
	 */

	cp = getdef_str( info->pw_uid == 0 ? "ENV_SUPATH" : "ENV_PATH", NULL );
	addenv(cp ? cp : "PATH=/bin:/usr/bin", NULL);

	/*
	 * Export the user name.  For BSD derived systems, it's "USER", for
	 * all others it's "LOGNAME".  We set both of them.
	 */

	addenv("USER", info->pw_name);
	addenv("LOGNAME", info->pw_name);

	/*
	 * MAILDIR environment variable for Qmail
	 */
	if ((cp=getdef_str("QMAIL_DIR", NULL)))
		addenv_qmail(info->pw_dir, cp);

	/*
	 * Create the MAIL environmental variable and export it.  login.defs
	 * knows the prefix.
	 */

	if ((cp=getdef_str("MAIL_DIR", NULL)))
		addenv_mail(cp, info->pw_name);
	else if ((cp=getdef_str("MAIL_FILE", NULL)))
		addenv_mail(info->pw_dir, cp);
	else {
#if defined(MAIL_SPOOL_FILE)
		addenv_mail(info->pw_dir, MAIL_SPOOL_FILE);
#elif defined(MAIL_SPOOL_DIR)
		addenv_mail(MAIL_SPOOL_DIR, info->pw_name);
#endif
	}

	/*
	 * Read environment from optional config file.  --marekm
	 */
	if ((envf = getdef_str("ENVIRON_FILE", NULL)) && (fp = fopen(envf, "r"))) {
		while (fgets(buf, sizeof buf, fp) == buf) {
			cp = strchr(buf, '\n');
			if (!cp)
				break;
			*cp = '\0';
			if (buf[0] == '#' || buf[0] == '\0')
				continue;
			addenv(buf, NULL);
		}
		fclose(fp);
	}
}
