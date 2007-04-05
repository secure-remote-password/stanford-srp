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

#include "defines.h"

#include <utmp.h>

#if HAVE_UTMPX_H
#include <utmpx.h>
#endif

#include <fcntl.h>
#include <stdio.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "rcsid.h"
RCSID("$Id: utmp.c,v 1.4 2003/04/22 02:25:19 tom Exp $")

#if HAVE_UTMPX_H
extern	struct	utmpx	utxent;
extern char *host;
#endif
extern	struct	utmp	utent;

#ifndef HAVE_UTMP_H
extern	struct	utmp	*getutent();
extern	struct	utmp	*getutline();
extern	void	setutent();
extern	void	endutent();
#endif
extern	time_t	time();
extern	char	*ttyname();
extern	off_t	lseek();

#define	NO_UTENT \
	"No utmp entry.  You must exec \"login\" from the lowest level \"sh\""
#define	NO_TTY \
	"Unable to determine your tty name."

/*
 * checkutmp - see if utmp file is correct for this process
 *
 *	System V is very picky about the contents of the utmp file
 *	and requires that a slot for the current process exist.
 *	The utmp file is scanned for an entry with the same process
 *	ID.  If no entry exists the process exits with a message.
 *
 *	The "picky" flag is for network and other logins that may
 *	use special flags.  It allows the pid checks to be overridden.
 *	This means that getty should never invoke login with any
 *	command line flags.
 */

void
checkutmp (picky)
	int picky;
{
	char	*line;
#ifdef LOGIN_PROCESS /* USG */
#if HAVE_UTMPX_H
#include <utmpx.h>
	struct	utmpx	*utx;
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#else
	struct	utmp	*getutline();
#endif
	struct	utmp	*ut;
#ifdef DEBUG
	pid_t pid = getppid();
#else
	pid_t pid = getpid();
#endif
#endif

#if HAVE_UTMPX_H
	setutxent ();
#endif
#if HAVE_SETUTENT
	setutent ();
#endif	/* !SUN */

#if defined(__linux__)
	/* First, try to find a valid utmp entry for this process.  */
	while ((ut = getutent()))
		if (ut->ut_pid == pid && ut->ut_line[0] && ut->ut_id[0] &&
		    (ut->ut_type==LOGIN_PROCESS || ut->ut_type==USER_PROCESS))
			break;

	/* If there is one, just use it, otherwise create a new one.  */
	if (ut) {
		utent = *ut;
	} else {
		if (picky) {
			puts(NO_UTENT);
			exit(1);
		}
		line = ttyname(0);
		if (!line) {
			puts(NO_TTY);
			exit(1);
		}
		if (strncmp(line, "/dev/", 5) == 0)
			line += 5;
		memset((void *) &utent, 0, sizeof utent);
		utent.ut_type = LOGIN_PROCESS;
		utent.ut_pid = pid;
		strncpy(utent.ut_line, line, sizeof utent.ut_line);
		/* XXX - assumes /dev/tty?? */
		strncpy(utent.ut_id, utent.ut_line + 3, sizeof utent.ut_id);
		strncpy(utent.ut_user, "LOGIN", sizeof utent.ut_user);
		time(&utent.ut_time);
	}
#elif defined(LOGIN_PROCESS)
	if (picky) {
#if HAVE_UTMPX_H
		while ((utx = getutxent()))
			if (utx->ut_pid == pid)
				break;

		if (utx)
			utxent = *utx;
#endif
		while ((ut = getutent()))
			if (ut->ut_pid == pid)
				break;

		if (ut)
			utent = *ut;

#if HAVE_UTMPX_H
		endutxent();
#endif
		endutent();

		if (!ut) {
 			puts(NO_UTENT);
			exit(1);
		}
#ifndef	UNIXPC

		/*
		 * If there is no ut_line value in this record, fill
		 * it in by getting the TTY name and stuffing it in
		 * the structure.  The UNIX/PC is broken in this regard
		 * and needs help ...
		 */

		if (utent.ut_line[0] == '\0')
#endif	/* !UNIXPC */
		{
			if (!(line = ttyname(0))) {
				puts(NO_TTY);
				exit(1);
			}
			if (strncmp(line, "/dev/", 5) == 0)
				line += 5;
			strncpy(utent.ut_line, line, sizeof utent.ut_line);
#if HAVE_UTMPX_H
			strncpy(utxent.ut_line, line, sizeof utxent.ut_line);
#endif
		}
	} else {
		if (!(line = ttyname(0))) {
			puts(NO_TTY);
			exit(1);
		}
		if (strncmp(line, "/dev/", 5) == 0)
			line += 5;

 		strncpy (utent.ut_line, line, sizeof utent.ut_line);
		if ((ut = getutline(&utent)))
 			strncpy(utent.ut_id, ut->ut_id, sizeof ut->ut_id);

		strcpy(utent.ut_user, "LOGIN");
		utent.ut_pid = getpid();
		utent.ut_type = LOGIN_PROCESS;
		time(&utent.ut_time);
#if HAVE_UTMPX_H
		if ((utx = getutxline(&utxent)))
			strncpy(utxent.ut_id, utent.ut_id, sizeof utxent.ut_id);

		strncpy (utxent.ut_user, utent.ut_user, sizeof utent.ut_user);
		utxent.ut_pid = utent.ut_pid;
		utxent.ut_type = utent.ut_type;
		gettimeofday((struct timeval *) &utxent.ut_tv, NULL);
		utent.ut_time = utxent.ut_tv.tv_sec;
#endif
	}
#else	/* !USG */

	/*
	 * Hand-craft a new utmp entry.
	 */

	bzero((char *)&utent, sizeof utent);
	if (! (line = ttyname (0))) {
		puts (NO_TTY);
		exit (1);
	}
	if (strncmp (line, "/dev/", 5) == 0)
		line += 5;

	(void) strncpy (utent.ut_line, line, sizeof utent.ut_line);
	(void) time (&utent.ut_time);
#endif	/* !USG */
}

/*
 * setutmp - put a USER_PROCESS entry in the utmp file
 *
 *	setutmp changes the type of the current utmp entry to
 *	USER_PROCESS.  the wtmp file will be updated as well.
 */

#ifdef __FreeBSD__
#define _WTMP_FILE _PATH_WTMP
#endif

void
setutmp (name, line)
	const char *name;
	const char *line;
{
#ifdef __linux__
	int fd;

	utent.ut_type = USER_PROCESS;
	strncpy(utent.ut_user, name, sizeof utent.ut_user);
	time(&utent.ut_time);
	/* other fields already filled in by checkutmp above */
	setutent();
	pututline(&utent);
	endutent();
	fd = open(_WTMP_FILE, O_APPEND | O_WRONLY, 0);
	if (fd >= 0) {
		write(fd, (char *) &utent, sizeof utent);
		close(fd);
	}
#elif HAVE_UTMPX_H
	struct	utmp	*utmp, utline;
	struct	utmpx	*utmpx, utxline;
	pid_t	pid = getpid ();
	FILE	*utmpx_fp;
	int	found_utmpx = 0, found_utmp = 0;
	int	fd;

	/*
	 * The canonical device name doesn't include "/dev/"; skip it
	 * if it is already there.
	 */

	if (strncmp (line, "/dev/", 5) == 0)
		line += 5;

	/*
	 * Update utmpx.  We create an empty entry in case there is
	 * no matching entry in the utmpx file.
	 */

	setutxent ();
	setutent ();

	while (utmpx = getutxent ()) {
		if (utmpx->ut_pid == pid) {
			found_utmpx = 1;
			break;
		}
	}
	while (utmp = getutent ()) {
		if (utmp->ut_pid == pid) {
			found_utmp = 1;
			break;
		}
	}

	/*
	 * If the entry matching `pid' cannot be found, create a new
	 * entry with the device name in it.
	 */

	if (! found_utmpx) {
		memset ((void *) &utxline, 0, sizeof utxline);
		strncpy (utxline.ut_line, line, sizeof utxline.ut_line);
		utxline.ut_pid = getpid ();
	} else {
		utxline = *utmpx;
		if (strncmp (utxline.ut_line, "/dev/", 5) == 0) {
			memmove (utxline.ut_line, utxline.ut_line + 5,
				sizeof utxline.ut_line - 5);
			utxline.ut_line[sizeof utxline.ut_line - 5] = '\0';
		}
	}
	if (! found_utmp) {
		memset ((void *) &utline, 0, sizeof utline);
		strncpy (utline.ut_line, utxline.ut_line,
			sizeof utline.ut_line);
		utline.ut_pid = utxline.ut_pid;
	} else {
		utline = *utmp;
		if (strncmp (utline.ut_line, "/dev/", 5) == 0) {
			memmove (utline.ut_line, utline.ut_line + 5,
				sizeof utline.ut_line - 5);
			utline.ut_line[sizeof utline.ut_line - 5] = '\0';
		}
	}

	/*
	 * Fill in the fields in the utmpx entry and write it out.  Do
	 * the utmp entry at the same time to make sure things don't
	 * get messed up.
	 */

	strncpy (utxline.ut_user, name, sizeof utxline.ut_user);
	strncpy (utline.ut_user, name, sizeof utline.ut_user);

	utline.ut_type = utxline.ut_type = USER_PROCESS;

	gettimeofday(&utxline.ut_tv, NULL);
	utline.ut_time = utxline.ut_tv.tv_sec;

	strncpy (utxline.ut_host, host, sizeof utxline.ut_host);

#ifdef HAVE_UT_SYSLEN
	utxline.ut_syslen = strlen (utxline.ut_host) + 1;
	if (utxline.ut_syslen > sizeof (utxline.ut_host))
	  utxline.ut_syslen = sizeof (utxline.ut_host);
#endif

	pututline (&utline);
	pututxline (&utxline);

#ifdef _WTMP_FILE
	if ((fd = open (_WTMP_FILE "x", O_WRONLY|O_APPEND)) != -1) {
		write (fd, (void *) &utxline, sizeof utxline);
		close (fd);
	}
	if ((fd = open (_WTMP_FILE, O_WRONLY|O_APPEND)) != -1) {
		write (fd, (void *) &utline, sizeof utline);
		close (fd);
	}
#elif defined(_WTMPX_FILE)
	if ((fd = open (_WTMPX_FILE, O_WRONLY|O_APPEND)) != -1) {
		write (fd, (void *) &utxline, sizeof utxline);
		close (fd);
	}
#endif /* !_WTMP_FILE */

	utxent = utxline;
	utent = utline;
	
#else /* !SVR4 */
	struct	utmp	utmp;
	int	fd;
	int	found = 0;
	off_t	pos;

	if ((fd = open(_UTMP_FILE, O_RDWR)) < 0)
		return;

#if !defined(SUN) && !defined(BSD) && !defined(SUN4)
 	while (!found && read(fd, (char *)&utmp, sizeof utmp) == sizeof utmp) {
 		if (! strncmp (line, utmp.ut_line, (int) sizeof utmp.ut_line))
			found++;
	}
#endif

	if (! found) {

		/*
		 * This is a brand-new entry.  Clear it out and fill it in
		 * later.
		 */

  		(void) bzero((char *)&utmp, sizeof utmp);
 		(void) strncpy (utmp.ut_line, line, (int) sizeof utmp.ut_line);
	}

	/*
	 * Fill in the parts of the UTMP entry.  BSD has just the name,
	 * while System V has the name, PID and a type.
	 */

	strncpy(utmp.UT_USER, name, sizeof utent.UT_USER);
#ifdef USER_PROCESS
	utmp.ut_type = USER_PROCESS;
	utmp.ut_pid = getpid ();
#endif

	/*
	 * Put in the current time (common to everyone)
	 */

	(void) time (&utmp.ut_time);

#ifdef UT_HOST
	/*
	 * Update the host name field for systems with networking support
	 */

	(void) strncpy (utmp.ut_host, utent.ut_host, (int) sizeof utmp.ut_host);
#endif

	/*
	 * Locate the correct position in the UTMP file for this
	 * entry.
	 */

#ifdef HAVE_TTYSLOT
	(void) lseek (fd, (off_t) (sizeof utmp) * ttyslot (), SEEK_SET);
#else
	if (found) {	/* Back up a slot */
		pos = lseek (fd, (off_t) 0, SEEK_CUR);
		lseek (fd, pos - sizeof utmp, SEEK_SET);
	}
	else		/* Otherwise, go to the end of the file */
		lseek (fd, (off_t) 0, SEEK_END);
#endif

	/*
	 * Scribble out the new entry and close the file.  We're done
	 * with UTMP, next we do WTMP (which is real easy, put it on
	 * the end of the file.
	 */

	(void) write (fd, (char *) &utmp, sizeof utmp);
	(void) close (fd);

#ifdef _WTMP_FILE
	if ((fd = open (_WTMP_FILE, O_WRONLY|O_APPEND)) >= 0) {
		(void) write (fd, (char *) &utmp, sizeof utmp);
		(void) close (fd);
	}
#endif /* _WTMP_FILE */
 	utent = utmp;
#endif /* SVR4 */
}
