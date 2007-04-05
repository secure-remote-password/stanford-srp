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
RCSID("$Id: log.c,v 1.2 2002/11/04 07:20:34 tom Exp $")

#include <sys/types.h>
#include <pwd.h>
#include <fcntl.h>
#include <time.h>
#include "defines.h"
#if HAVE_LASTLOG_H
#include <lastlog.h>
#else
#ifndef UTMP_LASTLOG
#include "lastlog_.h"
#endif
#endif
#if HAVE_UTMP_H
#include <utmp.h>
#endif

/* 
 * dolastlog - create lastlog entry
 *
 *	A "last login" entry is created for the user being logged in.  The
 *	UID is extracted from the global (struct passwd) entry and the
 *	TTY information is gotten from the (struct utmp).
 */

void
dolastlog(ll, pw, line, host)
	struct lastlog *ll;
	const struct passwd *pw;
	const char *line;
	const char *host;
{
	int	fd;
	off_t	offset;
	struct	lastlog	newlog;

	/*
	 * If the file does not exist, don't create it.
	 */

#ifdef LASTLOG_FILE
        if ((fd = open(LASTLOG_FILE, O_RDWR)) == -1)
                return;
#else
        return;
#endif

	/*
	 * The file is indexed by UID number.  Seek to the record
	 * for this UID.  Negative UID's will create problems, but ...
	 */

	offset = (unsigned long) pw->pw_uid * sizeof newlog;

	if (lseek(fd, offset, SEEK_SET) != offset) {
		close(fd);
		return;
	}

	/*
	 * Read the old entry so we can tell the user when they last
	 * logged in.  Then construct the new entry and write it out
	 * the way we read the old one in.
	 */

	if (read(fd, (char *) &newlog, sizeof newlog) != sizeof newlog)
		bzero((char *) &newlog, sizeof newlog);
	if (ll)
		*ll = newlog;

	time(&newlog.ll_time);
	strncpy(newlog.ll_line, line, sizeof newlog.ll_line);
#ifdef HAVE_LL_HOST
	strncpy(newlog.ll_host, host, sizeof newlog.ll_host);
#endif
	if (lseek(fd, offset, SEEK_SET) == offset)
		write(fd, (char *) &newlog, sizeof newlog);
	close(fd);
}

