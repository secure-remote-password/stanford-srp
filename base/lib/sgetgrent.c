/*
 * Copyright 1990 - 1994, Julianne Frances Haugh
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
RCSID("$Id: sgetgrent.c,v 1.1 2000/12/17 05:34:10 tom Exp $")

#include <stdio.h>
#include <grp.h>
#include "defines.h"

#define	NFIELDS	4
#define	MAXMEM	1024  /* really want to allocate it dynamically.  --marekm */

/*
 * list - turn a comma-separated string into an array of (char *)'s
 *
 *	list() converts the comma-separated list of member names into
 *	an array of character pointers.
 *
 *	WARNING: I profiled this once with and without strchr() calls
 *	and found that using a register variable and an explicit loop
 *	works best.  For large /etc/group files, this is a major win.
 */

static char **
list (s)
register char	*s;
{
	static char *members[MAXMEM+1];
	int	nmembers = 0;

	while (s && *s) {
		members[nmembers++] = s;
		while (*s && *s != ',')
			s++;

		if (*s)
			*s++ = '\0';
	}
	members[nmembers] = (char *) 0;
	return members;
}

struct group *
sgetgrent (buf)
	const char *buf;
{
	static char grpbuf[4*BUFSIZ];
	static char *grpfields[NFIELDS];
	static struct group grent;
	int	i;
	char	*cp;

	strncpy (grpbuf, buf, sizeof grpbuf);
	grpbuf[sizeof grpbuf - 1] = '\0';
	if ((cp = strrchr (grpbuf, '\n')))
		*cp = '\0';

	for (cp = grpbuf, i = 0;i < NFIELDS && cp;i++) {
		grpfields[i] = cp;
		if ((cp = strchr (cp, ':')))
			*cp++ = 0;
	}
	if (i < (NFIELDS-1) || *grpfields[2] == '\0')
		return 0;
	grent.gr_name = grpfields[0];
	grent.gr_passwd = grpfields[1];
	grent.gr_gid = atoi (grpfields[2]);
	grent.gr_mem = list (grpfields[3]);

	return (&grent);
}
