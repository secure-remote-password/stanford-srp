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

#ifdef GETGRENT

#include "rcsid.h"
RCSID("$Id: grent.c,v 1.1 2000/12/17 05:34:10 tom Exp $")

#include <stdio.h>
#include <grp.h>
#include "defines.h"

#ifdef	NDBM
#include <ndbm.h>
#include <fcntl.h>
DBM	*gr_dbm;
int	gr_dbm_mode = -1;
#endif	/* NDBM */

#define	NFIELDS	4
#define	MAXMEM	1024

static	char	grpbuf[4*BUFSIZ];
static	char	*grpfields[NFIELDS];
static	char	*members[MAXMEM+1];
static	struct	group	grent;

static	FILE	*grpfp;
static	char	*grpfile = GROUP_FILE;

#ifdef	NDBM
static	int	dbmopened;
static	int	dbmerror;
#endif	/* NDBM */

#ifdef	USE_NIS
static	int	nis_used;
static	int	nis_ignore;
static	enum	{ native, start, middle, native2 } nis_state;
static	int	nis_bound;
static	char	*nis_domain;
static	char	*nis_key;
static	int	nis_keylen;
static	char	*nis_val;
static	int	nis_vallen;
#define	IS_NISCHAR(c) ((c)=='+')
#endif

#ifdef	USE_NIS

/*
 * __setgrNIS - turn on or off NIS searches
 */

void
__setgrNIS (flag)
int	flag;
{
	nis_ignore = ! flag;

	if (nis_ignore)
		nis_used = 0;
}

/*
 * __isgrNIS - last getgr* returned a NIS group
 */

int
__isgrNIS (void)
{
	return nis_state == middle;
}

/*
 * bind_nis - bind to NIS server
 */

static int
bind_nis ()
{
	if (yp_get_default_domain (&nis_domain))
		return -1;

	nis_bound = 1;
	return 0;
}
#endif

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

static struct group *
sgetgrent (buf)
	const char *buf;
{
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
#ifdef	USE_NIS
		if (! IS_NISCHAR (grpfields[0][0]))
			return 0;
		else
			nis_used = 1;
#else
		return 0;
#endif
	grent.gr_name = grpfields[0];
	grent.gr_passwd = grpfields[1];
	grent.gr_gid = atoi (grpfields[2]);
	grent.gr_mem = list (grpfields[3]);

	return (&grent);
}

/*
 * fgetgrent - get a group file entry from a stream
 *
 * fgetgrent() reads the next line from a group file formatted stream
 * and returns a pointer to the group structure for that line.
 */

struct group *
fgetgrent (fp)
	FILE *fp;
{
	char	buf[BUFSIZ*4];
	char	*cp;

#ifdef	USE_NIS
	while (fgetsx (buf, sizeof buf, fp) != (char *) 0)
#else
	if (fgetsx (buf, sizeof buf, fp) != (char *) 0)
#endif
	{
		if (cp = strchr (buf, '\n'))
			*cp = '\0';
#ifdef	USE_NIS
		if (nis_ignore && IS_NISCHAR (buf[0]))
			continue;
#endif
		return (sgetgrent (buf));
	}
	return 0;
}

/*
 * endgrent - close a group file
 *
 * endgrent() closes the group file if open.
 */

SETXXENT_TYPE
endgrent ()
{
	if (grpfp)
		if (fclose (grpfp))
			SETXXENT_RET(-1);
	grpfp = 0;
#ifdef	NDBM
	if (dbmopened && gr_dbm) {
		dbm_close (gr_dbm);
		gr_dbm = 0;
	}
	dbmopened = 0;
	dbmerror = 0;
#endif	/* NDBM */
	SETXXENT_RET(0);
}

/*
 * getgrent - get a group entry from the group file
 *
 * getgrent() opens the group file, if not already opened, and reads
 * a single entry.  NULL is returned if any errors are encountered reading
 * the group file.
 */

struct group *
getgrent ()
{
#ifdef	USE_NIS
	int	nis_1_group = 0;
	struct	group	*val;
	char	buf[BUFSIZ];
#endif
	if (! grpfp) {
		SETXXENT_TEST(setgrent())
			return 0;
	}
#ifdef	USE_NIS
again:
	/*
	 * See if we are reading from the local file.
	 */

	if (nis_state == native || nis_state == native2) {

		/*
		 * Get the next entry from the group file.  Return NULL
		 * right away if there is none.
		 */

		if (! (val = fgetgrent (grpfp)))
			return 0;

		/*
		 * If this entry began with a NIS escape character, we have
		 * to see if this is just a single group, or if the entire
		 * map is being asked for.
		 */

		if (IS_NISCHAR (val->gr_name[0])) {
			if (val->gr_name[1])
				nis_1_group = 1;
			else
				nis_state = start;
		}

		/*
		 * If this isn't a NIS group and this isn't an escape to go
		 * use a NIS map, it must be a regular local group.
		 */

		if (nis_1_group == 0 && nis_state != start)
			return val;

		/*
		 * If this is an escape to use an NIS map, switch over to
		 * that bunch of code.
		 */

		if (nis_state == start)
			goto again;

		/*
		 * NEEDSWORK.  Here we substitute pieces-parts of this entry.
		 */

		return 0;
	} else {
		if (nis_bound == 0) {
			if (bind_nis ()) {
				nis_state = native2;
				goto again;
			}
		}
		if (nis_state == start) {
			if (yp_first (nis_domain, "group.byname", &nis_key,
				&nis_keylen, &nis_val, &nis_vallen)) {
				nis_state = native2;
				goto again;
			}
			nis_state = middle;
		} else if (nis_state == middle) {
			if (yp_next (nis_domain, "group.byname", nis_key,
				nis_keylen, &nis_key, &nis_keylen,
				&nis_val, &nis_vallen)) {
				nis_state = native2;
				goto again;
			}
		}
		return sgetgrent (nis_val);
	}
#else
	return fgetgrent (grpfp);
#endif
}

/*
 * getgrgid - locate the group entry for a given GID
 *
 * getgrgid() locates the first group file entry for the given GID.
 * If there is a valid DBM file, the DBM files are queried first for
 * the entry.  Otherwise, a linear search is begun of the group file
 * searching for an entry which matches the provided GID.
 */

struct group *
getgrgid (gid)
	gid_t gid;
{
	struct	group	*grp;
#ifdef NDBM
	datum	key;
	datum	content;
	int	cnt;
	int	i;
	char	*cp;
	char	grpkey[64];
#endif	/* NDBM */
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
	struct	sgrp	*sgrp;
#endif	/* AUTOSHADOW && SHADOWGRP */
#ifdef	USE_NIS
	char	buf[BUFSIZ];
	static	char	save_name[16];
#endif

	SETXXENT_TEST(setgrent())
		return 0;
#ifdef NDBM

	/*
	 * If the DBM file are now open, create a key for this GID and
	 * try to fetch the entry from the database.  A matching record
	 * will be unpacked into a static structure and returned to
	 * the user.
	 */

	if (dbmopened) {
		grent.gr_gid = gid;
		key.dsize = sizeof grent.gr_gid;
		key.dptr = (char *) &grent.gr_gid;
		content = dbm_fetch (gr_dbm, key);
		if (content.dptr == 0)
			return 0;

		if (content.dsize == sizeof (int)) {
			memcpy ((char *) &cnt, content.dptr, content.dsize);
			for (cp = grpbuf, i = 0;i < cnt;i++) {
				memcpy (grpkey, (char *) &i, (int) sizeof i);
				memcpy (grpkey + sizeof i,
					(char *) &grent.gr_gid,
					(int) sizeof grent.gr_gid);

				key.dsize = sizeof i + sizeof grent.gr_gid;
				key.dptr = grpkey;

				content = dbm_fetch (gr_dbm, key);
				if (content.dptr == 0)
					return 0;

				memcpy (cp, content.dptr, content.dsize);
				cp += content.dsize;
			}
			grent.gr_mem = members;
			gr_unpack (grpbuf, cp - grpbuf, &grent);
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
			if (sgrp = getsgnam (grent.gr_name)) {
				grent.gr_passwd = sgrp->sg_passwd;
				grent.gr_mem = sgrp->sg_mem;
			}
#endif	/* AUTOSHADOW && SHADOWGRP */
			return &grent;
		} else {
			grent.gr_mem = members;
			memcpy (grpbuf, content.dptr, content.dsize);
			gr_unpack (grpbuf, content.dsize, &grent);
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
			if (sgrp = getsgnam (grent.gr_name)) {
				grent.gr_passwd = sgrp->sg_passwd;
				grent.gr_mem = sgrp->sg_mem;
			}
#endif	/* AUTOSHADOW && SHADOWGRP */
			return &grent;
		}
	}
#endif	/* NDBM */
#ifdef	USE_NIS

	if (nis_used) {
again:

		/*
		 * Search the group.bygid map for this group.
		 */

		if (! nis_bound)
			bind_nis ();

		if (nis_bound) {
			char	*cp;

			sprintf (buf, "%d", gid);

			if (yp_match (nis_domain, "group.bygid", buf,
					strlen (buf), &nis_val, &nis_vallen) == 0) {
				if (cp = strchr (nis_val, '\n'))
					*cp = '\0';

				nis_state = middle;
				if (grp = sgetgrent (nis_val)) {
					strcpy (save_name, grp->gr_name);
					nis_key = save_name;
					nis_keylen = strlen (save_name);
				}
				return grp;
			} else
				nis_state = native2;
		}
	}
#endif
	/*
	 * Search for an entry which matches the GID.  Return the
	 * entry when a match is found.
	 */

	while (grp = getgrent ()) {
		if (grp->gr_gid == gid)
			break;

#ifdef	USE_NIS
		if (nis_used && nis_state != native && nis_state != native2)
			goto again;
#endif
	}
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
	if (grp) {
		if (sgrp = getsgnam (grent.gr_name)) {
			grp->gr_passwd = sgrp->sg_passwd;
			grp->gr_mem = sgrp->sg_mem;
		}
	}
#endif	/* AUTOSHADOW && SHADOWGRP */
	return grp;
}

/*
 * getgrnam - locate the group entry for a given name
 *
 * getgrnam() locates the first group file entry for the given name.
 * If there is a valid DBM file, the DBM files are queried first for
 * the entry.  Otherwise, a linear search is begun of the group file
 * searching for an entry which matches the provided name.
 */

struct group *
getgrnam (name)
	const char *name;
{
	struct	group	*grp;
#ifdef NDBM
	datum	key;
	datum	content;
	int	cnt;
	int	i;
	char	*cp;
	char	grpkey[64];
#endif	/* NDBM */
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
	struct	sgrp	*sgrp;
#endif	/* AUTOSHADOW && SHADOWGRP */
#ifdef	USE_NIS
	char	buf[BUFSIZ];
	static	char	save_name[16];
#endif

	SETXXENT_TEST(setgrent())
		return 0;
#ifdef NDBM

	/*
	 * If the DBM file are now open, create a key for this GID and
	 * try to fetch the entry from the database.  A matching record
	 * will be unpacked into a static structure and returned to
	 * the user.
	 */

	if (dbmopened) {
		key.dsize = strlen (name);
		key.dptr = (void *) name;
		content = dbm_fetch (gr_dbm, key);
		if (content.dptr == 0)
			return 0;

		if (content.dsize == sizeof (int)) {
			memcpy ((char *) &cnt, content.dptr, content.dsize);
			for (cp = grpbuf, i = 0;i < cnt;i++) {
				memcpy (grpkey, (char *) &i, (int) sizeof i);
				strcpy (grpkey + sizeof i, name);

				key.dsize = sizeof i + strlen (name);
				key.dptr = grpkey;

				content = dbm_fetch (gr_dbm, key);
				if (content.dptr == 0)
					return 0;

				memcpy (cp, content.dptr, content.dsize);
				cp += content.dsize;
			}
			grent.gr_mem = members;
			gr_unpack (grpbuf, cp - grpbuf, &grent);
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
			if (sgrp = getsgnam (grent.gr_name)) {
				grent.gr_passwd = sgrp->sg_passwd;
				grent.gr_mem = sgrp->sg_mem;
			}
#endif	/* AUTOSHADOW && SHADOWGRP */
			return &grent;
		} else {
			grent.gr_mem = members;
			memcpy (grpbuf, content.dptr, content.dsize);
			gr_unpack (grpbuf, content.dsize, &grent);
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
			if (sgrp = getsgnam (grent.gr_name)) {
				grent.gr_passwd = sgrp->sg_passwd;
				grent.gr_mem = sgrp->sg_mem;
			}
#endif	/* AUTOSHADOW && SHADOWGRP */
			return &grent;
		}
	}
#endif	/* NDBM */
#ifdef	USE_NIS

	if (nis_used) {
again:
		/*
		 * Search the group.byname map for this group.
		 */

		if (! nis_bound)
			bind_nis ();

		if (nis_bound) {
			char	*cp;

			if (! yp_match (nis_domain, "group.byname", name,
					strlen (name), &nis_val, &nis_vallen)) {
				if (cp = strchr (nis_val, '\n'))
					*cp = '\0';

				nis_state = middle;
				if (grp = sgetgrent (nis_val)) {
					strcpy (save_name, grp->gr_name);
					nis_key = save_name;
					nis_keylen = strlen (save_name);
				}
				return grp;
			} else
				nis_state = native2;
		}
	}
#endif
	/*
	 * Search for an entry which matches the name.  Return the
	 * entry when a match is found.
	 */

	while (grp = getgrent ()) {
		if (strcmp (grp->gr_name, name) == 0)
			break;

#ifdef	USE_NIS
		if (nis_used && nis_state != native && nis_state != native2)
			goto again;
#endif
	}
#if defined(AUTOSHADOW) && defined(SHADOWGRP)
	if (grp) {
		if (sgrp = getsgnam (grent.gr_name)) {
			grp->gr_passwd = sgrp->sg_passwd;
			grp->gr_mem = sgrp->sg_mem;
		}
	}
#endif	/* AUTOSHADOW && SHADOWGRP */
	return grp;
}

/*
 * setgrent - open the group file
 *
 * setgrent() opens the system group file, and the DBM group files
 * if they are present.  The system group file is rewound if it was
 * open already.
 */

SETXXENT_TYPE
setgrent ()
{
#ifdef	NDBM
	int	mode;
#endif	/* NDBM */

#ifdef	USE_NIS
	nis_state = native;
#endif
	if (! grpfp) {
		if (! (grpfp = fopen (grpfile, "r")))
			SETXXENT_RET(-1);
	} else {
		if (fseek (grpfp, (off_t) 0L, SEEK_SET) != 0)
			SETXXENT_RET(-1);
	}

	/*
	 * Attempt to open the DBM files if they have never been opened
	 * and an error has never been returned.
	 */

#ifdef NDBM
	if (! dbmerror && ! dbmopened) {
		char	dbmfiles[BUFSIZ];

		strcpy (dbmfiles, grpfile);
		strcat (dbmfiles, ".pag");
		if (gr_dbm_mode == -1)
			mode = O_RDONLY;
		else
			mode = (gr_dbm_mode == O_RDONLY ||
				gr_dbm_mode == O_RDWR) ? gr_dbm_mode:O_RDONLY;

		if (access (dbmfiles, 0) ||
			(! (gr_dbm = dbm_open (grpfile, mode, 0))))
			dbmerror = 1;
		else
			dbmopened = 1;
	}
#endif	/* NDBM */
	SETXXENT_RET(0);
}
#endif	/* GETGRENT */
