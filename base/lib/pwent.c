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
RCSID("$Id: pwent.c,v 1.1 2000/12/17 05:34:10 tom Exp $")

#include <sys/types.h>
#include "defines.h"
#include <stdio.h>
#include <pwd.h>

/*
 * If AUTOSHADOW is enabled, the getpwnam and getpwuid calls will
 * fill in the pw_passwd and pw_age fields from the passwd and
 * shadow files.
 */

#if defined(AUTOSHADOW) && !defined(SHADOWPWD)
#undef	AUTOSHADOW
#endif

/*
 * If DBM or NDBM is enabled, the getpwnam and getpwuid calls will
 * go to the database files to look for the requested entries.
 */

#ifdef	DBM
#include <dbm.h>
#endif
#ifdef	NDBM
#include <ndbm.h>
#include <fcntl.h>
DBM	*pw_dbm;
int	pw_dbm_mode = -1;
#endif

#define	NFIELDS	7

#ifdef	GETPWENT
static	char	*pwdfile = PASSWD_FILE;
static	FILE	*pwdfp;
#endif
static	char	pwdbuf[BUFSIZ];
#if defined(DBM) || defined(NDBM)
static	int	dbmopened;
static	int	dbmerror;
#endif
static	char	*pwdfields[NFIELDS];
static	struct	passwd	pwent;

#ifdef	USE_NIS
static	char	NISpwdbuf[BUFSIZ];
static	char	*NISpwdfields[NFIELDS];
static	struct	passwd	NISpwent;
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
 * __setpwNIS - turn on or off NIS searches
 */

void
__setpwNIS (flag)
int	flag;
{
	nis_ignore = ! flag;

	if (nis_ignore)
		nis_used = 0;
}

/*
 * __ispwNIS - last getpw* returned a NIS user
 */

int
__ispwNIS (void)
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

#if defined(AUTOSHADOW) && defined(ATT_AGE) && defined(GETPWENT)
/*
 * sptopwage - convert shadow ages to AT&T-style pw_age ages
 *
 *	sptopwage() converts the values in the shadow password
 *	entry to the format used in the old-style password
 *	entry.
 */

static char *
sptopwage (spwd)
struct	spwd	*spwd;
{
	static	char	age[5];
	long	min;
	long	max;
	long	last;

	if ((min = (spwd->sp_min * SCALE / WEEK)) < 0)
		min = 0;
	else if (min >= 64)
		min = 63;

	if ((max = (spwd->sp_max * SCALE / WEEK)) < 0)
		max = 0;
	else if (max >= 64)
		max = 63;

	if ((last = (spwd->sp_lstchg * SCALE / WEEK)) < 0)
		last = 0;
	else if (last >= 4096)
		last = 4095;

	age[0] = i64c (max);
	age[1] = i64c (min);
	age[2] = i64c (last % 64);
	age[3] = i64c (last / 64);
	age[4] = '\0';
	return age;
}
#endif

#ifdef	GETPWENT
/*
 * _sgetpwent - convert a string to a (struct passwd)
 *
 * _sgetpwent() parses a string into the parts required for a password
 * structure.  Strict checking is made for the UID and GID fields and
 * presence of the correct number of colons.  Any failing tests result
 * in a NULL pointer being returned.
 *
 * NOTE: This function uses hard-coded string scanning functions for
 *	performance reasons.  I am going to come up with some conditional
 *	compilation glarp to improve on this in the future.
 */

static struct passwd *
_sgetpwent (buf)
char	*buf;
{
	register int	i;
	register char	*cp;
	char	*ep;
	char	**fields;
	char	*buffer;
	struct	passwd	*pwd;

	/*
	 * Get my pointers all set up.
	 */
#ifdef	USE_NIS
	if (IS_NISCHAR (buf[0])) {
		fields = NISpwdfields;
		buffer = NISpwdbuf;
		pwd = &NISpwent;
	} else
#endif
	{
		fields = pwdfields;
		buffer = pwdbuf;
		pwd = &pwent;
	}


	/*
	 * Copy the string to a static buffer so the pointers into
	 * the password structure remain valid.
	 */

	strncpy (buffer, buf, BUFSIZ-1);
	buffer[BUFSIZ-1] = '\0';

	/*
	 * Save a pointer to the start of each colon separated
	 * field.  The fields are converted into NUL terminated strings.
	 */

	for (cp = buffer, i = 0;i < NFIELDS && cp;i++) {
		fields[i] = cp;
		while (*cp && *cp != ':')
			++cp;
	
		if (*cp)
			*cp++ = '\0';
		else
			cp = 0;
	}

	/*
	 * There must be exactly NFIELDS colon separated fields or
	 * the entry is invalid.  Also, the UID and GID must be non-blank.
	 */

	if (i != NFIELDS || *fields[2] == '\0' || *fields[3] == '\0') {
#ifdef	USE_NIS
		if (! IS_NISCHAR (fields[0][0]))
			return 0;
		else
			nis_used = 1;
#else
		return 0;
#endif
	}

	/*
	 * Each of the fields is converted the appropriate data type
	 * and the result assigned to the password structure.  If the
	 * UID or GID does not convert to an integer value, a NULL
	 * pointer is returned.
	 */

	pwd->pw_name = fields[0];
#ifdef	USE_NIS
	if (IS_NISCHAR (fields[0][0]))
		nis_used = 1;
#endif
	pwd->pw_passwd = fields[1];
	if (fields[2][0] == '\0' ||
		((pwd->pw_uid = strtol (fields[2], &ep, 10)) == 0 && *ep)) {
#ifdef	USE_NIS
		if (! nis_used)
			return 0;
		else
			pwd->pw_uid = -1;
#else
		return 0;
#endif
	}
	if (fields[3][0] == '\0' ||
		((pwd->pw_gid = strtol (fields[3], &ep, 10)) == 0 && *ep)) {
#ifdef	USE_NIS
		if (! nis_used)
			return 0;
		else
			pwd->pw_gid = -1;
#else
		return 0;
#endif
	}
#ifdef	ATT_AGE
	cp = pwd->pw_passwd;
	while (*cp && *cp != ',')
		++cp;

	if (*cp) {
		*cp++ = '\0';
		pwd->pw_age = cp;
	} else {
		cp = 0;
		pwd->pw_age = "";
	}
#endif
	pwd->pw_gecos = fields[4];
#ifdef	ATT_COMMENT
	pwd->pw_comment = "";
#endif
	pwd->pw_dir = fields[5];
	pwd->pw_shell = fields[6];

	return (pwd);
}

/*
 * fgetpwent - get a password file entry from a stream
 *
 * fgetpwent() reads the next line from a password file formatted stream
 * and returns a pointer to the password structure for that line.
 */

struct passwd *
fgetpwent (fp)
FILE	*fp;
{
	char	buf[BUFSIZ];

#ifdef	USE_NIS
	while (fgets (buf, sizeof buf, fp) != (char *) 0)
#else
	if (fgets (buf, sizeof buf, fp) != (char *) 0)
#endif
	{
		buf[strlen (buf) - 1] = '\0';
#ifdef	USE_NIS
		if (nis_ignore && IS_NISCHAR (buf[0]))
			continue;
#endif
		return (_sgetpwent (buf));
	}
	return 0;
}

/*
 * endpwent - close a password file
 *
 * endpwent() closes the password file if open.  if autoshadowing is
 * enabled the system must also end access to the shadow files since
 * the user is probably unaware it was ever accessed.
 */

SETXXENT_TYPE
endpwent ()
{
	if (pwdfp)
		if (fclose (pwdfp))
			SETXXENT_RET(-1);
	pwdfp = 0;
#ifdef	NDBM
	if (dbmopened && pw_dbm) {
		dbm_close (pw_dbm);
		dbmopened = 0;
		dbmerror = 0;
		pw_dbm = 0;
	}
#endif
#ifdef	AUTOSHADOW
	endspent ();
#endif
	SETXXENT_RET(0);
}

/*
 * getpwent - get a password entry from the password file
 *
 * getpwent() opens the password file, if not already opened, and reads
 * a single entry.  NULL is returned if any errors are encountered reading
 * the password file.
 */

struct passwd *
getpwent ()
{
#ifdef	USE_NIS
	int	nis_1_user = 0;
	struct	passwd	*val;
	struct	passwd	*NISval;
	char	buf[BUFSIZ];
	char	*cp;
	static	char	save_name[16];
#endif
	if (! pwdfp) {
		(void) setpwent ();
		if (! pwdfp)
			return 0;
	}
#ifdef	USE_NIS
again:
	/*
	 * See if we are reading from the local file.
	 */

	if (nis_state == native || nis_state == native2) {

		/*
		 * Get the next entry from the password file.  Return NULL
		 * right away if there is none.
		 */

		if (! (val = fgetpwent (pwdfp)))
			return 0;

		/*
		 * If this entry began with a NIS escape character, we have
		 * to see if this is just a single user, or if the entire
		 * map is being asked for.
		 */

		if (IS_NISCHAR (val->pw_name[0])) {
			if (val->pw_name[1])
				nis_1_user = 1;
			else
				nis_state = start;
		}

		/*
		 * If this isn't a NIS user and this isn't an escape to go
		 * use a NIS map, it must be a regular local user.
		 */

		if (nis_1_user == 0 && nis_state != start)
			return val;

		/*
		 * If this is an escape to use an NIS map, switch over to
		 * that bunch of code.
		 */

		if (nis_state == start)
			goto again;

		/*
		 * NEEDSWORK.  Here we substitute pieces-parts of this entry.
		 * As a first stab, let's call getpwnam() with the name we
		 * just matched, after skipping over the NIS glarp.
		 */

		if (! nis_bound)
			bind_nis ();

		if (! nis_bound)
			goto again;

		if (yp_match (nis_domain, "passwd.byname", val->pw_name + 1,
				strlen (val->pw_name + 1),
				&nis_val, &nis_vallen) == 0) {

			if (cp = strchr (nis_val, '\n'))
				*cp = '\0';

			if (! (NISval = _sgetpwent (nis_val)))
				goto again;
		} else
			goto again;

		/*
		 * NISval points to the reply from NIS, and val points to
		 * the value we got from the local file.
		 */

		val->pw_name++;

		if (val->pw_passwd[0] == '*')
			val->pw_passwd = NISval->pw_passwd;
#ifdef	ATT_AGE
		if (val->pw_age[0] == '\0')
			val->pw_age = NISval->pw_age;
#endif
		if (val->pw_uid == -1)
			val->pw_uid = NISval->pw_uid;
		if (val->pw_gid == -1)
			val->pw_gid = NISval->pw_gid;
		if (val->pw_gecos[0] == '\0')
			val->pw_gecos = NISval->pw_gecos;
		if (val->pw_dir[0] == '\0')
			val->pw_dir = NISval->pw_dir;
		if (val->pw_shell[0] == '\0')
			val->pw_shell = NISval->pw_shell;

		return val;
	} else {
		if (nis_bound == 0) {
			if (bind_nis ()) {
				nis_state = native2;
				goto again;
			}
		}
		if (nis_state == start) {
			if (yp_first (nis_domain, "passwd.byname", &nis_key,
				&nis_keylen, &nis_val, &nis_vallen)) {
				nis_state = native2;
				goto again;
			}
			nis_state = middle;
		} else if (nis_state == middle) {
			if (yp_next (nis_domain, "passwd.byname", nis_key,
				nis_keylen, &nis_key, &nis_keylen,
				&nis_val, &nis_vallen)) {
				nis_state = native2;
				goto again;
			}
		}
		return _sgetpwent (nis_val);
	}
#else
	return fgetpwent (pwdfp);
#endif
}

/*
 * getpwuid - locate the password entry for a given UID
 *
 * getpwuid() locates the first password file entry for the given UID.
 * If there is a valid DBM file, the DBM files are queried first for
 * the entry.  Otherwise, a linear search is begun of the password file
 * searching for an entry which matches the provided UID.
 */

struct passwd *
getpwuid (uid)
uid_t	uid;
{
	struct	passwd	*pwd;
#if defined(DBM) || defined(NDBM)
	datum	key;
	datum	content;
	uid_t	uid_key;
#endif
#ifdef	AUTOSHADOW
	struct	spwd	*spwd;
#endif
#ifdef	USE_NIS
	char	buf[BUFSIZ];
	static	char	save_name[16];
	int	nis_disabled = 0;
#endif

	(void) setpwent ();
	if (! pwdfp)
		return 0;

#if defined(DBM) || defined(NDBM)

	/*
	 * If the DBM file are now open, create a key for this UID and
	 * try to fetch the entry from the database.  A matching record
	 * will be unpacked into a static structure and returned to
	 * the user.
	 */

	if (dbmopened) {
		uid_key = uid;
		key.dsize = sizeof uid_key;
		key.dptr = (char *) &uid_key;
#ifdef	DBM
		content = fetch (key);
#endif
#ifdef	NDBM
		content = dbm_fetch (pw_dbm, key);
#endif
		if (content.dptr != 0) {
			memcpy (pwdbuf, content.dptr, content.dsize);
			pw_unpack (pwdbuf, content.dsize, &pwent);
#ifdef	AUTOSHADOW
			if ((spwd = getspnam (pwent.pw_name))) {
				pwent.pw_passwd = spwd->sp_pwdp;
#ifdef	ATT_AGE
				pwent.pw_age = sptopwage (spwd);
#endif
			}
#endif
			return &pwent;
		}
	}
#endif
#ifdef	USE_NIS

	/*
	 * Search the passwd.byuid map for this user.
	 */

	if (! nis_ignore && ! nis_bound)
		bind_nis ();

	if (! nis_ignore && nis_bound) {
		char	*cp;

		sprintf (buf, "%d", uid);

		if (yp_match (nis_domain, "passwd.byuid", buf,
				strlen (buf), &nis_val, &nis_vallen) == 0) {

			if (cp = strchr (nis_val, '\n'))
				*cp = '\0';

			nis_state = middle;
			if ((pwd = _sgetpwent (nis_val))) {
				strcpy (save_name, pwd->pw_name);
				nis_key = save_name;
				nis_keylen = strlen (save_name);
			}
			return pwd;
		} else
			nis_state = native2;
	}
#endif
#ifdef	USE_NIS
	/*
	 * NEEDSWORK -- this is a mess, and it is the same mess in the
	 * other three files.  I can't just blindly turn off NIS because
	 * this might be the first pass through the local files.  In
	 * that case, I never discover that NIS is present.
	 */

	if (nis_used) {
		nis_ignore++;
		nis_disabled++;
	}
#endif
	/*
	 * Search for an entry which matches the UID.  Return the
	 * entry when a match is found.
	 */

	while ((pwd = getpwent ()))
		if (pwd->pw_uid == uid)
			break;

#ifdef	USE_NIS
	if (nis_disabled)
		nis_ignore--;
#endif
#ifdef	AUTOSHADOW
	if (pwd && (spwd = getspnam (pwd->pw_name))) {
		pwd->pw_passwd = spwd->sp_pwdp;
#ifdef	ATT_AGE
		pwd->pw_age = sptopwage (spwd);
#endif
	}
#endif
	return pwd;
}

/*
 * getpwnam - locate the password entry for a given name
 *
 * getpwnam() locates the first password file entry for the given name.
 * If there is a valid DBM file, the DBM files are queried first for
 * the entry.  Otherwise, a linear search is begun of the password file
 * searching for an entry which matches the provided name.
 */

struct passwd *
getpwnam (name)
	const char *name;
{
	struct	passwd	*pwd;
#if defined(DBM) || defined(NDBM)
	datum	key;
	datum	content;
#endif
#ifdef	AUTOSHADOW
	struct	spwd	*spwd;
#endif
#ifdef	USE_NIS
	char	buf[BUFSIZ];
	static	char	save_name[16];
	int	nis_disabled = 0;
#endif

	(void) setpwent ();
	if (! pwdfp)
		return 0;

#if defined(DBM) || defined(NDBM)

	/*
	 * If the DBM file are now open, create a key for this UID and
	 * try to fetch the entry from the database.  A matching record
	 * will be unpacked into a static structure and returned to
	 * the user.
	 */

	if (dbmopened) {
		key.dsize = strlen (name);
		key.dptr = (void *) name;
#ifdef	DBM
		content = fetch (key);
#endif
#ifdef	NDBM
		content = dbm_fetch (pw_dbm, key);
#endif
		if (content.dptr != 0) {
			memcpy (pwdbuf, content.dptr, content.dsize);
			pw_unpack (pwdbuf, content.dsize, &pwent);
#ifdef	AUTOSHADOW
			if ((spwd = getspnam (pwent.pw_name))) {
				pwent.pw_passwd = spwd->sp_pwdp;
#ifdef	ATT_AGE
				pwent.pw_age = sptopwage (spwd);
#endif
			}
#endif
			return &pwent;
		}
	}
#endif

	/*
	 * Search for an entry which matches the name.  Return the
	 * entry when a match is found.
	 */

local:
	while ((pwd = getpwent ())) {
#ifdef	USE_NIS
		/*
		 * See if we hit a "+" symbol.  If we did, we can just
		 * query the map directly.  If that fails, we come back
		 * to next line.
		 */

		if (nis_state == middle)
			goto remote;
#endif
		if (strcmp (pwd->pw_name, name) == 0)
			break;
	}
fini:
#ifdef	AUTOSHADOW
	if (pwd && (spwd = getspnam (pwd->pw_name))) {
		pwd->pw_passwd = spwd->sp_pwdp;
#ifdef	ATT_AGE
		pwd->pw_age = sptopwage (spwd);
#endif	/* ATT_AGE */
	}
#endif	/* AUTOSHADOW */
	return pwd;

#ifdef	USE_NIS
remote:
	/*
	 * Search the passwd.byname map for this user.
	 */

	if (! nis_ignore && ! nis_bound)
		bind_nis ();

	if (! nis_ignore && nis_bound) {
		char	*cp;

		if (yp_match (nis_domain, "passwd.byname", name,
				strlen (name), &nis_val, &nis_vallen) == 0) {

			if (cp = strchr (nis_val, '\n'))
				*cp = '\0';

			nis_state = middle;
			if ((pwd = _sgetpwent (nis_val))) {
				strcpy (save_name, pwd->pw_name);
				nis_key = save_name;
				nis_keylen = strlen (save_name);
			}
			goto fini;
		} else {
			nis_state = native2;
			goto local;
		}
	}
	goto fini;
#endif	/* USE_NIS */
}

/*
 * setpwent - open the password file
 *
 * setpwent() opens the system password file, and the DBM password files
 * if they are present.  The system password file is rewound if it was
 * open already.
 */

SETXXENT_TYPE
setpwent ()
{
#ifdef	NDBM
	int	mode;
#endif

#ifdef	USE_NIS
	nis_state = native;
#endif
	if (! pwdfp) {
		if (! (pwdfp = fopen (pwdfile, "r")))
			SETXXENT_RET(-1);
	} else {
		if (fseek (pwdfp, (off_t) 0L, SEEK_SET) != 0) {
			fclose (pwdfp);
			pwdfp = 0;
			SETXXENT_RET(-1);
		}
	}

	/*
	 * Attempt to open the DBM files if they have never been opened
	 * and an error has never been returned.
	 */

#if defined (DBM) || defined (NDBM)
	if (! dbmerror && ! dbmopened) {
		char	dbmfiles[BUFSIZ];

		strcpy (dbmfiles, pwdfile);
		strcat (dbmfiles, ".pag");
#ifdef	NDBM
		if (pw_dbm_mode == -1)
			mode = O_RDONLY;
		else
			mode = (pw_dbm_mode == O_RDONLY ||
				pw_dbm_mode == O_RDWR) ? pw_dbm_mode:O_RDONLY;
#endif
#ifdef	DBM
		if (access (dbmfiles, 0) || dbminit (pwdfile))
#endif
#ifdef	NDBM
		if (access (dbmfiles, 0) ||
			(! (pw_dbm = dbm_open (pwdfile, mode, 0))))
#endif
			dbmerror = 1;
		else
			dbmopened = 1;
	}
#endif
	SETXXENT_RET(0);
}

#endif /* GETPWENT */
