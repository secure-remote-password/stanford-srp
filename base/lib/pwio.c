
#include <config.h>

#include "rcsid.h"
RCSID("$Id: pwio.c,v 1.1 2000/12/17 05:34:10 tom Exp $")

#include "prototypes.h"
#include "defines.h"
#include <pwd.h>
#include <stdio.h>

#include "commonio.h"
#include "pwio.h"

extern int fputs ();

extern struct passwd *sgetpwent P_((const char *));
extern int putpwent ();
/* extern int putpwent P_((const struct passwd *, FILE *)); */

struct passwd *
__pw_dup(pwent)
	const struct passwd *pwent;
{
	struct passwd *pw;

	if (!(pw = (struct passwd *) malloc(sizeof *pw)))
		return NULL;
	*pw = *pwent;
	if (!(pw->pw_name = strdup(pwent->pw_name)))
		return NULL;
	if (!(pw->pw_passwd = strdup(pwent->pw_passwd)))
		return NULL;
#ifdef ATT_AGE
	if (!(pw->pw_age = strdup(pwent->pw_age)))
		return NULL;
#endif
#ifdef ATT_COMMENT
	if (!(pw->pw_comment = strdup(pwent->pw_comment)))
		return NULL;
#endif
	if (!(pw->pw_gecos = strdup(pwent->pw_gecos)))
		return NULL;
	if (!(pw->pw_dir = strdup(pwent->pw_dir)))
		return NULL;
	if (!(pw->pw_shell = strdup(pwent->pw_shell)))
		return NULL;
	return pw;
}

static void *
passwd_dup(entry)
	const void *entry;
{
	const struct passwd *pw = entry;
	return __pw_dup(pw);
}

static void
passwd_free(entry)
	void *entry;
{
	struct passwd *pw = entry;

	free(pw->pw_name);
	free(pw->pw_passwd);
#ifdef ATT_AGE
	free(pw->pw_age);
#endif
#ifdef ATT_COMMENT
	free(pw->pw_comment);
#endif
	free(pw->pw_gecos);
	free(pw->pw_dir);
	free(pw->pw_shell);
	free(pw);
}

static const char *
passwd_getname(entry)
	const void *entry;
{
	const struct passwd *pw = entry;
	return pw->pw_name;
}

static void *
passwd_parse(line)
	const char *line;
{
	return (void *) sgetpwent(line);
}

static int
passwd_put(entry, file)
	const void *entry;
	FILE *file;
{
	const struct passwd *pw = entry;
	return (putpwent(pw, file) == -1) ? -1 : 0;
}

static struct commonio_ops passwd_ops = {
	passwd_dup,
	passwd_free,
	passwd_getname,
	passwd_parse,
	passwd_put,
	fgets,
	fputs
};

static struct commonio_db passwd_db = {
	"/etc/passwd",
	&passwd_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0
};

int
pw_name(filename)
	const char *filename;
{
	return commonio_setname(&passwd_db, filename);
}

int
pw_lock()
{
	return commonio_lock(&passwd_db);
}

int
pw_lock_first()
{
	return commonio_lock_first(&passwd_db);
}

int
pw_open(mode)
	int mode;
{
	return commonio_open(&passwd_db, mode);
}

const struct passwd *
pw_locate(name)
	const char *name;
{
	return commonio_locate(&passwd_db, name);
}

int
pw_update(pw)
	const struct passwd *pw;
{
	return commonio_update(&passwd_db, (const void *) pw);
}

int
pw_remove(name)
	const char *name;
{
	return commonio_remove(&passwd_db, name);
}

int
pw_rewind()
{
	return commonio_rewind(&passwd_db);
}

const struct passwd *
pw_next()
{
	return commonio_next(&passwd_db);
}

int
pw_close()
{
	return commonio_close(&passwd_db);
}

int
pw_unlock()
{
	return commonio_unlock(&passwd_db);
}

struct commonio_entry *
__pw_get_head()
{
	return passwd_db.head;
}

void
__pw_del_entry(entry)
	const struct commonio_entry *entry;
{
	commonio_del_entry(&passwd_db, entry);
}
