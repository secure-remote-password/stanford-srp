
#include <config.h>

#ifdef SHADOWPWD

#include "rcsid.h"
RCSID("$Id: shadowio.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

#include "prototypes.h"
#include "defines.h"
/* #include <shadow.h> */
#include <stdio.h>

#include "commonio.h"
#include "shadowio.h"

extern int fputs ();

struct spwd *
__spw_dup(spent)
	const struct spwd *spent;
{
	struct spwd *sp;

	if (!(sp = (struct spwd *) malloc(sizeof *sp)))
		return NULL;
	*sp = *spent;
	if (!(sp->sp_namp = strdup(spent->sp_namp)))
		return NULL;
	if (!(sp->sp_pwdp = strdup(spent->sp_pwdp)))
		return NULL;
	return sp;
}

static void *
shadow_dup(entry)
	const void *entry;
{
	const struct spwd *sp = entry;
	return __spw_dup(sp);
}

static void
shadow_free(entry)
	void *entry;
{
	struct spwd *sp = entry;

	free(sp->sp_namp);
	free(sp->sp_pwdp);
	free(sp);
}

static const char *
shadow_getname(entry)
	const void *entry;
{
	const struct spwd *sp = entry;
	return sp->sp_namp;
}

static void *
shadow_parse(line)
	const char *line;
{
	return (void *) sgetspent(line);
}

static int
shadow_put(entry, file)
	const void *entry;
	FILE *file;
{
	const struct spwd *sp = entry;
	return (putspent(sp, file) == -1) ? -1 : 0;
}

static struct commonio_ops shadow_ops = {
	shadow_dup,
	shadow_free,
	shadow_getname,
	shadow_parse,
	shadow_put,
	fgets,
	fputs
};

static struct commonio_db shadow_db = {
	"/etc/shadow",
	&shadow_ops,
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
spw_name(filename)
	const char *filename;
{
	return commonio_setname(&shadow_db, filename);
}

int
spw_lock()
{
	return commonio_lock(&shadow_db);
}

int
spw_lock_first()
{
	return commonio_lock_first(&shadow_db);
}

int
spw_open(mode)
	int mode;
{
	return commonio_open(&shadow_db, mode);
}

const struct spwd *
spw_locate(name)
	const char *name;
{
	return commonio_locate(&shadow_db, name);
}

int
spw_update(sp)
	const struct spwd *sp;
{
	return commonio_update(&shadow_db, (const void *) sp);
}

int
spw_remove(name)
	const char *name;
{
	return commonio_remove(&shadow_db, name);
}

int
spw_rewind()
{
	return commonio_rewind(&shadow_db);
}

const struct spwd *
spw_next()
{
	return commonio_next(&shadow_db);
}

int
spw_close()
{
	return commonio_close(&shadow_db);
}

int
spw_unlock()
{
	return commonio_unlock(&shadow_db);
}

struct commonio_entry *
__spw_get_head()
{
	return shadow_db.head;
}

void
__spw_del_entry(entry)
	const struct commonio_entry *entry;
{
	commonio_del_entry(&shadow_db, entry);
}
#endif
