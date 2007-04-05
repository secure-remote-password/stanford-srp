
#include <config.h>

#include "rcsid.h"
RCSID("$Id: groupio.c,v 1.1 2000/12/17 05:34:10 tom Exp $")

#include "prototypes.h"
#include "defines.h"

#include "commonio.h"
#include "groupio.h"

extern int putgrent P_((const struct group *, FILE *));
extern struct group *sgetgrent P_((const char *));

struct group *
__gr_dup(grent)
	const struct group *grent;
{
	struct group *gr;
	int i;

	if (!(gr = (struct group *) malloc(sizeof *gr)))
		return NULL;
	*gr = *grent;
	if (!(gr->gr_name = strdup(grent->gr_name)))
		return NULL;
	if (!(gr->gr_passwd = strdup(grent->gr_passwd)))
		return NULL;

	for (i = 0; grent->gr_mem[i]; i++)
		;
	gr->gr_mem = (char **) malloc((i + 1) * sizeof(char *));
	if (!gr->gr_mem)
		return NULL;
	for (i = 0; grent->gr_mem[i]; i++) {
		gr->gr_mem[i] = strdup(grent->gr_mem[i]);
		if (!gr->gr_mem[i])
			return NULL;
	}
	gr->gr_mem[i] = NULL;
	return gr;
}

static void *
group_dup(entry)
	const void *entry;
{
	const struct group *gr = entry;
	return __gr_dup(gr);
}

static void
group_free(entry)
	void *entry;
{
	struct group *gr = entry;

	free(gr->gr_name);
	free(gr->gr_passwd);
	while(*(gr->gr_mem)) {
		free(*(gr->gr_mem));
		gr->gr_mem++;
	}
	free(gr);
}

static const char *
group_getname(entry)
	const void *entry;
{
	const struct group *gr = entry;
	return gr->gr_name;
}

static void *
group_parse(line)
	const char *line;
{
	return (void *) sgetgrent(line);
}

static int
group_put(entry, file)
	const void *entry;
	FILE *file;
{
	const struct group *gr = entry;
	return (putgrent(gr, file) == -1) ? -1 : 0;
}

static struct commonio_ops group_ops = {
	group_dup,
	group_free,
	group_getname,
	group_parse,
	group_put,
	fgetsx,
	fputsx
};

static struct commonio_db group_db = {
	"/etc/group",
	&group_ops,
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
gr_name(filename)
	const char *filename;
{
	return commonio_setname(&group_db, filename);
}

int
gr_lock()
{
	return commonio_lock(&group_db);
}

int
gr_open(mode)
	int mode;
{
	return commonio_open(&group_db, mode);
}

const struct group *
gr_locate(name)
	const char *name;
{
	return commonio_locate(&group_db, name);
}

int
gr_update(gr)
	const struct group *gr;
{
	return commonio_update(&group_db, (const void *) gr);
}

int
gr_remove(name)
	const char *name;
{
	return commonio_remove(&group_db, name);
}

int
gr_rewind()
{
	return commonio_rewind(&group_db);
}

const struct group *
gr_next()
{
	return commonio_next(&group_db);
}

int
gr_close()
{
	return commonio_close(&group_db);
}

int
gr_unlock()
{
	return commonio_unlock(&group_db);
}

void
__gr_set_changed()
{
	group_db.changed = 1;
}

struct commonio_entry *
__gr_get_head()
{
	return group_db.head;
}

void
__gr_del_entry(entry)
	const struct commonio_entry *entry;
{
	commonio_del_entry(&group_db, entry);
}
