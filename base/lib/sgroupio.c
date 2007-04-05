
#include <config.h>

#ifdef SHADOWGRP

#include "rcsid.h"
RCSID("$Id: sgroupio.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

#include "prototypes.h"
#include "defines.h"

#include "commonio.h"
#include "sgroupio.h"

extern int putsgent P_((const struct sgrp *, FILE *));
extern struct sgrp *sgetsgent P_((const char *));

struct sgrp *
__sgr_dup(sgent)
	const struct sgrp *sgent;
{
	struct sgrp *sg;
	int i;

	if (!(sg = (struct sgrp *) malloc(sizeof *sg)))
		return NULL;
	*sg = *sgent;
	if (!(sg->sg_name = strdup(sgent->sg_name)))
		return NULL;
	if (!(sg->sg_passwd = strdup(sgent->sg_passwd)))
		return NULL;

	for (i = 0; sgent->sg_adm[i]; i++)
		;
	sg->sg_adm = (char **) malloc((i + 1) * sizeof(char *));
	if (!sg->sg_adm)
		return NULL;
	for (i = 0; sgent->sg_adm[i]; i++) {
		sg->sg_adm[i] = strdup(sgent->sg_adm[i]);
		if (!sg->sg_adm[i])
			return NULL;
	}
	sg->sg_adm[i] = NULL;

	for (i = 0; sgent->sg_mem[i]; i++)
		;
	sg->sg_mem = (char **) malloc((i + 1) * sizeof(char *));
	if (!sg->sg_mem)
		return NULL;
	for (i = 0; sgent->sg_mem[i]; i++) {
		sg->sg_mem[i] = strdup(sgent->sg_mem[i]);
		if (!sg->sg_mem[i])
			return NULL;
	}
	sg->sg_mem[i] = NULL;

	return sg;
}

static void *
gshadow_dup(entry)
	const void *entry;
{
	const struct sgrp *sg = entry;
	return __sgr_dup(sg);
}

static void
gshadow_free(entry)
	void *entry;
{
	struct sgrp *sg = entry;

	free(sg->sg_name);
	free(sg->sg_passwd);
	while(*(sg->sg_adm)) {
		free(*(sg->sg_adm));
		sg->sg_adm++;
	}
	while(*(sg->sg_mem)) {
		free(*(sg->sg_mem));
		sg->sg_mem++;
	}
	free(sg);
}

static const char *
gshadow_getname(entry)
	const void *entry;
{
	const struct sgrp *gr = entry;
	return gr->sg_name;
}

static void *
gshadow_parse(line)
	const char *line;
{
	return (void *) sgetsgent(line);
}

static int
gshadow_put(entry, file)
	const void *entry;
	FILE *file;
{
	const struct sgrp *sg = entry;
	return (putsgent(sg, file) == -1) ? -1 : 0;
}

static struct commonio_ops gshadow_ops = {
	gshadow_dup,
	gshadow_free,
	gshadow_getname,
	gshadow_parse,
	gshadow_put,
	fgetsx,
	fputsx
};

static struct commonio_db gshadow_db = {
	"/etc/gshadow",
	&gshadow_ops,
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
sgr_name(filename)
	const char *filename;
{
	return commonio_setname(&gshadow_db, filename);
}

int
sgr_lock()
{
	return commonio_lock(&gshadow_db);
}

int
sgr_open(mode)
	int mode;
{
	return commonio_open(&gshadow_db, mode);
}

const struct sgrp *
sgr_locate(name)
	const char *name;
{
	return commonio_locate(&gshadow_db, name);
}

int
sgr_update(sg)
	const struct sgrp *sg;
{
	return commonio_update(&gshadow_db, (const void *) sg);
}

int
sgr_remove(name)
	const char *name;
{
	return commonio_remove(&gshadow_db, name);
}

int
sgr_rewind()
{
	return commonio_rewind(&gshadow_db);
}

const struct sgrp *
sgr_next()
{
	return commonio_next(&gshadow_db);
}

int
sgr_close()
{
	return commonio_close(&gshadow_db);
}

int
sgr_unlock()
{
	return commonio_unlock(&gshadow_db);
}

void
__sgr_set_changed()
{
	gshadow_db.changed = 1;
}

struct commonio_entry *
__sgr_get_head()
{
	return gshadow_db.head;
}

void
__sgr_del_entry(entry)
	const struct commonio_entry *entry;
{
	commonio_del_entry(&gshadow_db, entry);
}
#endif
