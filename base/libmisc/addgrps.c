#include <config.h>

#ifdef HAVE_SETGROUPS

#include "defines.h"

#include <stdio.h>
#include <grp.h>
#include <errno.h>

#include "rcsid.h"
RCSID("$Id: addgrps.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

#define SEP ",:"

/*
 * Add groups with names from LIST (separated by commas or colons)
 * to the supplementary group set.  Silently ignore groups which are
 * already there.  Warning: uses strtok().
 */

int
add_groups(list)
	const char *list;
{
	gid_t grouplist[NGROUPS_MAX];
	int i, ngroups, added;
	struct group *grp;
	char *token;
	char buf[1024];

	if (strlen(list) >= sizeof(buf)) {
		errno = EINVAL;
		return -1;
	}
	strcpy(buf, list);

	ngroups = getgroups(NGROUPS_MAX, grouplist);
	if (ngroups < 0)
		return -1;

	added = 0;
	for (token = strtok(buf, SEP); token; token = strtok(NULL, SEP)) {

		grp = getgrnam(token);
		if (!grp) {
			fprintf(stderr, "Warning: unknown group %s\n", token);
			continue;
		}

		for (i = 0; i < ngroups && grouplist[i] != grp->gr_gid; i++)
			;

		if (i < ngroups)
			continue;

		if (ngroups >= NGROUPS_MAX) {
			fprintf(stderr, "Warning: too many groups\n");
			break;
		}
		grouplist[ngroups++] = grp->gr_gid;
		added++;
	}

	if (added)
		return setgroups(ngroups, grouplist);

	return 0;
}
#endif
