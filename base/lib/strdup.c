#include <config.h>
#include "defines.h"
#include "rcsid.h"
RCSID("$Id: strdup.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

extern char *malloc();

char *
strdup(str)
	const char *str;
{
	char *s = malloc(strlen(str) + 1);

	if (s)
		strcpy(s, str);
	return s;
}
