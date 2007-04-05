/*
 * basename.c - not worth copyrighting :-).  Some versions of Linux libc
 * already have basename(), other versions don't.  To avoid confusion,
 * we will not use the function from libc and use a different name here.
 * --marekm
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: basename.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

#include "defines.h"

char *
Basename(str)
	char *str;
{
	char *cp = strrchr(str, '/');

	return cp ? cp+1 : str;
}
