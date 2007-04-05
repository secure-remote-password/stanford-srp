
#include <config.h>

#include "rcsid.h"
RCSID("$Id: tpwio.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

#include "prototypes.h"
#include "defines.h"
#include <pwd.h>
#include <stdio.h>

#include "commonio.h"
#include "tpwio.h"

static struct commonio_db tpasswd_db = {
	"/etc/tpasswd",
	NULL,
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
tpw_lock()
{
	return commonio_lock(&tpasswd_db);
}

int
tpw_lock_first()
{
	return commonio_lock_first(&tpasswd_db);
}

int
tpw_unlock()
{
	return commonio_unlock(&tpasswd_db);
}
