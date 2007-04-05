#include <config.h>

#if defined(PAM) && defined(PAM_MISC)

#include "rcsid.h"
RCSID("$Id: pam_pass.c,v 1.1 2000/12/17 05:34:11 tom Exp $")

/*
 * Change the user's password using PAM.  Requires libpam and
 * libpam_misc (for misc_conv).  --marekm
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
	misc_conv,
	NULL
};

void
do_pam_passwd(user, flags)
	const char *user;
	int flags;
{
	pam_handle_t *pamh = NULL;
	int ret;

	ret = pam_start("passwd", user, &conv, &pamh);
	if (ret != PAM_SUCCESS)
		goto failure;

	ret = pam_chauthtok(pamh, flags);
	if (ret != PAM_SUCCESS) {
		pam_end(pamh, ret);
		goto failure;
	}

	ret = pam_end(pamh, PAM_SUCCESS);
	if (ret != PAM_SUCCESS) {
failure:
		/* TJW: Some older PAM installations have only
		 * one argument to "pam_strerror" below. */
		fprintf(stderr, "passwd: %s\n",
#ifdef PAM_OLD
			pam_strerror(ret)
#else
			pam_strerror(pamh, ret)
#endif /* PAM_OLD */
			);
		exit(1);
	}
}
#endif /* PAM && PAM_MISC */
