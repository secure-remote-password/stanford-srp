/* $Header: /usr/local/cvs/srp/base/pam_eps/pam_eps_auth.c,v 1.1 2000/12/17 05:34:12 tom Exp $ */

/*
 * Copyright Alexander O. Yuriev, 1996.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
/* 
 * $Log: pam_eps_auth.c,v $
 * Revision 1.1  2000/12/17 05:34:12  tom
 * Initial checkin
 *
 * Revision 1.1  1996/11/09 19:44:35  morgan
 * Initial revision
 *
 * Revision 1.9  1996/05/26 04:13:04  morgan
 * added static support
 *
 * Revision 1.8  1996/05/21 03:51:58  morgan
 * added "const" to rcsid[] definition
 *
 * Revision 1.7  1996/04/19 03:25:57  alex
 * minor corrections.
 *
 * Revision 1.6  1996/04/17 01:05:05  alex
 * _pam_auth_unix() cleaned up - non-authentication code is made into funcs
 * and mostly moved out to support.c.
 *
 * Revision 1.5  1996/04/16 21:12:46  alex
 * unix authentication works on Bach again. This is a tranitional stage.
 * I really don't like that _pam_unix_auth() grew into a monster that does
 * prompts etc etc. They should go into other functions.
 *
 * Revision 1.4  1996/04/07 08:06:12  morgan
 * tidied up a little
 *
 * Revision 1.3  1996/04/07 07:34:07  morgan
 * added conversation support. Now the module is capable of obtaining a
 * username and a password all by itself.
 *
 * Revision 1.2  1996/03/29 02:31:19  morgan
 * Marek Michalkiewicz's small patches for shadow support.
 *
 * Revision 1.1  1996/03/09 09:10:57  morgan
 * Initial revision
 *
 */

/* Additional coding and modification for EPS support by Tom Wu
 * <tjw@cs.Stanford.EDU>, Copyright 1997.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#ifndef NDEBUG

	#include <syslog.h>

#endif	/* NDEBUG */

#ifndef LINUX 

	#include <security/pam_appl.h>

#endif  /* LINUX */

#define _PAM_EXTERN_FUNCTIONS
#include <security/pam_modules.h>
#include <unistd.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

/* static const char rcsid[] = "$Id: pam_eps_auth.c,v 1.1 2000/12/17 05:34:12 tom Exp $ pam_unix authentication functions. alex@bach.cis.temple.edu"; */

/* Define function phototypes */

extern	int converse(   pam_handle_t *pamh, 
			int nargs, 
			struct pam_message **message,
                        struct pam_response **response  ); 
                        
extern 	int _set_auth_tok(	pam_handle_t *pamh, 
				int flags, int argc, 
				const char **argv	);

static	int _pam_auth_eps(	pam_handle_t *pamh, 
				int flags, int argc, 
				const char **argv	);

static	int _pam_set_credentials_eps (	pam_handle_t *pamh, 
					int flags, 
					int argc,
					const char ** argv ) ;


/*  fix for vlock, etc. (cf. pam_pwdb) */

static int t_run_helper_binary (const char *name, char *pass) {

  int retval, child, fds[2];
  char *args[2], *envp[1];

  if (pipe (fds) != 0)  return PAM_AUTH_ERR;

  child= fork();

  if (child == 0) {

    close (fds[1]);
    dup2 (fds[0], 0);
    args[0]= strdup("/sbin/eps_chkpwd");
    args[1]= NULL;  envp[0]= NULL;
    execve (args[0], args, envp);
    return PAM_AUTH_ERR;

  } else {

    close (fds[0]);
    write (fds[1], "1:", 2);
    write (fds[1], pass, strlen(pass)+1);
    close (fds[1]);

  };

  (void) waitpid (child, &retval, 0);
  return ((retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR);
}


/* Fun starts here :)
 * 
 * _pam_auth_eps() actually performs EPS local authentication
 */

static int _pam_auth_eps(	pam_handle_t *pamh,
				int flags, 
				int argc,
				const char **argv	) 
{
        int retval;
	const char *name;
	char *p;

	/* get the user'name' */

	if ( (retval = pam_get_user( pamh, &name, "login: ") ) != PAM_SUCCESS )
		return retval;

	/*
	 * at some point we will have to make this module pay
	 * attention to arguments, like 'pam_first_pass' etc...
	 */

	pam_get_item( pamh, PAM_AUTHTOK, (void*) &p );

	if ( !p ) 
		{
			retval = _set_auth_tok( pamh, flags, argc, argv );
			if ( retval != PAM_SUCCESS ) 
				return retval;
 		}
	
	/* 
	   We have to call pam_get_item() again because value of p should
	   change 
	 */
	
	pam_get_item( pamh, PAM_AUTHTOK, (void*) &p );

	/*
	if ( ( !pw->pw_passwd ) && ( !p ) )
		if ( flags && PAM_DISALLOW_NULL_AUTHTOK )
			return PAM_SUCCESS;
		else
			return PAM_AUTH_ERR;
			*/

	if (geteuid() == 0) {
		retval = t_verifypw(name, p);
	} else {
		retval = t_run_helper_binary (name, p);
		if (retval > 200)  retval= 256 - retval;
	};

	if(retval > 0)
	  return PAM_SUCCESS;
	else if(retval < 0)
	  return PAM_USER_UNKNOWN;
	else
	  return PAM_AUTH_ERR;
}

/* 
 * The only thing _pam_set_credentials_eps() does is initialization of
 * UNIX group IDs.
 *
 * Well, everybody but me on linux-pam is convinced that it should not
 * initialize group IDs, so I am not doing it but don't say that I haven't
 * warned you. -- AOY
 */

static	int _pam_set_credentials_eps (	pam_handle_t *pamh, 
					int flags, 
					int argc,
					const char **argv )

{	/* FIX ME: incorrect error code */

	return	PAM_SUCCESS;	/* This is a wrong result code. From what I
				   remember from reafing one of the guides
				   there's an error-level saying 'N/A func'
				   	-- AOY
				 */
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */
 
PAM_EXTERN
int pam_sm_authenticate(	pam_handle_t *pamh, 
				int flags,
				int argc, 
				const char **argv	)
{
	return _pam_auth_eps( pamh, flags, argc, argv	);
}

PAM_EXTERN
int pam_sm_setcred( pam_handle_t *pamh, 
		    int flags,
		    int argc, 
		    const char **argv)
{
	return _pam_set_credentials_eps ( pamh, flags, argc, argv ) ;
}


/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_eps_auth_modstruct = {
    "pam_eps_auth",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
