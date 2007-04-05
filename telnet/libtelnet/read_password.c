/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static char sccsid[] = "@(#)read_password.c	8.3 (Berkeley) 5/30/95";
#endif /* not lint */

/*
 * $Source: /usr/local/cvs/srp/telnet/libtelnet/read_password.c,v $
 * $Author: tom $
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * This routine prints the supplied string to standard
 * output as a prompt, and reads a password string without
 * echoing.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if	defined(RSA_ENCPWD) || defined(KRB4_ENCPWD) || defined(HAVE_SRP) || defined(TLS)

#include <stdio.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <setjmp.h>

#ifdef HAVE_TERMIOS_H
#define USE_TERMIO
#else  /* !HAVE_TERMIOS_H */
#ifdef HAVE_TERMIO_H
#define USE_TERMIO
#define SYSV_TERMIO
#endif
#endif /* HAVE_TERMIOS_H */

#ifdef USE_TERMIO
#include <termios.h>
#include <unistd.h>
#endif
#include <fcntl.h>

static jmp_buf env;

/*** Routines ****************************************************** */
/*
 * This version just returns the string, doesn't map to key.
 *
 * Returns 0 on success, non-zero on failure.
 */

int
local_des_read_pw_string(s,max,prompt,verify)
    char *s;
    int	max;
    char *prompt;
    int	verify;
{
    int ok = 0;
    char *ptr;

    jmp_buf old_env;
#ifndef USE_TERMIO
    struct sgttyb tty_state, old_state;
#else
    struct termios tty_state, old_state;
#endif
    int old_fflags;
    char key_string[BUFSIZ];

    if (max > BUFSIZ) {
	return -1;
    }

    /* XXX assume jmp_buf is typedef'ed to an array */
    memmove((char *)env, (char *)old_env, sizeof(env));
    if (setjmp(env))
	goto lose;

    /* save terminal state*/
#ifndef USE_TERMIO
    if (ioctl(0,TIOCGETP,(char *)&tty_state) == -1) {
	perror("ioctl");
	return -1;
    }
#else
    if (tcgetattr(0, &tty_state) < 0) {
	perror("tcgetattr");
	return -1;
    }
#endif
    memcpy(&old_state, &tty_state, sizeof(tty_state));
    if((old_fflags = fcntl(0, F_GETFL, 0)) < 0) {
      perror("fcntl");
      return -1;
    }
/*
    push_signals();
*/
    /* Turn off echo */
#ifndef USE_TERMIO
    tty_state.sg_flags &= ~ECHO;
    tty_state.sg_flags &= ~CBREAK;
    tty_state.sg_flags |= CRMOD;
#else
    tty_state.c_lflag &= ~ECHO;
    tty_state.c_lflag |= ICANON;
    tty_state.c_iflag |= ICRNL;
    tty_state.c_oflag |= ONLCR;
#endif
#ifndef USE_TERMIO
    if (ioctl(0,TIOCSETP,(char *)&tty_state) == -1)
	return -1;
#else
    if (tcsetattr(0, TCSANOW, &tty_state) < 0)
	return -1;
#endif
    /* Disable nonblocking I/O */
    if(old_fflags & O_NDELAY)
      fcntl(0, F_SETFL, old_fflags & ~O_NDELAY);
    while (!ok) {
	(void) printf(prompt);
	(void) fflush(stdout);
	while (!fgets(s, max, stdin));

	if ((ptr = strchr(s, '\n')))
	    *ptr = '\0';
	if (verify) {
	    printf("\nVerifying, please re-enter %s",prompt);
	    (void) fflush(stdout);
	    if (!fgets(key_string, sizeof(key_string), stdin)) {
		clearerr(stdin);
		continue;
	    }
	    if ((ptr = strchr(key_string, '\n')))
	    *ptr = '\0';
	    if (strcmp(s,key_string)) {
		printf("\n\07\07Mismatch - try again\n");
		(void) fflush(stdout);
		continue;
	    }
	}
	ok = 1;
    }

lose:
    if (!ok)
	memset(s, 0, max);
    printf("\n");
    /* turn echo back on */
#ifndef USE_TERMIO
    if (ioctl(0,TIOCSETP,(char *)&old_state))
	ok = 0;
#else
    if (tcsetattr(0, TCSANOW, &old_state))
	ok = 0;
#endif
    if(old_fflags & O_NDELAY)
      fcntl(0, F_SETFL, old_fflags);
/*
    pop_signals();
*/
    memmove((char *)old_env, (char *)env, sizeof(env));
    if (verify)
	memset(key_string, 0, sizeof (key_string));
    s[max-1] = 0;		/* force termination */
    return !ok;			/* return nonzero if not okay */
}

int
read_string(s,max,prompt)
    char *s;
    int	max;
    char *prompt;
{
    int ok = 0;
    char *ptr;

    jmp_buf old_env;
#ifndef USE_TERMIO
    struct sgttyb tty_state, old_state;
#else
    struct termios tty_state, old_state;
#endif
    int old_fflags;

    if (max > BUFSIZ) {
	return -1;
    }

    /* XXX assume jmp_buf is typedef'ed to an array */
    memmove((char *)env, (char *)old_env, sizeof(env));
    if (setjmp(env))
	goto lose;

    /* save terminal state*/
#ifndef USE_TERMIO
    if (ioctl(0,TIOCGETP,(char *)&tty_state) == -1) {
	perror("ioctl");
	return -1;
    }
#else
    if (tcgetattr(0, &tty_state) < 0) {
	perror("tcgetattr");
	return -1;
    }
#endif
    memcpy(&old_state, &tty_state, sizeof(tty_state));
    if((old_fflags = fcntl(0, F_GETFL, 0)) < 0) {
      perror("fcntl");
      return -1;
    }
/*
    push_signals();
*/
    /* Turn on echo */
#ifndef USE_TERMIO
    tty_state.sg_flags |= ECHO;
    tty_state.sg_flags &= ~CBREAK;
    tty_state.sg_flags |= CRMOD;
#else
    tty_state.c_lflag |= ECHO;
    tty_state.c_lflag |= ICANON;
    tty_state.c_iflag |= ICRNL;
    tty_state.c_oflag |= ONLCR;
#endif
#ifndef USE_TERMIO
    if (ioctl(0,TIOCSETP,(char *)&tty_state) == -1)
	return -1;
#else
    if (tcsetattr(0, TCSANOW, &tty_state) < 0)
	return -1;
#endif
    /* Disable nonblocking I/O */
    if(old_fflags & O_NDELAY)
      fcntl(0, F_SETFL, old_fflags & ~O_NDELAY);
    while (!ok) {
	(void) printf(prompt);
	(void) fflush(stdout);
	while (!fgets(s, max, stdin));

	if ((ptr = strchr(s, '\n')))
	    *ptr = '\0';
	ok = 1;
    }

lose:
    if (!ok)
	memset(s, 0, max);
#ifndef USE_TERMIO
    if (ioctl(0,TIOCSETP,(char *)&old_state))
	ok = 0;
#else
    if (tcsetattr(0, TCSANOW, &old_state))
	ok = 0;
#endif
    if(old_fflags & O_NDELAY)
      fcntl(0, F_SETFL, old_fflags);
/*
    pop_signals();
*/
    memmove((char *)old_env, (char *)env, sizeof(env));
    s[max-1] = 0;		/* force termination */
    return !ok;			/* return nonzero if not okay */
}
#endif	/* defined(RSA_ENCPWD) || defined(KRB4_ENCPWD) || defined(HAVE_SRP) || defined(TLS) */
