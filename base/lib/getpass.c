/*
 * Copyright 1990 - 1995, Julianne Frances Haugh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Julianne F. Haugh nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JULIE HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JULIE HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: getpass.c,v 1.1 2000/12/17 05:34:10 tom Exp $")

#include "defines.h"

#include <signal.h>
#include <stdio.h>

#if 0  /* XXX */
/*
 * limits.h may be kind enough to specify the length of a prompted
 * for password.
 */

#if defined(__STDC__)
#if __STDC__
#include <limits.h>
#endif
#elif defined(_POSIX_SOURCE)
#include <limits.h>
#endif
#endif  /* XXX */

#ifdef MD5_CRYPT
#define PASS_MAX 127
#endif

/*
 * This is really a giant mess.  On the one hand, it would be nice
 * if PASS_MAX were real big so that DOUBLESIZE isn't needed.  But
 * if it is defined we must honor it because some idiot might use
 * this in a routine expecting some standard behavior.
 */

#ifndef	PASS_MAX
#ifdef	SW_CRYPT
#define	PASS_MAX	80
#else	/* !SW_CRYPT */
#ifdef	SKEY
#define	PASS_MAX	40
#else	/* !SKEY */
#ifdef	DOUBLESIZE
#define	PASS_MAX	16
#else	/* !PASS_MAX */
#define	PASS_MAX	8
#endif	/* DOUBLESIZE */
#endif	/* SKEY */
#endif	/* SW_CRYPT */
#endif	/* !PASS_MAX */

static	int	sig_caught;
#ifdef HAVE_SIGACTION
static	struct	sigaction sigact;
#endif

/*ARGSUSED*/
static RETSIGTYPE
sig_catch (sig)
int	sig;
{
	sig_caught = 1;
}

char *
getpass (prompt)
	const char *prompt;
{
	static	char	input[PASS_MAX+1];
	char	*return_value = 0;
	char	*cp;
	FILE	*fp;
	int	tty_opened = 0;
#ifdef HAVE_SIGACTION
	struct	sigaction old_sigact;
#else
	RETSIGTYPE	(*old_signal)();
#endif
	TERMIO	new_modes;
	TERMIO	old_modes;

	/*
	 * set a flag so the SIGINT signal can be re-sent if it
	 * is caught
	 */

	sig_caught = 0;

	/*
	 * if /dev/tty can't be opened, getpass() needs to read
	 * from stdin instead.
	 */

	if ((fp = fopen ("/dev/tty", "r")) == 0) {
		fp = stdin;
		setbuf (fp, (char *) 0);
	} else {
		tty_opened = 1;
	}

	/*
	 * the current tty modes must be saved so they can be
	 * restored later on.  echo will be turned off, except
	 * for the newline character (BSD has to punt on this)
	 */

	if (GTTY (fileno (fp), &new_modes))
		return 0;

	old_modes = new_modes;
#ifdef HAVE_SIGACTION
	sigact.sa_handler = sig_catch;
	(void) sigaction (SIGINT, &sigact, &old_sigact);
#else
	old_signal = signal (SIGINT, sig_catch);
#endif

#ifdef USE_SGTTY
	new_modes.sg_flags &= ~ECHO ;
#else
	new_modes.c_lflag &= ~(ECHO|ECHOE|ECHOK);
	new_modes.c_lflag |= ECHONL;
#endif

	if (STTY (fileno (fp), &new_modes))
		goto out;

	/*
	 * the prompt is output, and the response read without
	 * echoing.  the trailing newline must be removed.  if
	 * the fgets() returns an error, a NULL pointer is
	 * returned.
	 */

	if (fputs (prompt, stdout) == EOF)
		goto out;

	(void) fflush (stdout);

	if (fgets (input, sizeof input, fp) == input) {
		if ((cp = strchr (input, '\n')))
			*cp = '\0';
		else
			input[sizeof input - 1] = '\0';

		return_value = input;
#ifdef USE_SGTTY
		putc ('\n', stdout);
#endif
	}
out:
	/*
	 * the old SIGINT handler is restored after the tty
	 * modes.  then /dev/tty is closed if it was opened in
	 * the beginning.  finally, if a signal was caught it
	 * is sent to this process for normal processing.
	 */

	if (STTY (fileno (fp), &old_modes))
		return_value = 0;

#ifdef HAVE_SIGACTION
	(void) sigaction (SIGINT, &old_sigact, NULL);
#else
	(void) signal (SIGINT, old_signal);
#endif
	if (tty_opened)
		(void) fclose (fp);

	if (sig_caught) {
		kill (getpid (), SIGINT);
		return_value = 0;
	}

#if 1
	/* Don't return NULL on EOF or SIGINT, breaks too many programs
	   that need to be linked with libshadow.a (screen).  --marekm */

	if (!return_value) {
		input[0] = '\0';
		return_value = input;
	}
#endif
	return return_value;
}
