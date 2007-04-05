/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |   Author: Eugene Jhong                                                     |
 |                                                                            |
 +----------------------------------------------------------------------------*/

/*
 * Copyright (c) 1997 Stanford University
 *
 * Permission to use, copy, modify, distribute, and sell this software and
 * its documentation for any purpose is hereby granted without fee, provided
 * that the above copyright notices and this permission notice appear in
 * all copies of the software and related documentation.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL STANFORD BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include "krypto.h"


static unsigned char key[] =
{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x07,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x07 };

static unsigned char iv[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static unsigned char message1[] = "Testing testing 1 2 3....";
static unsigned char message2[] = "This is a test of the emergency broadcast...";

static unsigned char seq[] = { 0x00, 0x00, 0x00, 0x00 };

int
main ()
{
  unsigned char buf1[512];
  unsigned char buf2[512];

  int len, i, j;
  krypto_context *ecc, *dcc;
  int status = 0;

  unsigned char *clist = cipher_getlist ();
  unsigned char *hlist = hash_getlist ();

  printf ("\n");

  for (i = 0; i < strlen (clist); i++)
  for (j = 0; j < strlen (hlist); j++)
  {
    ecc = krypto_new (clist[i], hlist[j], key, 24, iv, sizeof(iv),
      seq, KRYPTO_ENCODE);
    dcc = krypto_new (clist[i], hlist[j], key, 24, iv, sizeof(iv),
      seq, KRYPTO_DECODE);

    printf ("Testing %s with %s...\n",
      ecc->c->cipher->name, ecc->h->hash->name);

    len = krypto_msg_safe (ecc, message1, buf1, sizeof(message1));
    len = krypto_msg_safe (dcc, buf1, buf2, len);

    if (memcmp (message1, buf2, strlen (message1)))
    { printf ("  safe failed!"); status = 1; }

    len = krypto_msg_safe (ecc, message2, buf1, sizeof(message2));
    len = krypto_msg_safe (dcc, buf1, buf2, len);

    if (memcmp (message2, buf2, strlen (message2)))
    { printf ("  safe failed!"); status = 1; }

    len = krypto_msg_priv (ecc, message1, buf1, sizeof(message1));
    len = krypto_msg_priv (dcc, buf1, buf2, len);

    if (memcmp (message1, buf2, strlen (message1)))
    { printf ("  priv failed!"); status = 1; }

    len = krypto_msg_priv (ecc, message2, buf1, sizeof(message2));
    len = krypto_msg_priv (dcc, buf1, buf2, len);

    if (memcmp (message2, buf2, strlen (message2)))
    { printf ("  priv failed!"); status = 1; }

    krypto_delete (ecc);
    krypto_delete (dcc);
  }

  printf ("\n");

  return status;
}
