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
#include "krypto_locl.h"

struct test_entry {
    char *string;
    unsigned char digest[20];
};

struct test_entry md_test_suite[] = {
    { "",
        { 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
          0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e } },
    { "a",
        { 0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
          0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61 } },
    { "abc",
        { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
          0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 } }, 
    { "message digest",
        { 0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
          0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0 } },
    { "abcdefghijklmnopqrstuvwxyz",
        { 0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00,
          0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b } },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        { 0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5,
          0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f } },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	{ 0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55,
          0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a } },
    { 0, { 0 } }
};


struct test_entry sha_test_suite[] = {
    { "abc",
        { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
          0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d } }, 
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
          0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 } },
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        { 0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e,
          0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f } },
    { 0, { 0 } }
};


int
main(argc, argv)
  int argc;
  char **argv;
{
  hash_desc * desc;
  hash *h;
  unsigned char *list = hash_getlist ();
  int i;
  unsigned char digest[20];
  int status = 0;

  struct test_entry *entry;
  int num_tests = 0, num_failed = 0;

  /* print out supported hashs */

  printf ("\nSupported Hash Functions:\n\n");
  for (i = 0; i < strlen (list); i++)
  {
    desc = hash_getdescbyid (list[i]);
    printf ("  %s (%d)\n", desc->name, desc->id);
  }
  printf ("\n");

#ifdef HASH_MD5
  printf ("Testing MD5...\n");

  desc = hash_getdescbyname ("MD5");
  h = hash_new (desc);

  for (entry = md_test_suite; entry->string; entry++)
  {
    unsigned int len = strlen (entry->string);

    hash_init (h);
    hash_update (h, (unsigned char *) entry->string, len);
    hash_final (h, digest);

    for (i=0; i < 16; i++)
      if (digest[i] != entry->digest[i]) { num_failed++; break; }

    num_tests++;
  }

  hash_delete (h);

  if (num_failed)
  { printf("%d out of %d tests failed for MD5!!!\n\n", num_failed, num_tests);
    status = 1; }
#endif /* HASH_MD5 */

  printf ("Testing SHA...\n");

  num_failed = 0; num_tests = 0;

  desc = hash_getdescbyname ("SHA");
  h = hash_new (desc);

  for (entry = sha_test_suite; entry->string; entry++)
  {
    unsigned int len = strlen (entry->string);

    hash_init (h);
    if (num_tests == 2)
      for (i = 0; i < 15625; i++)
        hash_update (h, (unsigned char *) entry->string, len);
    else
        hash_update (h, (unsigned char *) entry->string, len);
    hash_final (h, digest);

    for (i=0; i < 20; i++)
      if (digest[i] != entry->digest[i]) { num_failed++; break; }

    num_tests++;
  }

  hash_delete (h);

  if (num_failed)
  { printf("%d out of %d tests failed for SHA!!!\n\n", num_failed, num_tests);
    status = 1; }

  printf ("\n");

  return status;
}
