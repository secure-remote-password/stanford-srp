/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |   Author: Thomas Wu                                                        |
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

#include <stdio.h>
#ifdef WIN32
#include <sys/timeb.h>
#else
#include <sys/time.h>
#endif /* WIN32 */

#include "krypto.h"

static unsigned char testkey[] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
  0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
  0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F
};

#define NRUNS	500000

void
bcipher_bench(cipher_name, len)
     char * cipher_name;
     int len;
{
  cipher_desc * desc;
  cipher * cph;
  unsigned char data[8];
  unsigned int *lo, *hi;
  int i;
#ifdef WIN32
  struct timeb before, after;
  unsigned long elapsedms;
#else
  struct timeval before, after;
  unsigned long elapsedus;
#endif /* WIN32 */

  lo = (unsigned int *) data;
  hi = (unsigned int *) (data + 4);

  desc = cipher_getdescbyname(cipher_name);

  if (!desc) return;

  printf("Benchmarking %d-bit %s:\n", 8 * len, cipher_name);

  cph = cipher_new(desc);

  cipher_initencrypt(cph, testkey, len);
  memset(data, 0, 8);
#ifdef WIN32
  ftime(&before);
#else
  gettimeofday(&before, NULL);
#endif /* WIN32 */
  for(i = 0; i < NRUNS; ++i)
    cipher_crypt(cph, data, data, 8);
#ifdef WIN32
  ftime(&after);
  elapsedms = 1000 * (after.time - before.time) +
    after.millitm - before.millitm;
#else
  gettimeofday(&after, NULL);
  elapsedus = 1000000 * (after.tv_sec - before.tv_sec) +
    after.tv_usec - before.tv_usec;
#endif /* WIN32 */
  cipher_initdecrypt(cph, testkey, len);
#ifdef WIN32
  ftime(&before);
#else
  gettimeofday(&before, NULL);
#endif /* WIN32 */
  for(i = 0; i < NRUNS; ++i)
    cipher_crypt(cph, data, data, 8);
#ifdef WIN32
  ftime(&after);
  elapsedms += 1000 * (after.time - before.time) +
    after.millitm - before.millitm;
#else
  gettimeofday(&after, NULL);
  elapsedus += 1000000 * (after.tv_sec - before.tv_sec) +
    after.tv_usec - before.tv_usec;
#endif /* WIN32 */
  if(*lo || *hi)
    printf("*** %s encryption/decryption error: [%08x %08x] != 0\n", *lo, *hi);
#ifdef WIN32
  printf("Time for %d runs: %d.%03d sec (%g Kb/sec)\n", 2 * NRUNS,
	 elapsedms / 1000, elapsedms % 1000,
	 16.0 * NRUNS / (float) elapsedms);
#else
  printf("Time for %d runs: %d.%06d sec (%g Kb/sec)\n", 2 * NRUNS,
	 elapsedus / 1000000, elapsedus % 1000000,
	 16000.0 * NRUNS / (float) elapsedus);
#endif /* WIN32 */
  putchar('\n');

  cipher_delete(cph);
}

int
main(argc, argv)
     int argc;
     char **argv;
{
  bcipher_bench("BLOWFISH_ECB", 16);
  bcipher_bench("IDEA_ECB", 16);
  bcipher_bench("DES_ECB", 8);
  bcipher_bench("DES3_ECB", 24);
  bcipher_bench("CAST5_ECB", 16);
  bcipher_bench("ARCFOUR", 16);
  return 0;
}
