/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: srpftp                                                          |
 |   Author: Eugene Jhong                                                     |
 |                                                                            |
 +----------------------------------------------------------------------------*/

/*
 * Copyright (c) 1997-2007  The Stanford SRP Authentication Project
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
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
 *
 * Redistributions in source or binary form must retain an intact copy
 * of this copyright notice.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef SRP

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <arpa/ftp.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pwd.h>
#include "t_pwd.h"
#include "t_server.h"
#include "krypto.h"

#define SRP_PROT_VERSION	1

/* SRP states */

#define SRP_OFF   0
#define SRP_PROT1 1
#define SRP_PROT2 2
#define SRP_PROT3 3
#define SRP_PROT4 4
#define SRP_PROT5 5
#define SRP_PROT6 6
#define SRP_ON    7

/* global variables */

char srp_user[MAXUSERLEN];

static int srp_state = SRP_OFF;
static struct t_server *ts = NULL;
static unsigned char *skey = NULL;
static krypto_context *incrypt = NULL;
static krypto_context *outcrypt = NULL;

#if (SIZEOF_SHORT == 4)
typedef unsigned short srp_uint32;
#elif (SIZEOF_INT == 4)
typedef unsigned int srp_uint32;
#elif (SIZEOF_LONG == 4)
typedef unsigned long srp_uint32;
#endif

extern char *auth_type;
extern int level;
extern int logging;
extern char remotehost[];


/*--------------------------------------------------------------+
 | srp_reset: reset and clean up state                          |
 +--------------------------------------------------------------*/
void srp_reset ()
{
  srp_state = SRP_OFF;

  if (ts)
  { t_serverclose (ts); ts = NULL; }
  if (incrypt)
  { krypto_delete (incrypt); incrypt = NULL; }
  if (outcrypt)
  { krypto_delete (outcrypt); outcrypt = NULL; }
}

/*--------------------------------------------------------------+
 | srp_auth:                                                    |
 +--------------------------------------------------------------*/
int srp_auth ()
{
  srp_reset ();
  srp_state = SRP_PROT1;
  return 1;
}

/*--------------------------------------------------------------+
 | srp_adat: do SRP protocol                                    |
 +--------------------------------------------------------------*/
int srp_adat (data)
  char *data;
{
  static unsigned char seqnum[4];

  unsigned char tmp[FTP_BUFSIZ];
  unsigned char buf[FTP_BUFSIZ];
  unsigned char *bp;
  int e, blen;

  switch (srp_state)
  {
  case SRP_PROT1:
  {
    unsigned char vers[4];
    unsigned char *vp;
    int vlen;

    bp = buf;

    /* get and send protocol version */

    if (e = radix_encode (data, bp, &blen, 1)) goto decode_error;
    if (srp_get (&bp, &vp, &blen, &vlen) != 4) goto data_error;

    memset (vers, 0, 4); vers[3] = SRP_PROT_VERSION;
    bp = tmp; blen = 0;
    srp_put (vers, &bp, 4, &blen);

    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;
    reply (335, "ADAT=%s", buf);
    srp_state++; return 0;
  }
  case SRP_PROT2:
  {
    /*
    struct t_pw *tpw;
    struct t_conf *tcnf;
    */
    unsigned char *up;
    int ulen;

    bp = buf;

    if (e = radix_encode (data, bp, &blen, 1)) goto decode_error;
    if (srp_get (&bp, &up, &blen, &ulen) < 0) goto data_error;

    up[ulen] = '\0';

    /*
    if ((tpw = t_openpw (NULL)) == NULL)
    {
      reply (431, "Need some unavailable resource for %s security.", "SRP");
      syslog (LOG_ERR, "Couldn't open tpasswd");
      srp_reset (); return 0;
    }
  
    if ((tcnf = t_openconf (NULL)) == NULL)
    {
      t_closepw (tpw);
      reply (431, "Need some unavailable resource for %s security.", "SRP");
      syslog (LOG_ERR, "Couldn't open tconf");
      srp_reset (); return 0;
    }
    */

    /*
    if ((ts = t_serveropen (up, tpw, tcnf)) == NULL)
    */
    if ((ts = t_serveropen (up)) == NULL)
    {
      /*
      t_closepw (tpw); t_closeconf (tcnf);
      */
      reply (535, "User %s access denied.", buf);
      if (logging) syslog (LOG_NOTICE, "SRP FTP LOGIN REFUSED FROM %s, %s",
        remotehost, buf);
      srp_reset (); return 0;
    }

    strncpy (srp_user, up, sizeof (srp_user));
    if (srp_user[sizeof(srp_user)] != '\0') srp_user[sizeof(srp_user)] = '\0';

    /*
    t_closepw (tpw); t_closeconf (tcnf);
    */

    /* send N, g and s */

    bp = tmp; blen = 0;
    srp_put (ts->n.data, &bp, ts->n.len, &blen);
    srp_put (ts->g.data, &bp, ts->g.len, &blen);
    srp_put (ts->s.data, &bp, ts->s.len, &blen);

    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;
    reply (335, "ADAT=%s", buf);

    /* generate yp */

    t_servergenexp (ts);

    srp_state++; return 0;
  }
  case SRP_PROT3:
  {
    struct t_num *yp;
    struct t_num wp;

    bp = buf;

    /* get wp */

    if (e = radix_encode (data, bp, &blen, 1)) goto decode_error;
    if (srp_get (&bp, &(wp.data), &blen, &(wp.len)) < 0) goto data_error;

    /* generate session key */

    skey = t_servergetkey (ts, &wp);
    yp = &(ts->B); 

    /* send yp */

    bp = tmp; blen = 0;
    srp_put (yp->data, &bp, yp->len, &blen);

    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;
    reply (335, "ADAT=%s", buf);

    srp_state++; return 0;
  }
  case SRP_PROT4:
  {
    unsigned char *rp; int rlen;

    bp = buf;

    /* get response */

    if (e = radix_encode (data, bp, &blen, 1)) goto decode_error;
    if (srp_get (&bp, &rp, &blen, &rlen) != 20) goto data_error;

    if (t_serververify (ts, rp))
    {
      reply (535, "User %s access denied.", srp_user);
      if (logging) syslog (LOG_NOTICE, "SRP FTP LOGIN REFUSED FROM %s, %s",
        remotehost, srp_user);
      srp_reset (); return 0;
    }

    bp = tmp; blen = 0;
    srp_put (t_serverresponse (ts), &bp, 20, &blen);

    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;
    reply (335, "ADAT=%s", buf);
    srp_state++; return 0;
  }
  case SRP_PROT5:
  {
    unsigned char *clist = cipher_getlist ();
    unsigned char *hlist = hash_getlist ();

    /* send list of ciphers and seqnum */

    t_random (seqnum, 4);

    bp = tmp; blen = 0;
    srp_put (clist, &bp, strlen (clist) + 1, &blen);
    srp_put (hlist, &bp, strlen (hlist) + 1, &blen);
    srp_put (seqnum, &bp, 4, &blen);
    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;

    reply (335, "ADAT=%s", buf);
    srp_state++; return 0;
  }
  case SRP_PROT6:
  {
    unsigned char *cp;
    int clen;
    int cid, hid;

    bp = buf;

    if (e = radix_encode (data, bp, &blen, 1)) goto decode_error;

    /* get cipher id */

    if (srp_get (&bp, &cp, &blen, &clen) != 1) goto data_error;
    cid = *cp;

    /* get hash id */

    if (srp_get (&bp, &cp, &blen, &clen) != 1) goto data_error;
    hid = *cp;

    /* get sequence number */

    if (srp_get (&bp, &cp, &blen, &clen) != 4) goto data_error;

    if (!(incrypt = krypto_new (cid, hid, skey+20, 20, NULL, 0, cp,
         KRYPTO_DECODE)))
    {
      reply (431, "Need some unavailable resource for %s security.", "SRP");
      syslog (LOG_ERR, "Couldn't create decoder for cid %d hid %d", cid, hid);
      srp_reset (); return 0;
    }

    if (!(outcrypt = krypto_new (cid, hid, skey, 20, NULL, 0, seqnum,
         KRYPTO_ENCODE)))
    {
      reply (431, "Need some unavailable resource for %s security.", "SRP");
      syslog (LOG_ERR, "Couldn't create encoder for cid %d hid %d", cid, hid);
      srp_reset (); return 0;
    }

    t_serverclose (ts); ts = NULL;

    reply (235, "SRP authentication successful");
    srp_state++; return 1;
  }

  default:

    reply (503, "Please issue AUTH SRP command first.");
    return 0;
  }

encode_error:

  reply (501, "Base 64 encoding failed: %s.", radix_error (e));
  syslog (LOG_ERR, "Couldn't encode ADAT (%s)", radix_error (e));
  srp_reset (); return 0;

decode_error:

  reply (501, "Couldn't decode ADAT (%s).", radix_error (e));
  syslog (LOG_ERR, "Couldn't decode ADAT (%s)", radix_error (e));
  srp_reset (); return 0;

data_error:

  reply (501, "Unexpected length of authentication data");
  syslog (LOG_ERR, "Unexpected length of authentication data");
  srp_reset (); return 0;

}

/*--------------------------------------------------------------+
 | srp_put: put item to send buffer                             |
 +--------------------------------------------------------------*/
int srp_put (in, out, inlen, outlen)
unsigned char *in;
unsigned char **out;
int inlen;
int *outlen;
{
  srp_uint32 net_len;

  net_len = htonl (inlen);
  memcpy (*out, &net_len, 4);

  *out += 4; *outlen += 4;

  memcpy (*out, in, inlen);

  *out += inlen; *outlen += inlen;
}

/*--------------------------------------------------------------+
 | srp_get: get item from receive buffer                        |
 +--------------------------------------------------------------*/
int srp_get (in, out, inlen, outlen)
unsigned char **in;
unsigned char **out;
int *inlen;
int *outlen;
{
  srp_uint32 net_len;

  if (*inlen < 4) return -1;

  memcpy (&net_len, *in, 4); *inlen -= 4; *in += 4;
  *outlen = ntohl (net_len);

  if (*inlen < *outlen) return -1;

  *out = *in; *inlen -= *outlen; *in += *outlen;

  return *outlen;
}

/*--------------------------------------------------------------+
 | srp_encode: encode control message                           |
 +--------------------------------------------------------------*/
int srp_encode (private, in, out, len)
  int private;
  unsigned char *in;
  unsigned char *out;
  unsigned len;
{
  if (private)
    return krypto_msg_priv (outcrypt, in, out, len);
  else
    return krypto_msg_safe (outcrypt, in, out, len);
}

/*--------------------------------------------------------------+
 | srp_decode: decode control message                           |
 +--------------------------------------------------------------*/
int srp_decode (private, in, out, len)
  int private;
  unsigned char *in;
  unsigned char *out;
  unsigned len;
{
  if (private)
    return krypto_msg_priv (incrypt, in, out, len);
  else
    return krypto_msg_safe (incrypt, in, out, len);
}

#endif /* SRP */
