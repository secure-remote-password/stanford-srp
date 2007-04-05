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
#undef SRP /* unfortunately this clashes with libsrp/srp.h */

#include <stdio.h>
#include <string.h>
#include <arpa/ftp.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "pwd.h"
#include "t_pwd.h"
#include "srp.h"
#include "krypto.h"

#define SRP_PROT_VERSION 	1

char srp_user[BUFSIZ];
char *srp_pass;
char *srp_acct;

unsigned char srp_pref_cipher = 0;
unsigned char srp_pref_hash = 0;

SRP *ctx = NULL;
static cstr *skey = NULL;
static krypto_context *incrypt = NULL;
static krypto_context *outcrypt = NULL;

extern char *reply_parse;
extern char *mygetpass ();
extern char *auth_type;
extern int verbose;
extern int level;
extern int radix_encode ();
extern int command ();
extern int setprivate ();

#if (SIZEOF_SHORT == 4)
typedef unsigned short srp_uint32;
#elif (SIZEOF_INT == 4)
typedef unsigned int srp_uint32;
#elif (SIZEOF_LONG == 4)
typedef unsigned long srp_uint32;
#endif

/*--------------------------------------------------------------+
 | srp_selcipher: select cipher                                 |
 +--------------------------------------------------------------*/
int srp_selcipher (cname)
  char *cname;
{
  cipher_desc *cd;

  if (!(cd = cipher_getdescbyname (cname)))
  {
    int i;
    unsigned char *list = cipher_getlist ();

    fprintf (stderr, "ftp: supported ciphers:\n\n");
    for (i = 0; i < strlen (list); i++)
      fprintf (stderr, "	%s\n", cipher_getdescbyid(list[i])->name);
    fprintf (stderr, "\n");
    return -1;
  }

  srp_pref_cipher = cd->id;
  return 0;
}

/*--------------------------------------------------------------+
 | srp_selhash: select hash                                     |
 +--------------------------------------------------------------*/
int srp_selhash (hname)
  char *hname;
{
  hash_desc *hd;

  if (!(hd = hash_getdescbyname (hname)))
  {
    int i;
    unsigned char *list = hash_getlist ();

    fprintf (stderr, "ftp: supported hash functions:\n\n");
    for (i = 0; i < strlen (list); i++)
      fprintf (stderr, "	%s\n", hash_getdescbyid(list[i])->name);
    fprintf (stderr, "\n");
    return -1;
  }

  srp_pref_hash = hd->id;
  return 0;
}

/*--------------------------------------------------------------+
 | srp_userpass: get username and password                      |
 +--------------------------------------------------------------*/
int srp_userpass (host)
  char *host;
{
  char tmp[BUFSIZ];
  char *user, *getenv(), *getlogin(), *mygetpass();

  user = NULL;
  ruserpass (host, &user, &srp_pass, &srp_acct);

  while (user == NULL)
  {
    char *myname;

    myname = getenv("LOGNAME");
    if (myname == NULL)
      myname = getenv("USER");
    if (myname == NULL)
      myname = getlogin();
    if (myname == NULL)
    {
      struct passwd *pp = getpwuid(getuid());
      if (pp != NULL) myname = pp->pw_name;
    }

    if (myname) printf("Name (%s:%s): ", host, myname);
    else printf("Name (%s): ", host);

    tmp[0] = '\0';
    (void) fgets(tmp, sizeof(tmp) - 1, stdin);
    if (strlen(tmp) > 0) tmp[strlen(tmp)-1] = '\0';
    if ((*tmp == '\0')) user = myname;
    else user = tmp;
  }

  strcpy (srp_user, user);
}

/*--------------------------------------------------------------+
 | srp_reset: reset srp information                             |
 +--------------------------------------------------------------*/
int srp_reset ()
{
  if (ctx)
  { SRP_free(ctx); ctx = NULL; }
  if (incrypt)
  { krypto_delete (incrypt); incrypt = NULL; }
  if (outcrypt)
  { krypto_delete (outcrypt); outcrypt = NULL; }
}

/*--------------------------------------------------------------+
 | srp_auth: perform srp authentication                         |
 +--------------------------------------------------------------*/
int srp_auth (host, user, pass)
char *host;
char *user;
char *pass;
{
  cstr *wp = NULL;
  cstr *resp = NULL;
  struct t_num N;
  struct t_num g;
  struct t_num s;
  struct t_num yp;
  unsigned char buf[FTP_BUFSIZ];
  unsigned char tmp[FTP_BUFSIZ];
  unsigned char *bp, *cp;
  int n, e, clen, blen, i;
  int overbose = verbose;
  unsigned char cid = 0;
  unsigned char hid = 0;

  srp_pass = srp_acct = 0;
  verbose = 0;

  n = command ("AUTH %s", "SRP");

  if (n == CONTINUE)
  {
    unsigned char vers[4];
    memset (vers, 0, 4);
    vers[3] = SRP_PROT_VERSION;

    if (overbose) printf ("%s accepted as authentication type.\n", "SRP");

    /* send protocol version */

    bp = tmp; blen = 0;
    srp_put (vers, &bp, 4, &blen);
    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;

    reply_parse = "ADAT=";
    n = command ("ADAT %s", buf);
  }

  if (n == CONTINUE)
  {
    /* get protocol version */

    bp = buf;

    if (!reply_parse) goto data_error;
    if (e = radix_encode (reply_parse, bp, &blen, 1)) goto decode_error;
    if (srp_get (&bp, &cp, &blen, &clen) != 4) goto data_error;

    /* get username and password if necessary */

    if (host) srp_userpass (host);
    else { strcpy (srp_user, user); srp_pass = pass; }

    /* send username */

    bp = tmp; blen = 0;
    srp_put (srp_user, &bp, strlen (srp_user), &blen);
    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;

    reply_parse = "ADAT=";
    n = command ("ADAT %s", buf);
  }
  
  if (n == CONTINUE)
  {
    bp = buf;

    if (!reply_parse) goto data_error;
    if (e = radix_encode (reply_parse, bp, &blen, 1)) goto decode_error;

    /* get N, g and s */

    if (srp_get (&bp, &(N.data), &blen, &(N.len)) < 0) goto data_error;
    if (srp_get (&bp, &(g.data), &blen, &(g.len)) < 0) goto data_error;
    if (srp_get (&bp, &(s.data), &blen, &(s.len)) < 0) goto data_error;

    if ((ctx = SRP_new(SRP_RFC2945_client_method())) == NULL)
    {
      fprintf (stderr, "Unable to initialize SRP context.\n");
      goto bad;
    }

    if (SRP_set_username(ctx, srp_user) != SRP_SUCCESS)
    {
      fprintf (stderr, "Error initializing SRP username.\n");
      goto bad;
    }

    if (SRP_set_params(ctx, N.data, N.len, g.data, g.len, s.data, s.len) != SRP_SUCCESS)
    {
      fprintf (stderr, "Error initializing SRP parameters.\n");
      goto bad;
    }

    if(SRP_gen_pub(ctx, &wp) != SRP_SUCCESS)
    {
      fprintf (stderr, "Error generating SRP public value.\n");
      goto bad;
    }

    /* send wp */

    bp = tmp; blen = 0;
    srp_put (wp->data, &bp, wp->length, &blen);
    cstr_free(wp);
    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;

    reply_parse = "ADAT=";
    n = command ("ADAT %s", buf);
  }

  if (n == CONTINUE)
  {
    bp = buf;

    /* get yp */

    if (!reply_parse) goto data_error;
    if (e = radix_encode (reply_parse, bp, &blen, 1)) goto decode_error;
    if (srp_get (&bp, &(yp.data), &blen, &(yp.len)) < 0) goto data_error;

    if (!srp_pass) srp_pass = mygetpass ("SRP Password:");
    if(SRP_set_auth_password(ctx, srp_pass) != SRP_SUCCESS)
    {
      fprintf (stderr, "Error setting SRP password.\n");
      goto bad;
    }

    memset (srp_pass, 0, strlen (srp_pass));

    if(SRP_compute_key(ctx, &skey, yp.data, yp.len) != SRP_SUCCESS)
    {
      fprintf (stderr, "Error computing SRP session key.\n");
      goto bad;
    }

    /* send response */

    bp = tmp; blen = 0;
    if(SRP_respond(ctx, &resp) != SRP_SUCCESS)
    {
      fprintf (stderr, "Error computing SRP client response.\n");
      goto bad;
    }
    srp_put (resp->data, &bp, resp->length, &blen);
    cstr_free(resp);
    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;

    reply_parse = "ADAT=";
    n = command ("ADAT %s", buf); 
  }

  if (n == CONTINUE)
  {
    bp = buf;

    /* get response */

    if (!reply_parse) goto data_error;
    if (e = radix_encode (reply_parse, bp, &blen, 1)) goto encode_error;
    if (srp_get (&bp, &cp, &blen, &clen) != 20) goto data_error;

    if (SRP_verify(ctx, cp, 20) != SRP_SUCCESS)
    {
      fprintf (stderr, "WARNING: bad response to client challenge.\n");
      goto bad;
    }

    /* send nothing */

    bp = tmp; blen = 0;
    srp_put ("\0", &bp, 1, &blen);
    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;

    reply_parse = "ADAT=";
    n = command ("ADAT %s", buf); 
  }

  if (n == CONTINUE)
  {
    unsigned char seqnum[4];
    unsigned char *clist;
    unsigned char *hlist;
    unsigned char *p1;
    int clist_len, hlist_len;

    bp = buf;

    /* get cipher list, hash list, seqnum */

    if (!reply_parse) goto data_error;
    if (e = radix_encode (reply_parse, bp, &blen, 1)) goto encode_error;
    if (srp_get (&bp, &clist, &blen, &clist_len) < 0) goto data_error;
    if (srp_get (&bp, &hlist, &blen, &hlist_len) < 0) goto data_error;
    if (srp_get (&bp, &cp, &blen, &clen) != 4) goto data_error;
    memcpy (seqnum, cp, 4);

    /* choose cipher */

    if (cipher_supported (clist, srp_pref_cipher))
      cid = srp_pref_cipher;

    /*
    if (!cid && cipher_supported (clist, SRP_DEFAULT_CIPHER))
      cid = SRP_DEFAULT_CIPHER;
    */

    if (!cid)
    {
      unsigned char *loclist = cipher_getlist ();
      for (i = 0; i < strlen (loclist); i++)
        if (cipher_supported (clist, loclist[i])) { cid = loclist[i]; break; }
    }

    if (!cid)
    { fprintf (stderr, "Unable to agree on cipher.\n"); goto bad; }

    /* choose hash */

    if (srp_pref_hash && hash_supported (hlist, srp_pref_hash))
      hid = srp_pref_hash;

    /*
    if (!hid && hash_supported (hlist, SRP_DEFAULT_HASH))
      hid = SRP_DEFAULT_HASH;
    */

    if (!hid)
    {
      unsigned char *loclist = hash_getlist ();
      for (i = 0; i < strlen (loclist); i++)
        if (hash_supported (hlist, loclist[i])) { hid = loclist[i]; break; }
    }

    if (!hid)
    { fprintf (stderr, "Unable to agree on hash.\n"); goto bad; }

    /* set incrypt */

    if (!(incrypt = krypto_new (cid, hid, skey->data, 20, NULL, 0, seqnum,
         KRYPTO_DECODE)))
      goto bad;

    /* generate random number for outkey and outseqnum */

    t_random (seqnum, 4);

    /* send cid, hid, outkey, outseqnum */
    
    bp = tmp; blen = 0;
    srp_put (&cid, &bp, 1, &blen);
    srp_put (&hid, &bp, 1, &blen);
    srp_put (seqnum, &bp, 4, &blen);
    if (e = radix_encode (tmp, buf, &blen, 0)) goto encode_error;

    reply_parse = "ADAT=";
    n = command ("ADAT %s", buf); 

    /* set outcrypt */

    if (!(outcrypt = krypto_new (cid, hid, skey->data+20, 20, NULL, 0, seqnum,
         KRYPTO_ENCODE)))
      goto bad;

    SRP_free(ctx); ctx = NULL;
  }

  if (n != COMPLETE) goto bad;

  if (overbose) printf ("SRP authentication succeeded.\n");
  if (overbose) printf ("Using cipher %s and hash function %s.\n",
    cipher_getdescbyid(cid)->name, hash_getdescbyid(hid)->name);

  verbose = overbose;
  reply_parse = NULL;
  auth_type = "SRP";

#ifndef NOENCRYPTION
  setprivate ();
#endif

  return 1;

encode_error:

  fprintf (stderr, "Base 64 encoding failed: %s.\n", radix_error (e));
  goto bad;

decode_error:

  fprintf (stderr, "Base 64 decoding failed: %s.\n", radix_error (e));
  goto bad;

data_error:

  fprintf (stderr, "Unable to unmarshal authentication data.\n");
  goto bad;

bad:

  fprintf (stderr, "SRP authentication failed, trying regular login.\n");
  verbose = overbose;
  reply_parse = NULL;
  return 0; 

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
