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

#ifdef HAVE_SRP
#include <sys/types.h>
#include <arpa/telnet.h>
#include <stdio.h>
#include <pwd.h>

#ifdef	__STDC__
#include <stdlib.h>
#endif
#ifdef	HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "encrypt.h"
#include "auth.h"
#include "misc.h"

#include "srp.h"

extern auth_debug_mode;

#  ifdef TLS
extern int	tls_active;
extern int	tls_anon;
extern int	tls_get_client_finished(void *buf, size_t len);
extern int	tls_get_server_finished(void *buf, size_t len);

static unsigned char fin_buf[128];
#  endif /* TLS */

static unsigned char str_data[1024] = { IAC, SB, TELOPT_AUTHENTICATION, 0,
			  		AUTHTYPE_SRP, };
static unsigned char str_name[1024] = { IAC, SB, TELOPT_AUTHENTICATION,
					TELQUAL_NAME, };

static SRP * s_srp = NULL;
static cstr * s_key = NULL;
static SRP * c_srp = NULL;
static cstr * c_key = NULL;

static int waitresponse = 0;	/* Flag to indicate readiness for response */
static cstr * B = NULL;		/* Holder for B */

#define PWD_SZ 128

static char user_passwd[PWD_SZ];

#define	SRP_AUTH	0		/* Authentication data follows */
#define	SRP_REJECT	1		/* Rejected (reason might follow) */
#define	SRP_ACCEPT	2		/* Accepted */
#define SRP_CHALLENGE	3
#define SRP_RESPONSE	4

#define SRP_EXP		8
#define SRP_PARAMS	9

static int
Data(ap, type, d, c)
	Authenticator *ap;
	int type;
	void *d;
	int c;
{
	unsigned char *p = str_data + 4;
	unsigned char *cd = (unsigned char *)d;

	if (c == -1)
		c = strlen((char *)cd);

	if (auth_debug_mode) {
		printf("%s:%d: [%d] (%d)",
			str_data[3] == TELQUAL_IS ? ">>>IS" : ">>>REPLY",
			str_data[3],
			type, c);
		printd(d, c);
		printf("\r\n");
	}
	*p++ = ap->type;
	*p++ = ap->way;
	*p++ = type;
	while (c-- > 0) {
		if ((*p++ = *cd++) == IAC)
			*p++ = IAC;
	}
	*p++ = IAC;
	*p++ = SE;
	if (str_data[3] == TELQUAL_IS)
		printsub('>', &str_data[2], p - (&str_data[2]));
	return(net_write(str_data, p - str_data));
}

int
srp_init(ap, server)
	Authenticator *ap;
	int server;
{
  if (server) {
    str_data[3] = TELQUAL_REPLY;
/*
    if((tpw = t_openpw(NULL)) == NULL)
      return 0;
*/
  }
  else {
    str_data[3] = TELQUAL_IS;
  }
  waitresponse = 0;
  return 1;
}

int
srp_send(ap)
     Authenticator *ap;
{
  char ubuf[128];

  printf("[ Trying SRP ... ]\r\n");
  if (!UserNameRequested) {
    if (auth_debug_mode) {
      printf("SRP: no user name supplied\r\n");
    }
    return(0);
  }
  if(ForceUserName == 0) {
    printf("SRP Username");
    if(UserNameRequested)
      printf(" (%s)", UserNameRequested);
    printf(": ");
    ubuf[0] = '\0';
    read_string(ubuf, sizeof(ubuf) - 1, "");
    if(strlen(ubuf) > 0) {
      free(UserNameRequested);
      UserNameRequested = strdup(ubuf);
    }
  }
  if (!auth_sendname(UserNameRequested, strlen(UserNameRequested))) {
    if (auth_debug_mode)
      printf("Not enough room for user name\r\n");
    return(0);
  }
  if (!Data(ap, SRP_AUTH, (void *)NULL, 0)) {
    return(0);
  }
  return(1);
}

void
encode_length(data, num)
     unsigned char * data;
     int num;
{
  *data = (num >> 8) & 0xff;
  *++data = num & 0xff;
}

int
decode_length(data)
     unsigned char * data;
{
  return (((int) *data & 0xff) << 8) | (*(data + 1) & 0xff);
}

void
srp_is(ap, data, cnt)
	Authenticator *ap;
	unsigned char *data;
	int cnt;
{
  char * pbuf;
  char * ptr;
  /**
  struct t_passwd * pass;
  */
  cstr * resp;
/*
  FILE * passfp = NULL;
  FILE * conffp = NULL;
*/
#ifdef	ENCRYPTION
  Session_Key skey;
#endif
#ifdef  TLS
  int flen;
#endif
  int modlen, genlen;
  unsigned char type_check[2];

  if(cnt-- < 1)
    return;
  switch(*data++) {
  case SRP_AUTH:
    /* Send parameters back to client */
    if(s_srp != NULL) {
      SRP_free(s_srp);
      s_srp = NULL;
    }
    if(!UserNameRequested) {
      if (auth_debug_mode)
	printf("No username available\r\n");
      Data(ap, SRP_REJECT, (void *) "No username supplied", -1);
      break;
    }
/*
    if(tpw == NULL) {
      if((tpw = t_openpw(NULL)) == NULL) {
	if (auth_debug_mode)
	  printf("Unable to open password file\r\n");
	Data(ap, SRP_REJECT, (void *) "No password file", -1);
	break;
      }
    }
    if(tconf == NULL) {
      if((tconf = t_openconf(NULL)) == NULL) {
	if (auth_debug_mode)
	  printf("Unable to open configuration file\r\n");
	Data(ap, SRP_REJECT, (void *) "No configuration file", -1);
	break;
      }
    }
    ts = t_serveropen(UserNameRequested, tpw, tconf);
*/
    /*
    ts = t_serveropen(UserNameRequested);
    */
    s_srp = SRP_new(SRP_RFC2945_server_method());
    if(s_srp == NULL) {
      if (auth_debug_mode)
	printf("Error initializing SRP server\r\n");
      Data(ap, SRP_REJECT, (void *) "SRP server init failed", -1);
      break;
    }
    /**
    pass = gettpnam(UserNameRequested);
    */
/*
    t_closepw(tpw);
    if(passfp)
      fclose(passfp);
    tpw = NULL;
    t_closeconf(tconf);
    if(conffp)
      fclose(conffp);
    tconf = NULL;
*/

    SRP_set_server_lookup(s_srp, SRP_SERVER_system_lookup());
    if(SRP_set_username(s_srp, UserNameRequested) != SRP_SUCCESS) {
      if (auth_debug_mode)
	printf("User %s not found\r\n", UserNameRequested);
      Data(ap, SRP_REJECT, (void *) "Password not set", -1);
      break;
    }
    /*
    if(pass == NULL) {
      if (auth_debug_mode)
	printf("User %s not found\r\n", UserNameRequested);
      Data(ap, SRP_REJECT, (void *) "Password not set", -1);
      break;
    }
    if(SRP_set_username(s_srp, UserNameRequested) != SRP_SUCCESS ||
       SRP_set_params(s_srp, pass->tc.modulus.data, pass->tc.modulus.len,
		      pass->tc.generator.data, pass->tc.generator.len,
		      pass->tp.salt.data, pass->tp.salt.len) != SRP_SUCCESS ||
       SRP_set_authenticator(s_srp, pass->tp.password.data,
			     pass->tp.password.len) != SRP_SUCCESS) {
      if (auth_debug_mode)
	printf("Error initializing SRP parameters\r\n");
      Data(ap, SRP_REJECT, (void *) "SRP parameter init failed", -1);
      break;
    }
    */

    modlen = BigIntegerByteLen(s_srp->modulus);
    genlen = BigIntegerByteLen(s_srp->generator);
    pbuf = (char *)malloc(modlen + genlen + s_srp->salt->length + 7);
    ptr = pbuf;

    encode_length(ptr, modlen);
    ptr += 2;
    BigIntegerToBytes(s_srp->modulus, ptr, modlen);
    ptr += modlen;

    encode_length(ptr, genlen);
    ptr += 2;
    BigIntegerToBytes(s_srp->generator, ptr, genlen);
    ptr += genlen;

    encode_length(ptr, s_srp->salt->length);
    ptr += 2;
    memcpy(ptr, s_srp->salt->data, s_srp->salt->length);
    ptr += s_srp->salt->length;

    Data(ap, SRP_PARAMS, pbuf, ptr - pbuf);  /* Ideally, this is flushed */
    free(pbuf);

    if(SRP_gen_pub(s_srp, &B) != SRP_SUCCESS) {
      if (auth_debug_mode)
	printf("Error generating SRP public value\r\n");
      Data(ap, SRP_REJECT, (void *) "SRP_gen_pub failed", -1);
      break;
    }

    break;

  case SRP_EXP:
    /* Client is sending A to us.  Compute challenge and expected response. */
    if(s_srp == NULL || B == NULL) {
      if (auth_debug_mode)
	printf("Protocol error: SRP_EXP unexpected\r\n");
      Data(ap, SRP_REJECT, (void *) "Protocol error: unexpected EXP", -1);
      break;
    }

    /* Wait until now to send B, since it contains the key to "u" */
    Data(ap, SRP_CHALLENGE, B->data, B->length);
    cstr_free(B);
    B = NULL;

    if ( ap->way & AUTH_ENCRYPT_MASK ) {
      type_check[0] = (unsigned char) ap->type;
      type_check[1] = (unsigned char) ap->way;
      SRP_add_ex_data(s_srp, type_check, 2);
    }
 
#ifdef TLS
    /*
     * If ENCRYPT_START_TLS is set, authenticate the TLS Finished
     * messages as well.  This prevents MITM attacks, and is especially
     * useful when anonymous TLS is used.
     */
    if(tls_active && (ap->way & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_START_TLS) {
      flen = tls_get_client_finished(fin_buf, sizeof(fin_buf));
      SRP_add_ex_data(s_srp, fin_buf, flen);
      flen = tls_get_server_finished(fin_buf, sizeof(fin_buf));
      SRP_add_ex_data(s_srp, fin_buf, flen);
    }
#endif /* TLS */

    if(SRP_compute_key(s_srp, &s_key, data, cnt) != SRP_SUCCESS) {
      if (auth_debug_mode)
	printf("Security alert: Trivial session key attempted\r\n");
      Data(ap, SRP_REJECT, (void *) "Trivial session key detected", -1);
      break;
    }

    waitresponse = 1;
    break;

  case SRP_RESPONSE:
    /* Got the response; see if it's correct */
    if(s_srp == NULL || !waitresponse) {
      if (auth_debug_mode)
	printf("Protocol error: SRP_RESPONSE unexpected\r\n");
      Data(ap, SRP_REJECT, (void *) "Protocol error: unexpected RESPONSE", -1);
      break;
    }

    if(cnt < RFC2945_RESP_LEN) {
      if (auth_debug_mode)
	printf("Protocol error: malformed response\r\n");
      Data(ap, SRP_REJECT, (void *) "Protocol error: malformed response", -1);
      break;
    }

    if(SRP_verify(s_srp, data, cnt) == SRP_SUCCESS) {
      resp = cstr_new();
      if(SRP_respond(s_srp, &resp) != SRP_SUCCESS) {
	if (auth_debug_mode)
	  printf("Error computing response\r\n");
	Data(ap, SRP_REJECT, (void *) "Error computing response", -1);
	break;
      }
      Data(ap, SRP_ACCEPT, resp->data, resp->length);
      cstr_free(resp);

#ifdef	ENCRYPTION
      skey.type = SK_GENERIC;
      skey.length = s_key->length;
      skey.data = s_key->data;
      encrypt_session_key(&skey, 1);
      cstr_clear_free(s_key);
      s_key = NULL;
#endif

      auth_finished(ap, AUTH_VALID);
    }
    else {
      Data(ap, SRP_REJECT, (void *) "Login incorrect", -1);
      auth_finished(ap, AUTH_REJECT);
    }

    break;

  default:
    if (auth_debug_mode)
      printf("Unknown SRP option %d\r\n", data[-1]);
    Data(ap, SRP_REJECT, (void *) "Unknown option received", -1);
    break;
  }
}

void
srp_reply(ap, data, cnt)
	Authenticator *ap;
	unsigned char *data;
	int cnt;
{
  unsigned char * ndata;
  int nlen;
  unsigned char * gdata;
  int glen;
  unsigned char * sdata;
  int slen;

  cstr * resp;
  cstr * A;

  int pflag;
#ifdef	ENCRYPTION
  Session_Key skey;
#endif
#ifdef  TLS
  int flen;
#endif
  unsigned char type_check[2];

  if(cnt-- < 1)
    return;
  switch(*data++) {
  case SRP_REJECT:
    if (cnt > 0) {
      printf("[ SRP refuses authentication for '%s' (%.*s) ]\r\n",
	     UserNameRequested, cnt, data);
    } else
      printf("[ SRP refuses authentication for '%s' ]\r\n", UserNameRequested);
    auth_send_retry();
    break;
  case SRP_ACCEPT:
    if(c_srp == NULL || cnt < RFC2945_RESP_LEN || !waitresponse) {
      if (auth_debug_mode)
	printf("Protocol error\r\n");
      break;
    }

    if(SRP_verify(c_srp, data, cnt) == SRP_SUCCESS) {
      printf("[ SRP authentication successful ]\r\n");
#ifdef TLS
      if(tls_active &&
	 (ap->way & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_START_TLS) {
	printf("[ TLS session parameters verified by SRP ]\r\n");
	tls_anon = 0;	/* We're sure the key is good now */
      }
#endif

#ifdef	ENCRYPTION
      skey.type = SK_GENERIC;
      skey.length = c_key->length;
      skey.data = c_key->data;
      encrypt_session_key(&skey, 0);
      cstr_clear_free(c_key);
      c_key = NULL;
#endif

      auth_finished(ap, AUTH_VALID);
    }
    else {
      printf("[ Error: SRP server authentication failed ]\r\n");
      auth_send_retry();
      break;
    }
    SRP_free(c_srp);
    c_srp = NULL;
    break;
  case SRP_PARAMS:
    if(!UserNameRequested) {
      if (auth_debug_mode)
	printf("No username available\r\n");
      break;
    }

    nlen = decode_length(data);
    data += 2;
    cnt -= 2;
    if(nlen > cnt) {
      if (auth_debug_mode)
	printf("n too long\r\n");
      break;
    }
    ndata = data;
    data += nlen;
    cnt -= nlen;

    printf("[ Using %d-bit modulus for '%s' ]\r\n", 8 * nlen, UserNameRequested);

    glen = decode_length(data);
    data += 2;
    cnt -= 2;
    if(glen > cnt) {
      if (auth_debug_mode)
	printf("g too long\r\n");
      break;
    }
    gdata = data;
    data += glen;
    cnt -= glen;

    slen = decode_length(data);
    data += 2;
    cnt -= 2;
    if(slen > cnt) {
      if (auth_debug_mode)
	printf("salt too long\r\n");
      break;
    }
    sdata = data;
    data += slen;
    cnt -= slen;

    c_srp = SRP_new(SRP_RFC2945_client_method());
    if(c_srp == NULL ||
       SRP_set_username(c_srp, UserNameRequested) != SRP_SUCCESS ||
       SRP_set_params(c_srp, ndata, nlen, gdata, glen, sdata, slen) !=
       SRP_SUCCESS) {
      printf("[ Parameter initialization error ]\r\n");
      auth_send_retry();
      break;
    }

    A = cstr_new();
    if(SRP_gen_pub(c_srp, &A) != SRP_SUCCESS) {
      printf("[ Error generating key exchange ]\r\n");
      auth_send_retry();
      break;
    }

    Data(ap, SRP_EXP, A->data, A->length);
    cstr_free(A);

    local_des_read_pw_string(user_passwd, sizeof(user_passwd) - 1, "SRP Password: ", 0);
    if(SRP_set_auth_password(c_srp, user_passwd) != SRP_SUCCESS) {
      printf("[ Error setting client password ]\r\n");
      auth_send_retry();
    }
    memset(user_passwd, 0, sizeof(user_passwd));

    break;

  case SRP_CHALLENGE:
    if(c_srp == NULL) {
      if (auth_debug_mode)
	printf("Protocol error\r\n");
      break;
    }
      
    if ( ap->way & AUTH_ENCRYPT_MASK ) {
      type_check[0] = (unsigned char) ap->type;
      type_check[1] = (unsigned char) ap->way;
      SRP_add_ex_data(c_srp, type_check, 2);
    }

#ifdef TLS
    if(tls_active && (ap->way & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_START_TLS) {
      flen = tls_get_client_finished(fin_buf, sizeof(fin_buf));
      if(flen <= 0) {
	printf("ERROR: no TLS client Finished message\r\n");
	auth_send_retry();
	break;
      }
      SRP_add_ex_data(c_srp, fin_buf, flen);
      flen = tls_get_server_finished(fin_buf, sizeof(fin_buf));
      if(flen <= 0) {
	printf("ERROR: no TLS server Finished message\r\n");
	auth_send_retry();
	break;
      }
      SRP_add_ex_data(c_srp, fin_buf, flen);
    }
#endif /* TLS */

    if(SRP_compute_key(c_srp, &c_key, data, cnt) != SRP_SUCCESS) {
      printf("ERROR: unable to compute client key\r\n");
      auth_send_retry();
      break;
    }

    resp = cstr_new();
    if(SRP_respond(c_srp, &resp) != SRP_SUCCESS) {
      printf("ERROR: unable to compute client response\r\n");
      auth_send_retry();
      break;
    }
    Data(ap, SRP_RESPONSE, resp->data, resp->length);
    cstr_free(resp);
    waitresponse = 1;

    break;

  default:
    if(auth_debug_mode)
      printf("Unknown reply option\r\n");
    break;
  }
}

int
srp_status(ap, name, level)
	Authenticator *ap;
	char *name;
	int level;
{
	if (level < AUTH_USER)
	  return(level);

	if (UserNameRequested) {
	  strcpy(name, UserNameRequested);
	  return AUTH_VALID;
	}
	return AUTH_USER;
}

#define	BUMP(buf, len)		while (*(buf)) {++(buf), --(len);}
#define	ADDC(buf, len, c)	if ((len) > 0) {*(buf)++ = (c); --(len);}

	void
srp_printsub(data, cnt, buf, buflen)
	unsigned char *data, *buf;
	int cnt, buflen;
{
	char lbuf[32];
	register int i;

	buf[buflen-1] = '\0';		/* make sure its NULL terminated */
	buflen -= 1;

	switch(data[3]) {
	case SRP_REJECT:		/* Rejected (reason might follow) */
		strncpy((char *)buf, " REJECT ", buflen);

	common:
		BUMP(buf, buflen);
		if (cnt <= 4)
			break;
		ADDC(buf, buflen, '"');
		for (i = 4; i < cnt; i++)
			ADDC(buf, buflen, data[i]);
		ADDC(buf, buflen, '"');
		ADDC(buf, buflen, '\0');
		break;

	case SRP_ACCEPT:		/* Accepted (data might follow) */
		strncpy((char *)buf, " ACCEPT", buflen);
		goto common2;

	case SRP_AUTH:			/* Authentication data follows */
		strncpy((char *)buf, " AUTH", buflen);
		goto common2;

	case SRP_CHALLENGE:
		strncpy((char *)buf, " CHALLENGE", buflen);
		goto common2;

	case SRP_RESPONSE:
		strncpy((char *)buf, " RESPONSE", buflen);
		goto common2;

	case SRP_PARAMS:
		strncpy((char *)buf, " PARAMS", buflen);
		goto common2;

	case SRP_EXP:
		strncpy((char *)buf, " EXP", buflen);
		goto common2;

	default:
		sprintf(lbuf, " %d (unknown)", data[3]);
		strncpy((char *)buf, lbuf, buflen);
	common2:
		BUMP(buf, buflen);
		for (i = 4; i < cnt; i++) {
			sprintf(lbuf, " %d", data[i]);
			strncpy((char *)buf, lbuf, buflen);
			BUMP(buf, buflen);
		}
		break;
	}
}

#endif
