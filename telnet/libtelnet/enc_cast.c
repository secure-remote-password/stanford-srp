/*-
 * Copyright (c) 1991, 1993
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

#ifdef	ENCRYPTION
# ifdef	AUTHENTICATION
#  if defined(CAST_ENCRYPTION) || defined(CAST_EXPORT_ENCRYPTION)
#include <arpa/telnet.h>
#include <stdio.h>
#ifdef	__STDC__
#include <stdlib.h>
#endif

#include "cast.h"

#include "encrypt.h"
#include "key-proto.h"
#include "misc-proto.h"

extern encrypt_debug_mode;

#define CFB_40	0
#define OFB_40	1
#ifdef CAST_EXPORT_ENCRYPTION
#define FB_CNT	2
#else
#define	CFB_128	2
#define	OFB_128	3
#define FB_CNT	4
#endif

#define	NO_SEND_IV	1
#define	NO_RECV_IV	2
#define	NO_KEYID	4
#define	IN_PROGRESS	(NO_SEND_IV|NO_RECV_IV|NO_KEYID)
#define	SUCCESS		0
#define	FAILED		-1


struct fb {
	Block temp_feed;
	unsigned char fb_feed[64];
	int key_isset;
	int need_start;
	int state[2];
	struct stinfo {
		Block		str_output;
		Block		str_feed;
		Block		str_iv;
		CastKeySched	str_sched;
		int		str_index;
	} streams[2];
};

static struct fb fb[FB_CNT];

#define	FB64_IV		1
#define	FB64_IV_OK	2
#define	FB64_IV_BAD	3


static void cast_fb64_stream_iv P((Block, struct stinfo *));
static void cast_fb64_init P((struct fb *));
static int cast_fb64_start P((struct fb *, int, int));
static int cast_fb64_is P((unsigned char *, int, struct fb *));
static int cast_fb64_reply P((unsigned char *, int, struct fb *));
static int cast_fb64_session P((Session_Key *, int, struct fb *, int));
static void cast_fb64_stream_key P((Block, struct stinfo *, int));
static int cast_fb64_keyid P((int, unsigned char *, int *, struct fb *));
static void _cast_cfb64_encrypt P((unsigned char *, int, struct stinfo *));
static int _cast_cfb64_decrypt P((int, struct stinfo *));
static void _cast_ofb64_encrypt P((unsigned char *, int, struct stinfo *));
static int _cast_ofb64_decrypt P((int, struct stinfo *));

#ifndef CAST_EXPORT_ENCRYPTION
void
cast_cfb64_init(server)
	int server;
{
	cast_fb64_init(&fb[CFB_128]);
	fb[CFB_128].fb_feed[4] = ENCTYPE_CAST128_CFB64;
}

void
cast_ofb64_init(server)
	int server;
{
	cast_fb64_init(&fb[OFB_128]);
	fb[OFB_128].fb_feed[4] = ENCTYPE_CAST128_OFB64;
}
#endif

void
castexp_cfb64_init(server)
	int server;
{
	cast_fb64_init(&fb[CFB_40]);
	fb[CFB_40].fb_feed[4] = ENCTYPE_CAST5_40_CFB64;
}

void
castexp_ofb64_init(server)
	int server;
{
	cast_fb64_init(&fb[OFB_40]);
	fb[OFB_40].fb_feed[4] = ENCTYPE_CAST5_40_OFB64;
}

static void
cast_fb64_init(fbp)
	register struct fb *fbp;
{
	memset((void *)fbp, 0, sizeof(*fbp));
	fbp->key_isset = 0;
	fbp->state[0] = fbp->state[1] = FAILED;
	fbp->fb_feed[0] = IAC;
	fbp->fb_feed[1] = SB;
	fbp->fb_feed[2] = TELOPT_ENCRYPT;
	fbp->fb_feed[3] = ENCRYPT_IS;
}

/*
 * Returns:
 *	-1: some error.  Negotiation is done, encryption not ready.
 *	 0: Successful, initial negotiation all done.
 *	 1: successful, negotiation not done yet.
 *	 2: Not yet.  Other things (like getting the key from
 *	    Kerberos) have to happen before we can continue.
 */
#ifndef CAST_EXPORT_ENCRYPTION
int
cast_cfb64_start(dir, server)
	int dir;
	int server;
{
	return(cast_fb64_start(&fb[CFB_128], dir, server));
}

int
cast_ofb64_start(dir, server)
	int dir;
	int server;
{
	return(cast_fb64_start(&fb[OFB_128], dir, server));
}
#endif

int
castexp_cfb64_start(dir, server)
	int dir;
	int server;
{
	return(cast_fb64_start(&fb[CFB_40], dir, server));
}

int
castexp_ofb64_start(dir, server)
	int dir;
	int server;
{
	return(cast_fb64_start(&fb[OFB_40], dir, server));
}

static int
cast_fb64_start(fbp, dir, server)
	struct fb *fbp;
	int dir;
	int server;
{
	Block b;
	int x;
	unsigned char *p;
	register int state;

	switch (dir) {
	case DIR_DECRYPT:
		/*
		 * This is simply a request to have the other side
		 * start output (our input).  He will negotiate an
		 * IV so we need not look for it.
		 */
		state = fbp->state[dir-1];
		if (state == FAILED)
			state = IN_PROGRESS;
		break;

	case DIR_ENCRYPT:
		state = fbp->state[dir-1];
		if (state == FAILED)
			state = IN_PROGRESS;
		else if ((state & NO_SEND_IV) == 0)
			break;

		if (!fbp->key_isset) {
			fbp->need_start = 1;
			break;
		}
		state &= ~NO_SEND_IV;
		state |= NO_RECV_IV;
		if (encrypt_debug_mode)
			printf("Creating new feed\r\n");
		/*
		 * Create a random feed and send it over.
		 */
		cast_ecb_encrypt(fbp->temp_feed, fbp->temp_feed,
				 &fbp->streams[dir-1].str_sched, 0);

		p = fbp->fb_feed + 3;
		*p++ = ENCRYPT_IS;
		p++;
		*p++ = FB64_IV;
		for (x = 0; x < sizeof(Block); ++x) {
			if ((*p++ = fbp->temp_feed[x]) == IAC)
				*p++ = IAC;
		}
		*p++ = IAC;
		*p++ = SE;
		printsub('>', &fbp->fb_feed[2], p - &fbp->fb_feed[2]);
		net_write(fbp->fb_feed, p - fbp->fb_feed);
		break;
	default:
		return(FAILED);
	}
	return(fbp->state[dir-1] = state);
}

/*
 * Returns:
 *	-1: some error.  Negotiation is done, encryption not ready.
 *	 0: Successful, initial negotiation all done.
 *	 1: successful, negotiation not done yet.
 */
#ifndef CAST_EXPORT_ENCRYPTION
int
cast_cfb64_is(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_is(data, cnt, &fb[CFB_128]));
}

int
cast_ofb64_is(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_is(data, cnt, &fb[OFB_128]));
}
#endif

int
castexp_cfb64_is(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_is(data, cnt, &fb[CFB_40]));
}

int
castexp_ofb64_is(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_is(data, cnt, &fb[OFB_40]));
}

static int
cast_fb64_is(data, cnt, fbp)
	unsigned char *data;
	int cnt;
	struct fb *fbp;
{
	int x;
	unsigned char *p;
	Block b;
	register int state = fbp->state[DIR_DECRYPT-1];

	if (cnt-- < 1)
		goto failure;

	switch (*data++) {
	case FB64_IV:
		if (cnt != sizeof(Block)) {
			if (encrypt_debug_mode)
				printf("FB64: initial vector failed on size\r\n");
			state = FAILED;
			goto failure;
		}

		if (encrypt_debug_mode)
			printf("FB64: initial vector received\r\n");

		if (encrypt_debug_mode)
			printf("Initializing Decrypt stream\r\n");

		cast_fb64_stream_iv((void *)data, &fbp->streams[DIR_DECRYPT-1]);

		p = fbp->fb_feed + 3;
		*p++ = ENCRYPT_REPLY;
		p++;
		*p++ = FB64_IV_OK;
		*p++ = IAC;
		*p++ = SE;
		printsub('>', &fbp->fb_feed[2], p - &fbp->fb_feed[2]);
		net_write(fbp->fb_feed, p - fbp->fb_feed);

		state = fbp->state[DIR_DECRYPT-1] = IN_PROGRESS;
		break;

	default:
		if (encrypt_debug_mode) {
			printf("Unknown option type: %d\r\n", *(data-1));
			printd(data, cnt);
			printf("\r\n");
		}
		/* FALL THROUGH */
	failure:
		/*
		 * We failed.  Send an FB64_IV_BAD option
		 * to the other side so it will know that
		 * things failed.
		 */
		p = fbp->fb_feed + 3;
		*p++ = ENCRYPT_REPLY;
		p++;
		*p++ = FB64_IV_BAD;
		*p++ = IAC;
		*p++ = SE;
		printsub('>', &fbp->fb_feed[2], p - &fbp->fb_feed[2]);
		net_write(fbp->fb_feed, p - fbp->fb_feed);

		break;
	}
	return(fbp->state[DIR_DECRYPT-1] = state);
}

/*
 * Returns:
 *	-1: some error.  Negotiation is done, encryption not ready.
 *	 0: Successful, initial negotiation all done.
 *	 1: successful, negotiation not done yet.
 */
#ifndef CAST_EXPORT_ENCRYPTION
int
cast_cfb64_reply(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_reply(data, cnt, &fb[CFB_128]));
}

int
cast_ofb64_reply(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_reply(data, cnt, &fb[OFB_128]));
}
#endif

int
castexp_cfb64_reply(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_reply(data, cnt, &fb[CFB_40]));
}

int
castexp_ofb64_reply(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(cast_fb64_reply(data, cnt, &fb[OFB_40]));
}

static int
cast_fb64_reply(data, cnt, fbp)
	unsigned char *data;
	int cnt;
	struct fb *fbp;
{
	int x;
	unsigned char *p;
	Block b;
	register int state = fbp->state[DIR_ENCRYPT-1];

	if (cnt-- < 1)
		goto failure;

	switch (*data++) {
	case FB64_IV_OK:
		cast_fb64_stream_iv(fbp->temp_feed, &fbp->streams[DIR_ENCRYPT-1]);
		if (state == FAILED)
			state = IN_PROGRESS;
		state &= ~NO_RECV_IV;
		encrypt_send_keyid(DIR_ENCRYPT, (unsigned char *)"\0", 1, 1);
		break;

	case FB64_IV_BAD:
		memset(fbp->temp_feed, 0, sizeof(Block));
		cast_fb64_stream_iv(fbp->temp_feed, &fbp->streams[DIR_ENCRYPT-1]);
		state = FAILED;
		break;

	default:
		if (encrypt_debug_mode) {
			printf("Unknown option type: %d\r\n", data[-1]);
			printd(data, cnt);
			printf("\r\n");
		}
		/* FALL THROUGH */
	failure:
		state = FAILED;
		break;
	}
	return(fbp->state[DIR_ENCRYPT-1] = state);
}

#ifndef CAST_EXPORT_ENCRYPTION
int
cast_cfb64_session(key, server)
	Session_Key *key;
	int server;
{
	return cast_fb64_session(key, server, &fb[CFB_128], 1);
}

int
cast_ofb64_session(key, server)
	Session_Key *key;
	int server;
{
	return cast_fb64_session(key, server, &fb[OFB_128], 1);
}
#endif

int
castexp_cfb64_session(key, server)
	Session_Key *key;
	int server;
{
	return cast_fb64_session(key, server, &fb[CFB_40], 0);
}

int
castexp_ofb64_session(key, server)
	Session_Key *key;
	int server;
{
	return cast_fb64_session(key, server, &fb[OFB_40], 0);
}

#define CAST128_KEYLEN	16	/* 128 bits */
#define CAST5_40_KEYLEN	 5	/*  40 bits */

static int
cast_fb64_session(key, server, fbp, fs)
	Session_Key *key;
	int server;
	struct fb *fbp;
	int fs;
{
	int klen;
	unsigned char * kptr;

	if(fs)
	  klen = CAST128_KEYLEN;
	else
	  klen = CAST5_40_KEYLEN;

	if (!key || key->length < klen) {
		if (encrypt_debug_mode)
			printf("Can't set CAST session key (%d < %d)\r\n",
				key ? key->length : 0, klen);
		return -1;
	}
	if(key->length < 2 * klen)
	  kptr = key->data;
	else
	  kptr = key->data + klen;

	if(server) {
	  cast_fb64_stream_key(kptr, &fbp->streams[DIR_ENCRYPT-1], fs);
	  cast_fb64_stream_key(key->data, &fbp->streams[DIR_DECRYPT-1], fs);
	}
	else {
	  cast_fb64_stream_key(kptr, &fbp->streams[DIR_DECRYPT-1], fs);
	  cast_fb64_stream_key(key->data, &fbp->streams[DIR_ENCRYPT-1], fs);
	}

	/* Stuff leftovers into the feed */
	if(key->length >= 2 * klen + sizeof(Block))
	  memmove(fbp->temp_feed, key->data + 2 * klen, sizeof(Block));
	else
#ifdef HAVE_SRP
          t_random(fbp->temp_feed, sizeof(Block));
#else
          memset(fbp->temp_feed, 0, sizeof(Block));
#endif

	fbp->key_isset = 1;
	/*
	 * Now look to see if cast_fb64_start() was was waiting for
	 * the key to show up.  If so, go ahead an call it now
	 * that we have the key.
	 */
	if (fbp->need_start) {
		fbp->need_start = 0;
		cast_fb64_start(fbp, DIR_ENCRYPT, server);
	}
        return 0;
}

/*
 * We only accept a keyid of 0.  If we get a keyid of
 * 0, then mark the state as SUCCESS.
 */
#ifndef CAST_EXPORT_ENCRYPTION
int
cast_cfb64_keyid(dir, kp, lenp)
	int dir, *lenp;
	unsigned char *kp;
{
	return(cast_fb64_keyid(dir, kp, lenp, &fb[CFB_128]));
}

int
cast_ofb64_keyid(dir, kp, lenp)
	int dir, *lenp;
	unsigned char *kp;
{
	return(cast_fb64_keyid(dir, kp, lenp, &fb[OFB_128]));
}
#endif

int
castexp_cfb64_keyid(dir, kp, lenp)
	int dir, *lenp;
	unsigned char *kp;
{
	return(cast_fb64_keyid(dir, kp, lenp, &fb[CFB_40]));
}

int
castexp_ofb64_keyid(dir, kp, lenp)
	int dir, *lenp;
	unsigned char *kp;
{
	return(cast_fb64_keyid(dir, kp, lenp, &fb[OFB_40]));
}

static int
cast_fb64_keyid(dir, kp, lenp, fbp)
	int dir, *lenp;
	unsigned char *kp;
	struct fb *fbp;
{
	register int state = fbp->state[dir-1];

	if (*lenp != 1 || (*kp != '\0')) {
		*lenp = 0;
		return(state);
	}

	if (state == FAILED)
		state = IN_PROGRESS;

	state &= ~NO_KEYID;

	return(fbp->state[dir-1] = state);
}

static void
cast_fb64_printsub(data, cnt, buf, buflen, type)
	unsigned char *data, *buf, *type;
	int cnt, buflen;
{
	char lbuf[32];
	register int i;
	char *cp;

	buf[buflen-1] = '\0';		/* make sure it's NULL terminated */
	buflen -= 1;

	switch(data[2]) {
	case FB64_IV:
		sprintf(lbuf, "%s_IV", type);
		cp = lbuf;
		goto common;

	case FB64_IV_OK:
		sprintf(lbuf, "%s_IV_OK", type);
		cp = lbuf;
		goto common;

	case FB64_IV_BAD:
		sprintf(lbuf, "%s_IV_BAD", type);
		cp = lbuf;
		goto common;

	default:
		sprintf(lbuf, " %d (unknown)", data[2]);
		cp = lbuf;
	common:
		for (; (buflen > 0) && (*buf = *cp++); buf++)
			buflen--;
		for (i = 3; i < cnt; i++) {
			sprintf(lbuf, " %d", data[i]);
			for (cp = lbuf; (buflen > 0) && (*buf = *cp++); buf++)
				buflen--;
		}
		break;
	}
}

void
cast_cfb64_printsub(data, cnt, buf, buflen)
	unsigned char *data, *buf;
	int cnt, buflen;
{
	cast_fb64_printsub(data, cnt, buf, buflen, "CFB64");
}

void
cast_ofb64_printsub(data, cnt, buf, buflen)
	unsigned char *data, *buf;
	int cnt, buflen;
{
	cast_fb64_printsub(data, cnt, buf, buflen, "OFB64");
}

static void
cast_fb64_stream_iv(seed, stp)
	Block seed;
	register struct stinfo *stp;
{
	memmove((void *)stp->str_iv, (void *)seed, sizeof(Block));
	memmove((void *)stp->str_output, (void *)seed, sizeof(Block));

	stp->str_index = sizeof(Block);
}

static void
cast_fb64_stream_key(key, stp, fs)
	unsigned char * key;
	register struct stinfo *stp;
	int fs;
{
#ifndef CAST_EXPORT_ENCRYPTION
	if(fs)
	  cast128_key_sched(&stp->str_sched, key);
	else
#endif
	  cast5_40_key_sched(&stp->str_sched, key);

	memmove((void *)stp->str_output, (void *)stp->str_iv, sizeof(Block));

	stp->str_index = sizeof(Block);
}

/*
 * CAST 64 bit Cipher Feedback
 *
 *     key --->+------+
 *          +->| CAST |--+
 *          |  +------+  |
 *	    |            v
 *  INPUT --(---------->(+)+---> DATA
 *          |              |
 *	    +--------------+
 *
 *
 * Given:
 *	iV: Initial vector, 64 bits (8 bytes) long.
 *	Dn: the nth chunk of 64 bits (8 bytes) of data to encrypt (decrypt).
 *	On: the nth chunk of 64 bits (8 bytes) of encrypted (decrypted) output.
 *
 *	V0 = CAST(iV, key)
 *	On = Dn ^ Vn
 *	V(n+1) = CAST(On, key)
 */
#ifndef CAST_EXPORT_ENCRYPTION
void
cast_cfb64_encrypt(s, c)
	register unsigned char *s;
	int c;
{
  _cast_cfb64_encrypt(s, c, &fb[CFB_128].streams[DIR_ENCRYPT-1]);
}
#endif

void
castexp_cfb64_encrypt(s, c)
	register unsigned char *s;
	int c;
{
  _cast_cfb64_encrypt(s, c, &fb[CFB_40].streams[DIR_ENCRYPT-1]);
}

static void
_cast_cfb64_encrypt(s, c, stp)
	register unsigned char *s;
	int c;
	register struct stinfo *stp;
{
	register int index;

	index = stp->str_index;
	while (c-- > 0) {
		if (index == sizeof(Block)) {
			Block b;
			cast_ecb_encrypt(b, stp->str_output, &stp->str_sched, 0);
			memmove((void *)stp->str_feed, (void *)b, sizeof(Block));
			index = 0;
		}

		/* On encryption, we store (feed ^ data) which is cypher */
		*s = stp->str_output[index] = (stp->str_feed[index] ^ *s);
		s++;
		index++;
	}
	stp->str_index = index;
}

#ifndef CAST_EXPORT_ENCRYPTION
int
cast_cfb64_decrypt(data)
	int data;
{
  return _cast_cfb64_decrypt(data, &fb[CFB_128].streams[DIR_DECRYPT-1]);
}
#endif

int
castexp_cfb64_decrypt(data)
	int data;
{
  return _cast_cfb64_decrypt(data, &fb[CFB_40].streams[DIR_DECRYPT-1]);
}

static int
_cast_cfb64_decrypt(data, stp)
	int data;
	register struct stinfo *stp;
{
	int index;

	if (data == -1) {
		/*
		 * Back up one byte.  It is assumed that we will
		 * never back up more than one byte.  If we do, this
		 * may or may not work.
		 */
		if (stp->str_index)
			--stp->str_index;
		return(0);
	}

	index = stp->str_index++;
	if (index == sizeof(Block)) {
		Block b;
		cast_ecb_encrypt(b, stp->str_output, &stp->str_sched, 0);
		memmove((void *)stp->str_feed, (void *)b, sizeof(Block));
		stp->str_index = 1;	/* Next time will be 1 */
		index = 0;		/* But now use 0 */
	}

	/* On decryption we store (data) which is cypher. */
	stp->str_output[index] = data;
	return(data ^ stp->str_feed[index]);
}

/*
 * CAST 64 bit Output Feedback
 *
 * key --->+------+
 *	+->| CAST |--+
 *	|  +------+  |
 *	+------------+
 *	             v
 *  INPUT --------->(+) ----> DATA
 *
 * Given:
 *	iV: Initial vector, 64 bits (8 bytes) long.
 *	Dn: the nth chunk of 64 bits (8 bytes) of data to encrypt (decrypt).
 *	On: the nth chunk of 64 bits (8 bytes) of encrypted (decrypted) output.
 *
 *	V0 = CAST(iV, key)
 *	V(n+1) = CAST(Vn, key)
 *	On = Dn ^ Vn
 */
#ifndef CAST_EXPORT_ENCRYPTION
void
cast_ofb64_encrypt(s, c)
	register unsigned char *s;
	int c;
{
  _cast_ofb64_encrypt(s, c, &fb[OFB_128].streams[DIR_ENCRYPT-1]);
}
#endif

void
castexp_ofb64_encrypt(s, c)
	register unsigned char *s;
	int c;
{
  _cast_ofb64_encrypt(s, c, &fb[OFB_40].streams[DIR_ENCRYPT-1]);
}

static void
_cast_ofb64_encrypt(s, c, stp)
	register unsigned char *s;
	int c;
	register struct stinfo *stp;
{
	register int index;

	index = stp->str_index;
	while (c-- > 0) {
		if (index == sizeof(Block)) {
			Block b;
			cast_ecb_encrypt(b, stp->str_feed, &stp->str_sched, 0);
			memmove((void *)stp->str_feed, (void *)b, sizeof(Block));
			index = 0;
		}
		*s++ ^= stp->str_feed[index];
		index++;
	}
	stp->str_index = index;
}

#ifndef CAST_EXPORT_ENCRYPTION
int
cast_ofb64_decrypt(data)
	int data;
{
  return _cast_ofb64_decrypt(data, &fb[OFB_128].streams[DIR_DECRYPT-1]);
}
#endif

int
castexp_ofb64_decrypt(data)
	int data;
{
  return _cast_ofb64_decrypt(data, &fb[OFB_40].streams[DIR_DECRYPT-1]);
}

static int
_cast_ofb64_decrypt(data, stp)
	int data;
	register struct stinfo *stp;
{
	int index;

	if (data == -1) {
		/*
		 * Back up one byte.  It is assumed that we will
		 * never back up more than one byte.  If we do, this
		 * may or may not work.
		 */
		if (stp->str_index)
			--stp->str_index;
		return(0);
	}

	index = stp->str_index++;
	if (index == sizeof(Block)) {
		Block b;
		cast_ecb_encrypt(b, stp->str_feed, &stp->str_sched, 0);
		memmove((void *)stp->str_feed, (void *)b, sizeof(Block));
		stp->str_index = 1;	/* Next time will be 1 */
		index = 0;		/* But now use 0 */
	}

	return(data ^ stp->str_feed[index]);
}
#  endif /* CAST_ENCRYPTION */
# endif	/* AUTHENTICATION */
#endif	/* ENCRYPTION */
