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
 * 3DES Telnet encryption code incorporated into distribution by
 * Tom Wu (tjw@CS.Stanford.EDU) based on code contributed by
 * Jeffrey Altman (jaltman@columbia.edu).
 */

#ifndef lint
static char sccsid[] = "@(#)enc_des_ede3.c	8.3 (Berkeley) 5/30/95";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef	ENCRYPTION
# ifdef	AUTHENTICATION
#  ifdef DES_ENCRYPTION
#include <arpa/telnet.h>
#include <stdio.h>
#ifdef	__STDC__
#include <stdlib.h>
#endif

#ifdef OPENSSL_DES
#include <openssl/rand.h>
#include <openssl/des.h>
#endif
#ifdef CRYPTOLIB_DES
#include "libcrypt.h"
#endif
#include "encrypt.h"
#include "key-proto.h"
#include "misc-proto.h"

extern encrypt_debug_mode;

#define	CFB	0
#define	OFB	1

#define	NO_SEND_IV	1
#define	NO_RECV_IV	2
#define	NO_KEYID	4
#define	IN_PROGRESS	(NO_SEND_IV|NO_RECV_IV|NO_KEYID)
#define	SUCCESS		0
#define	FAILED		-1


struct fb {
	Block krbdes_key[3];
	Schedule krbdes_sched[3];
	Block temp_feed;
	unsigned char fb_feed[64];
	int need_start;
	int state[2];
	int keyid[2];
	int once;
	struct stinfo {
		Block		str_output;
		Block		str_feed;
		Block		str_iv;
		Block		str_ikey[3];
		Schedule	str_sched[3];
		int		str_index;
		int		str_flagshift;
	} streams[2];
};

static struct fb fb[2];

#if 0 /* TJW: is this needed? */
struct keyidlist {
	char	*keyid;
	int	keyidlen;
	char	*key;
	int	keylen;
	int	flags;
} keyidlist [] = {
	{ "\0", 1, 0, 0, 0 },		/* default key of zero */
	{ 0, 0, 0, 0, 0 }
};
#endif /* 0 */

#define	KEYFLAG_MASK	03

#define	KEYFLAG_NOINIT	00
#define	KEYFLAG_INIT	01
#define	KEYFLAG_OK	02
#define	KEYFLAG_BAD	03

#define	KEYFLAG_SHIFT	2

#define	SHIFT_VAL(a,b)	(KEYFLAG_SHIFT*((a)+((b)*2)))

#define	FB64_IV		1
#define	FB64_IV_OK	2
#define	FB64_IV_BAD	3


void des3_fb64_stream_iv P((Block, struct stinfo *));
void des3_fb64_init P((struct fb *));
static int des3_fb64_start P((struct fb *, int, int));
int des3_fb64_is P((unsigned char *, int, struct fb *));
int des3_fb64_reply P((unsigned char *, int, struct fb *));
static int des3_fb64_session P((Session_Key *, int, struct fb *));
void des3_fb64_stream_key P((Block *, struct stinfo *));
int des3_fb64_keyid P((int, unsigned char *, int *, struct fb *));

void
des3_cfb64_init(server)
	int server;
{
	des3_fb64_init(&fb[CFB]);
	fb[CFB].fb_feed[4] = ENCTYPE_DES3_CFB64;
	fb[CFB].streams[0].str_flagshift = SHIFT_VAL(0, CFB);
	fb[CFB].streams[1].str_flagshift = SHIFT_VAL(1, CFB);
}

void
des3_ofb64_init(server)
	int server;
{
	des3_fb64_init(&fb[OFB]);
	fb[OFB].fb_feed[4] = ENCTYPE_DES3_OFB64;
	fb[OFB].streams[0].str_flagshift = SHIFT_VAL(0, OFB);
	fb[OFB].streams[1].str_flagshift = SHIFT_VAL(1, OFB);
}

void
des3_fb64_init(fbp)
	register struct fb *fbp;
{
	memset((void *)fbp, 0, sizeof(*fbp));
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
int
des3_cfb64_start(dir, server)
	int dir;
	int server;
{
	return(des3_fb64_start(&fb[CFB], dir, server));
}
int
des3_ofb64_start(dir, server)
	int dir;
	int server;
{
	return(des3_fb64_start(&fb[OFB], dir, server));
}

static int
des3_fb64_start(fbp, dir, server)
	struct fb *fbp;
	int dir;
	int server;
{
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

		if (!VALIDKEY(fbp->krbdes_key[0]) ||
		    !VALIDKEY(fbp->krbdes_key[1]) ||
		    !VALIDKEY(fbp->krbdes_key[2])) {
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
#ifdef CRYPTOLIB_DES
		randomBytes(fbp->temp_feed, sizeof(Block), PSEUDO);
#else
		des_new_random_key(fbp->temp_feed);
#endif
#ifdef OPENSSL_DES
		des_ecb3_encrypt(fbp->temp_feed, fbp->temp_feed,
				 fbp->krbdes_sched[0],
				 fbp->krbdes_sched[1],
				 fbp->krbdes_sched[2], 1);
#elif defined(CRYPTOLIB_DES)
		block_cipher((unsigned char *)fbp->krbdes_sched[0],
			     fbp->temp_feed, 0);
		block_cipher((unsigned char *)fbp->krbdes_sched[1],
			     fbp->temp_feed, 1);
		block_cipher((unsigned char *)fbp->krbdes_sched[2],
			     fbp->temp_feed, 0);
#else
		des_ecb_encrypt(fbp->temp_feed, fbp->temp_feed,
				fbp->krbdes_sched[0], 1);
		des_ecb_encrypt(fbp->temp_feed, fbp->temp_feed,
				fbp->krbdes_sched[1], 0);
		des_ecb_encrypt(fbp->temp_feed, fbp->temp_feed,
				fbp->krbdes_sched[2], 1);
#endif
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
int
des3_cfb64_is(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(des3_fb64_is(data, cnt, &fb[CFB]));
}
int
des3_ofb64_is(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(des3_fb64_is(data, cnt, &fb[OFB]));
}

int
des3_fb64_is(data, cnt, fbp)
	unsigned char *data;
	int cnt;
	struct fb *fbp;
{
	int x;
	unsigned char *p;
	register int state = fbp->state[DIR_DECRYPT-1];

	if (cnt-- < 1)
		goto failure;

	switch (*data++) {
	case FB64_IV:
		if (cnt != sizeof(Block)) {
			if (encrypt_debug_mode)
				printf("DES3_FB64: initial vector failed on size\r\n");
			state = FAILED;
			goto failure;
		}

		if (encrypt_debug_mode)
			printf("DES3_FB64: initial vector received\r\n");

		if (encrypt_debug_mode)
			printf("Initializing Decrypt stream\r\n");

		des3_fb64_stream_iv((void *)data, &fbp->streams[DIR_DECRYPT-1]);

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
int
des3_cfb64_reply(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(des3_fb64_reply(data, cnt, &fb[CFB]));
}
int
des3_ofb64_reply(data, cnt)
	unsigned char *data;
	int cnt;
{
	return(des3_fb64_reply(data, cnt, &fb[OFB]));
}

int
des3_fb64_reply(data, cnt, fbp)
	unsigned char *data;
	int cnt;
	struct fb *fbp;
{
	int x;
	unsigned char *p;
	register int state = fbp->state[DIR_ENCRYPT-1];

	if (cnt-- < 1)
		goto failure;

	switch (*data++) {
	case FB64_IV_OK:
		des3_fb64_stream_iv(fbp->temp_feed, &fbp->streams[DIR_ENCRYPT-1]);
		if (state == FAILED)
			state = IN_PROGRESS;
		state &= ~NO_RECV_IV;
		encrypt_send_keyid(DIR_ENCRYPT, (unsigned char *)"\0", 1, 1);
		break;

	case FB64_IV_BAD:
		memset(fbp->temp_feed, 0, sizeof(Block));
		des3_fb64_stream_iv(fbp->temp_feed, &fbp->streams[DIR_ENCRYPT-1]);
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

int
des3_cfb64_session(key, server)
	Session_Key *key;
	int server;
{
	return des3_fb64_session(key, server, &fb[CFB]);
}

int
des3_ofb64_session(key, server)
	Session_Key *key;
	int server;
{
	return des3_fb64_session(key, server, &fb[OFB]);
}

static int
des3_fb64_session(key, server, fbp)
	Session_Key *key;
	int server;
	struct fb *fbp;
{
	int i, keys2use;
	struct stinfo * s_stream;
	struct stinfo * c_stream;
#ifdef CRYPTOLIB_DES
	unsigned char des_seed[64];
#endif

	if(server) {
	  s_stream = &fbp->streams[DIR_ENCRYPT-1];
	  c_stream = &fbp->streams[DIR_DECRYPT-1];
	}
	else {
	  s_stream = &fbp->streams[DIR_DECRYPT-1];
	  c_stream = &fbp->streams[DIR_ENCRYPT-1];
	}

	keys2use = (key != NULL) ? key->length / sizeof(Block) : 0;
	if (keys2use < 2) {
		if (encrypt_debug_mode)
			printf("Can't set 3DES session key (%d < %d)\r\n",
				key ? key->length : 0, 2 * sizeof(Block));
		return -1;
	}

	/* Compute the first set of keys / key order */
	switch ( keys2use ) {
	case 2:
	  memcpy((void *)fbp->krbdes_key[0],
		 (void *)key->data, sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[1],
		 (void *)(key->data + sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[2],
		 (void *)key->data, sizeof(Block));
	  break;
	case 3:
	default:
	  memcpy((void *)fbp->krbdes_key[0],
		 (void *)key->data, sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[1],
		 (void *)(key->data + sizeof(Block)), sizeof(Block));
	  memcpy((void *) fbp->krbdes_key[2],
                 (void *)(key->data + 2*sizeof(Block)), sizeof(Block));
	  break;
	}

	/* TJW:  Can this occur before fix_parity?  This code assumes yes. */
	if (fbp->once == 0) {
#ifdef OPENSSL_DES
		des_random_seed(fbp->krbdes_key[0]);
#elif defined(CRYPTOLIB_DES)
		memmove((void *)des_seed, fbp->krbdes_key[0], sizeof(Block));
		memmove((void *)(des_seed + sizeof(Block)), fbp->krbdes_key[1], sizeof(Block));
		memmove((void *)(des_seed + 2*sizeof(Block)), fbp->krbdes_key[2], sizeof(Block));
		seedDesRandom(des_seed, sizeof(des_seed));
#elif defined(DESLIB4)
		des_init_random_number_generator(fbp->krbdes_key[0]);
#endif
		fbp->once = 1;
	}

#ifndef CRYPTOLIB_DES
	for(i = 0; i < 3; ++i)
	  des_fixup_key_parity(fbp->krbdes_key[i]);
#endif
	des3_fb64_stream_key(fbp->krbdes_key, s_stream);

	/* Compute the second set of keys / key order */
	switch ( keys2use ) {
	case 2:
	  memcpy((void *)fbp->krbdes_key[0],
		 (void *)(key->data + sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[1],
		 (void *)key->data, sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[2],
		 (void *)(key->data + sizeof(Block)), sizeof(Block));
	  break;
	case 3:
	  memcpy((void *)fbp->krbdes_key[0],
		 (void *)(key->data + sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[1],
                 (void *)(key->data + 2*sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[2],
		 (void *)key->data, sizeof(Block));
	  break;
	case 4:
	  memcpy((void *)fbp->krbdes_key[0],
		 (void *)(key->data + sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[1],
                 (void *)(key->data + 3*sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[2],
		 (void *)key->data, sizeof(Block));
	  break;
	case 5:
	  memcpy((void *)fbp->krbdes_key[0],
		 (void *)(key->data + sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[1],
                 (void *)(key->data + 3*sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[2],
                 (void *)(key->data + 4*sizeof(Block)), sizeof(Block));
	  break;
	case 6:
	  memcpy((void *)fbp->krbdes_key[0],
                 (void *)(key->data + 3*sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[1],
                 (void *)(key->data + 4*sizeof(Block)), sizeof(Block));
	  memcpy((void *)fbp->krbdes_key[2],
                 (void *)(key->data + 5*sizeof(Block)), sizeof(Block));
	  break;
	}

#ifndef CRYPTOLIB_DES
	for(i = 0; i < 3; ++i)
	  des_fixup_key_parity(fbp->krbdes_key[i]);
#endif

	des3_fb64_stream_key(fbp->krbdes_key, c_stream);

	for(i = 0; i < 3; ++i) {
#ifdef CRYPTOLIB_DES
	  key_setup(fbp->krbdes_key[i], (unsigned char *)fbp->krbdes_sched[i]);
#else
	  des_key_sched(fbp->krbdes_key[i], fbp->krbdes_sched[i]);
#endif
	}
	/*
	 * Now look to see if krbdes_start() was was waiting for
	 * the key to show up.  If so, go ahead an call it now
	 * that we have the key.
	 */
	if (fbp->need_start) {
		fbp->need_start = 0;
		des3_fb64_start(fbp, DIR_ENCRYPT, server);
	}
        return 0;
}

/*
 * We only accept a keyid of 0.  If we get a keyid of
 * 0, then mark the state as SUCCESS.
 */
int
des3_cfb64_keyid(dir, kp, lenp)
	int dir, *lenp;
	unsigned char *kp;
{
	return(des3_fb64_keyid(dir, kp, lenp, &fb[CFB]));
}

int
des3_ofb64_keyid(dir, kp, lenp)
	int dir, *lenp;
	unsigned char *kp;
{
	return(des3_fb64_keyid(dir, kp, lenp, &fb[OFB]));
}

int
des3_fb64_keyid(dir, kp, lenp, fbp)
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

void
des3_fb64_printsub(data, cnt, buf, buflen, type)
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
des3_cfb64_printsub(data, cnt, buf, buflen)
	unsigned char *data, *buf;
	int cnt, buflen;
{
	des3_fb64_printsub(data, cnt, buf, buflen, "CFB64");
}

void
des3_ofb64_printsub(data, cnt, buf, buflen)
	unsigned char *data, *buf;
	int cnt, buflen;
{
	des3_fb64_printsub(data, cnt, buf, buflen, "OFB64");
}

void
des3_fb64_stream_iv(seed, stp)
	Block seed;
	register struct stinfo *stp;
{
	int i;

	memmove((void *)stp->str_iv, (void *)seed, sizeof(Block));
	memmove((void *)stp->str_output, (void *)seed, sizeof(Block));

	for(i = 0; i < 3; ++i) {
#ifdef CRYPTOLIB_DES
	  key_setup(stp->str_ikey[i], (unsigned char *)stp->str_sched[i]);
#else
	  des_key_sched(stp->str_ikey[i], stp->str_sched[i]);
#endif
	}

	stp->str_index = sizeof(Block);
}

void
des3_fb64_stream_key(key, stp)
	Block * key;
	register struct stinfo *stp;
{
	int i;

	for(i = 0; i < 3; ++i) {
	  memmove((void *)stp->str_ikey[i], (void *)key[i], sizeof(Block));
#ifdef CRYPTOLIB_DES
	  key_setup(key[i], (unsigned char *)stp->str_sched[i]);
#else
	  des_key_sched(key[i], stp->str_sched[i]);
#endif
	}

	memmove((void *)stp->str_output, (void *)stp->str_iv, sizeof(Block));
	stp->str_index = sizeof(Block);
}

/*
 * DES3 64 bit Cipher Feedback
 *
 *                key1       key2       key3
 *                 |          |          |
 *                 v          v          v
 *             +-------+  +-------+  +-------+
 *          +->| DES-e |->| DES-d |->| DES-e |-- +
 *          |  +-------+  +-------+  +-------+   |
 *          |                                    v
 *  INPUT --(-------------------------------->(+)+---> DATA
 *          |                                    |
 *          +------------------------------------+
 *
 *
 * Given:
 *	iV: Initial vector, 64 bits (8 bytes) long.
 *	Dn: the nth chunk of 64 bits (8 bytes) of data to encrypt (decrypt).
 *	On: the nth chunk of 64 bits (8 bytes) of encrypted (decrypted) output.
 *
 *	V0 = DES-e(DES-d(DES-e(iV, key1),key2),key3)
 *	On = Dn ^ Vn
 *	V(n+1) = DES-e(DES-d(DES-e(On, key1),key2),key3)
 */

void
des3_cfb64_encrypt(s, c)
	register unsigned char *s;
	int c;
{
	register struct stinfo *stp = &fb[CFB].streams[DIR_ENCRYPT-1];
	register int index;

	index = stp->str_index;
	while (c-- > 0) {
		if (index == sizeof(Block)) {
#ifdef OPENSSL_DES
			des_ecb3_encrypt(stp->str_output, stp->str_feed,
					 stp->str_sched[0],
					 stp->str_sched[1],
					 stp->str_sched[2], 1);
#elif defined(CRYPTOLIB_DES)
			memmove((void *)stp->str_feed, (void *)stp->str_output,
				sizeof(Block));
			block_cipher((unsigned char *)stp->str_sched[0],
				     stp->str_feed, 0);
			block_cipher((unsigned char *)stp->str_sched[1],
				     stp->str_feed, 1);
			block_cipher((unsigned char *)stp->str_sched[2],
				     stp->str_feed, 0);
#else
			memmove((void *)stp->str_feed, (void *)stp->str_output,
				sizeof(Block));
			des_ecb_encrypt(stp->str_feed, stp->str_feed, stp->str_sched[0], 1);
			des_ecb_encrypt(stp->str_feed, stp->str_feed, stp->str_sched[1], 0);
			des_ecb_encrypt(stp->str_feed, stp->str_feed, stp->str_sched[2], 1);
#endif
			index = 0;
		}

		/* On encryption, we store (feed ^ data) which is cypher */
		*s = stp->str_output[index] = (stp->str_feed[index] ^ *s);
		s++;
		index++;
	}
	stp->str_index = index;
}

int
des3_cfb64_decrypt(data)
	int data;
{
	register struct stinfo *stp = &fb[CFB].streams[DIR_DECRYPT-1];
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
#ifdef OPENSSL_DES
		des_ecb3_encrypt(stp->str_output, stp->str_feed,
				 stp->str_sched[0],
				 stp->str_sched[1],
				 stp->str_sched[2], 1);
#elif defined(CRYPTOLIB_DES)
		memmove((void *)stp->str_feed, (void *)stp->str_output,
			sizeof(Block));
		block_cipher((unsigned char *)stp->str_sched[0],
			     stp->str_feed, 0);
		block_cipher((unsigned char *)stp->str_sched[1],
			     stp->str_feed, 1);
		block_cipher((unsigned char *)stp->str_sched[2],
			     stp->str_feed, 0);
#else
		memmove((void *)stp->str_feed, (void *)stp->str_output,
			sizeof(Block));
		des_ecb_encrypt(stp->str_feed, stp->str_feed,
				stp->str_sched[0], 1);
		des_ecb_encrypt(stp->str_feed, stp->str_feed,
				stp->str_sched[1], 0);
		des_ecb_encrypt(stp->str_feed, stp->str_feed,
				stp->str_sched[2], 1);
#endif
		stp->str_index = 1;	/* Next time will be 1 */
		index = 0;		/* But now use 0 */
	}

	/* On decryption we store (data) which is cypher. */
	stp->str_output[index] = data;
	return(data ^ stp->str_feed[index]);
}

/*
 * DES3 64 bit Output Feedback
 *
 *                key1       key2       key3
 *                 |          |          |
 *                 v          v          v
 *             +-------+  +-------+  +-------+
 *          +->| DES-e |->| DES-d |->| DES-e |-- +
 *          |  +-------+  +-------+  +-------+   |
 *          +------------------------------------+
 *                                               v
 *  INPUT ------------------------------------->(+) ----> DATA
 *
 * Given:
 *	iV: Initial vector, 64 bits (8 bytes) long.
 *	Dn: the nth chunk of 64 bits (8 bytes) of data to encrypt (decrypt).
 *	On: the nth chunk of 64 bits (8 bytes) of encrypted (decrypted) output.
 *
 *	V0 = DES-e(DES-d(DES-e(iV, key1),key2),key3)
 *	V(n+1) = DES-e(DES-d(DES-e(Vn, key1),key2),key3)
 *	On = Dn ^ Vn
 */
void
des3_ofb64_encrypt(s, c)
	register unsigned char *s;
	int c;
{
	register struct stinfo *stp = &fb[OFB].streams[DIR_ENCRYPT-1];
	register int index;

	index = stp->str_index;
	while (c-- > 0) {
		if (index == sizeof(Block)) {
#ifdef OPENSSL_DES
			des_ecb3_encrypt(stp->str_feed, stp->str_feed,
					 stp->str_sched[0],
					 stp->str_sched[1],
					 stp->str_sched[2], 1);
#elif defined(CRYPTOLIB_DES)
			block_cipher((unsigned char *)stp->str_sched[0],
				     stp->str_feed, 0);
			block_cipher((unsigned char *)stp->str_sched[1],
				     stp->str_feed, 1);
			block_cipher((unsigned char *)stp->str_sched[2],
				     stp->str_feed, 0);
#else
			des_ecb_encrypt(stp->str_feed, stp->str_feed,
					stp->str_sched[0], 1);
			des_ecb_encrypt(stp->str_feed, stp->str_feed,
					stp->str_sched[1], 0);
			des_ecb_encrypt(stp->str_feed, stp->str_feed,
					stp->str_sched[2], 1);
#endif
			index = 0;
		}
		*s++ ^= stp->str_feed[index];
		index++;
	}
	stp->str_index = index;
}

int
des3_ofb64_decrypt(data)
	int data;
{
	register struct stinfo *stp = &fb[OFB].streams[DIR_DECRYPT-1];
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
#ifdef OPENSSL_DES
		des_ecb3_encrypt(stp->str_feed, stp->str_feed,
				 stp->str_sched[0],
				 stp->str_sched[1],
				 stp->str_sched[2], 1);
#elif defined(CRYPTOLIB_DES)
		block_cipher((unsigned char *)stp->str_sched[0],
			     stp->str_feed, 0);
		block_cipher((unsigned char *)stp->str_sched[1],
			     stp->str_feed, 1);
		block_cipher((unsigned char *)stp->str_sched[2],
			     stp->str_feed, 0);
#else
		des_ecb_encrypt(stp->str_feed, stp->str_feed,
				stp->str_sched[0], 1);
		des_ecb_encrypt(stp->str_feed, stp->str_feed,
				stp->str_sched[1], 0);
		des_ecb_encrypt(stp->str_feed, stp->str_feed,
				stp->str_sched[2], 1);
#endif
		stp->str_index = 1;	/* Next time will be 1 */
		index = 0;		/* But now use 0 */
	}

	return(data ^ stp->str_feed[index]);
}
#  endif /* DES_ENCRYPTION */
# endif	/* AUTHENTICATION */
#endif	/* ENCRYPTION */
