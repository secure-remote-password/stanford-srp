/*
 * Copyright (c) Peter 'Luna' Runestig 1999, 2000 <peter@runestig.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY PETER RUNESTIG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Incorporated into the SRP Telnet distribution 10/19/2000 by
 * Tom Wu <tjw@cs.stanford.edu>
 */

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) Peter 'Luna' Runestig 1999, 2000 <peter@runestig.com>.\n";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef FWD_X

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/telnet.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "ring.h"
#include "defines.h"
#include "externs.h"
#include "fwdxutil.h"
#include "Xauth.h"

#ifdef FWDX_UNIX_SOCK
# ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#  ifndef AF_LOCAL
#   define AF_LOCAL AF_UNIX
#  endif /* AF_LOCAL */
#  ifndef PF_LOCAL
#   define PF_LOCAL PF_UNIX
#  endif /* PF_LOCAL */
# else
#  undef FWDX_UNIX_SOCK
# endif /* HAVE_SYS_UN_H  */
#endif  /* FWDX_UNIX_SOCK */

#ifdef TLS
#define SEND  tls_send
#define WRITE tls_write
#define READ  tls_read
#include "tlsutil.h"
#else
#define SEND  send
#define WRITE write
#define READ  read
#endif

int netflush();
int parse_displayname(
    char *displayname,
    int *familyp,			/* return */
    char **hostp,			/* return */
    int *dpynump, int *scrnump,		/* return */
    char **restp			/* return */
    );

#ifdef FWDX_XDM
void XdmcpWrap (
    unsigned char	*input,
    unsigned char	*wrapper,
    unsigned char	*output,
    int			bytes);
#endif /* FWDX_XDM */

extern int net;  /* the network socket */

unsigned char buffer[BUFSIZ], fwdx_options[255], *fwdx_sbdata = NULL;
int *fwdx_sockets = NULL, *fwdx_sent_xauth = NULL, *fwdx_suspend = NULL;
int fwdx_sbdata_size = sizeof(buffer) * 2 + 10;
int fwdx_enable_flag = 1;
unsigned short num_channels = 0;
Xauth *real_xauth = NULL;
#ifdef FWDX_XDM
unsigned int xdm_auth_serial = 0;
#endif /* FWDX_XDM */

void fxwd_init(void)
{
    memset(fwdx_options, 0, sizeof(fwdx_options));
}

unsigned char *fwdx_add_quoted_twobyte(unsigned char *p, unsigned short twobyte)
/* adds the IAC quoted (MSB) representation of 'twobyte' at buffer pointer 'p',
 * returning pointer to new buffer position. NO OVERFLOW CHECK!
 */
{
    *p++ = (unsigned char)((twobyte >> 8) & 0xFF);
    if (*(p - 1) == 0xFF)
    	*p++ = 0xFF;
    *p++ = (unsigned char)(twobyte & 0xFF);
    if (*(p - 1) == 0xFF)
    	*p++ = 0xFF;
    return p;
}

int fwdx_open_channel(unsigned short channel)
/* returns 0 if OK, else a custom error code */
{
    int s, dpynum, scrnum, family, rv = 0;
    struct sockaddr_in saddr_in = { AF_INET };
#ifdef FWDX_UNIX_SOCK
    struct sockaddr_un saddr_un = { AF_UNIX };
#endif  /* FWDX_UNIX_SOCK */
    struct hostent *hi;
    char *display, *host = NULL, *rest = NULL;

    /* parse the local DISPLAY env var */
    if (!(display = getenv("DISPLAY")))
    	return 1;
    if (!parse_displayname(display, &family, &host, &dpynum, &scrnum, &rest)) {
    	rv = 2;
	goto cleanup;
    }
#ifndef FWDX_UNIX_SOCK
    /* if $DISPLAY indicates use of unix domain sockets, but we don't support it,
     * we change things to use inet sockets on the ip loopback interface instead,
     * and hope that it works.
     */
    if (family == FamilyLocal) {
	family = FamilyInternet;
	if (host) free(host);
	if (host = malloc(strlen("localhost") + 1))
	    strcpy(host, "localhost");
	else {
	    rv = 3;
	    goto cleanup;
	}
    }
#endif  /* ! FWDX_UNIX_SOCK */

#ifdef FWDX_UNIX_SOCK
    if (family == FamilyLocal)
	s = socket(PF_UNIX, SOCK_STREAM, 0);
    else
#endif  /* FWDX_UNIX_SOCK */
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
    	rv = 4;
	goto cleanup;
    }

    /* expand some channel info arrays */
    if (fwdx_sockets)
	fwdx_sockets = realloc(fwdx_sockets, (num_channels + 1) * sizeof(int));
    else
	fwdx_sockets = malloc(sizeof(int));
    if (!fwdx_sockets) {
	rv = 5;
	goto cleanup;
    }
    if (fwdx_sent_xauth)
	fwdx_sent_xauth = realloc(fwdx_sent_xauth, (num_channels + 1) * sizeof(int));
    else
	fwdx_sent_xauth = malloc(sizeof(int));
    if (!fwdx_sent_xauth) {
	rv = 6;
	goto cleanup;
    }
    if (fwdx_suspend)
	fwdx_suspend = realloc(fwdx_suspend, (num_channels + 1) * sizeof(int));
    else
	fwdx_suspend = malloc(sizeof(int));
    fwdx_suspend[num_channels] = 0;

    /* connect to the local X server */
#ifdef FWDX_UNIX_SOCK
#ifndef SUN_LEN
#define SUN_LEN(ptr) \
	(((size_t) (((struct sockaddr_un *) 0)->sun_path) + strlen((ptr)->sun_path)))
#endif /* !SUN_LEN */
    if (family == FamilyLocal) {
	char sock_name[30];
	if(access("/tmp/.X11-unix", X_OK) == 0)
	  snprintf(sock_name, sizeof(sock_name), "/tmp/.X11-unix/X%d", dpynum);
	else	/* HP-UX */
	  snprintf(sock_name, sizeof(sock_name), "/var/spool/sockets/X11/%d", dpynum);
	strncpy(saddr_un.sun_path, sock_name, sizeof(saddr_un.sun_path));
	if (connect(s, (struct sockaddr *) &saddr_un, SUN_LEN(&saddr_un)) < 0) {
	    fwdx_sockets[num_channels] = -1;
	    rv = 7;
	    goto cleanup;
	}
    }
    else {
#endif  /* FWDX_UNIX_SOCK */
    saddr_in.sin_port = htons(dpynum + 6000);
    /* first try if "host" is really a dotted address */
    if (!(inet_aton(host, (struct in_addr *) &saddr_in.sin_addr))) {
    	if (hi = gethostbyname(host))
    	    saddr_in.sin_addr = *(struct in_addr *)hi->h_addr;
	else {
    	    rv = 8;
	    goto cleanup;
	}
    }
    if (connect(s, (struct sockaddr *) &saddr_in, sizeof(saddr_in)) < 0) {
    	fwdx_sockets[num_channels] = -1;
    	rv = 9;
	goto cleanup;
    }
#ifdef FWDX_UNIX_SOCK
    }
#endif  /* FWDX_UNIX_SOCK */
    
    fwdx_sockets[num_channels] = s;
    fwdx_sent_xauth[num_channels] = 0;
    num_channels++;
  cleanup:
    if (host) free(host);
    if (rest) free(rest);
    return rv;
}

int fwdx_get_screen_no(char *display)
{
    int dpynum, scrnum = 0, family;
    char *host = NULL, *rest = NULL;

    if (!display)
    	return -1;
    if (!parse_displayname(display, &family, &host, &dpynum, &scrnum, &rest))
    	scrnum -1;
    if (host) free(host);
    if (rest) free(rest);
    return scrnum;
}

void fwdx_close_channel(unsigned short channel)
{
    if (fwdx_sockets && channel < num_channels) {
    	if (fwdx_sockets[channel] != -1)
    	    close(fwdx_sockets[channel]);
	fwdx_sockets[channel] = -1;
        fwdx_sent_xauth[channel] = 0;
    }
}

void fwdx_do_server_options(unsigned char *sp, int len)
{
    unsigned char sb[255] = { IAC, SB, TELOPT_FORWARD_X, FWDX_OPTIONS }, *p = sb + 4;
    int n = 0;

    /* test first option byte */
    *p = FWDX_OPT_NONE;

#ifdef COMMENT
    /* If we had an option to test for this is how/where we would do it */
    if (sp[n] & option) {
        flag = 1;
	*p |= option;
    }
#endif
    n++; p++;
    
    /* if there are more option bytes, we don't support any of it */
    for (; n < len && n < (sizeof(sb) - 2); n++, p++)
    	*p = FWDX_OPT_NONE;

    sprintf(p, "%c%c", IAC, SE);	/* safe */
    p += 2;
    /* send away which server options we support */
    /* TODO: what if we can't send, here and elsewhere? */
    if (p - sb < NETROOM()) {
	ring_supply_data(&netoring, sb, p - sb);
	printsub('>', sb + 2, p - sb - 2);
    }
}

void fwdx_forward(unsigned short channel, unsigned char *data, int len)
{
    if (fwdx_sockets && channel < num_channels)
    	if (fwdx_sockets[channel] != -1) {
	    int c, left, obsize, idx = 0;
	    unsigned char *p;

	    /* check if fwdx_sbdata is big enough for worst case */
	    if ((len * 2 + 10) > fwdx_sbdata_size)
	    	if (!(fwdx_sbdata = realloc(fwdx_sbdata, fwdx_sbdata_size = len * 2 + 10))) {
		    unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_CLOSE }, *p;
		    fwdx_sbdata_size = 0;
		    fwdx_close_channel(channel);
		    p = fwdx_add_quoted_twobyte(sb + 4, channel);
	    	    sprintf(p, "%c%c", IAC, SE);	/* safe */
	    	    p += 2;
		    if (p - sb < NETROOM()) {
			ring_supply_data(&netoring, sb, p - sb);
			printsub('>', sb + 2, p - sb - 2);
	    	    }
		    return;
	    	}
		    
	    p = fwdx_sbdata;
	    sprintf(p, "%c%c%c%c", IAC, SB, TELOPT_FORWARD_X, FWDX_DATA);  /* safe */
	    p += 4;
	    p = fwdx_add_quoted_twobyte(p, channel);
	    for (c = 0; c < len; c++) {
	    	*p++ = data[c];
	    	if (data[c] == 0xFF)
		    *p++ = 0xFF;
	    }
	    sprintf(p, "%c%c", IAC, SE);	/* safe */
	    p += 2;
	    
	    left = p - fwdx_sbdata;	/* how much left to send */
	    while (left) {
	    	obsize = NETROOM(); /* how much space in netobuf */
		if (left > obsize) {
		    ring_supply_data(&netoring, fwdx_sbdata + idx, obsize);
		    idx += obsize;
		    left -= obsize;
		} else {
		    ring_supply_data(&netoring, fwdx_sbdata + idx, left);
		    left = 0;
		}
		netflush();
	    }
	    printsub('>', fwdx_sbdata + 2, p - fwdx_sbdata - 2);
	}	
}

int fwdx_check_sockets(fd_set *ibits)
/* returns 1 if we did something, else 0 */
{
    unsigned short c;
    int rv = 0;

    if (fwdx_sockets)
    	for (c = 0; c < num_channels; c++)
	    if (fwdx_sockets[c] > -1 && FD_ISSET(fwdx_sockets[c], ibits)) {
	    	int r;
		rv = 1;
	    	r = read(fwdx_sockets[c], buffer, sizeof(buffer));
	    	if (r > 0)
	    	    fwdx_forward(c, buffer, r);
		else {
		    unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_CLOSE }, *p;
		    fwdx_close_channel(c);
		    p = fwdx_add_quoted_twobyte(sb + 4, c);
	    	    sprintf(p, "%c%c", IAC, SE);	/* safe */
	    	    p += 2;
		    if (p - sb < NETROOM()) {
			ring_supply_data(&netoring, sb, p - sb);
			printsub('>', sb + 2, p - sb - 2);
	    	    }
		}
	    }
    return rv;
}

int fwdx_max_socket(void)
/* return the highest value socket number */
{
    int c, rv = 0;

    if (fwdx_sockets)
    	for (c = 0; c < num_channels; c++)
	    if (fwdx_sockets[c] > rv)
		rv = fwdx_sockets[c];
    return rv;
}

void fwdx_init_fd_set(fd_set *ibits)
{
    int c;
    
    if (fwdx_sockets)
    	for (c = 0; c < num_channels; c++)
	    if (fwdx_sockets[c] > -1 && !fwdx_suspend[c])
	    	FD_SET(fwdx_sockets[c], ibits);
}

int 
fwdx_send_xauth_to_xserver(channel, data, len)
    int channel; unsigned char * data; int len;
{
    int name_len, data_len, i;

    if ( fwdx_sent_xauth[channel] )
        return(0);

    if (len < 12)
        goto auth_err;

    /* Parse the lengths of variable-length fields. */
    /* for documentation about this, see page 113 in
     * "X Window System Protocol / X Consortion Standard / X Version 11, Release 6.4"
     * available at ftp://ftp.x.org/pub/R6.4/xc/doc/hardcopy/XProtocol/proto.PS.gz */
    if (data[0] == 0x42) {		/* byte order MSB first. */
        /* Xauth packets appear to always have this format */
        if ( data[1] != 0x00 ||
             data[2] != 0x00 ||
             data[3] != 0x0B ||
             data[4] != 0x00 ||
             data[5] != 0x00 )
            goto auth_err;

        name_len = (data[6] << 8) + data[7];
        data_len = (data[8] << 8) + data[9];
    } else if (data[0] == 0x6c) {	/* Byte order LSB first. */
        /* Xauth packets appear to always have this format */
        if ( data[1] != 0x00 ||
             data[2] != 0x0B ||
             data[3] != 0x00 ||
             data[4] != 0x00 ||
             data[5] != 0x00 )
            goto auth_err;

        name_len = data[6] + (data[7] << 8);
        data_len = data[8] + (data[9] << 8);
    } else {
        /* bad byte order byte */
        goto auth_err;
    }

    /* Check if the whole packet is in buffer. */
    if (len < 12 + ((name_len + 3) & ~3) + ((data_len + 3) & ~3))
        goto auth_err;
    /* If the Telnet Server allows a real Xauth message to be sent */
    /* Then let the message be processed by the Xserver.           */
    if ( name_len + data_len > 0 ) {
        fwdx_sent_xauth[channel] = 1;
        return(0);
    }
    else
    /* If an empty Xauth message was received.  We are going to   */
    /* send our own Xauth message using the real Xauth data.  And */
    /* then send any other data in the buffer.                    */
    {
        int c, err, dpynum, scrnum, family, sb_len;
        char *display, *host = NULL, *rest = NULL;
        unsigned char *sb, *p;

        /* parse the local DISPLAY env var */
        display = getenv("DISPLAY");
        if ( !display )
            display = "127.0.0.1:0.0";

        if (parse_displayname(display, &family, &host, &dpynum, &scrnum, &rest)) {
            char disp_no[10];
            snprintf(disp_no, sizeof(disp_no), "%u", dpynum);
            if (family == FamilyLocal) {
                /* call with address = "<local host name>" */
                char address[300] = "localhost";

                real_xauth = XauGetAuthByAddr(family, strlen(address), address,
					      strlen(disp_no), disp_no, 0, NULL);
                if ( !real_xauth ) {
                    gethostname(address, sizeof(address) - 1);
                    real_xauth = XauGetAuthByAddr(family, strlen(address), address,
						  strlen(disp_no), disp_no, 0, NULL);
                }
            }
            else if (family == FamilyInternet) {
                /* call with address = 4 bytes numeric ip addr (MSB) */
                struct hostent *hi;
                struct in_addr inaddrx;

                if (hi = gethostbyname(host)) {
                    real_xauth = XauGetAuthByAddr(family, 4, hi->h_addr, 
                                                  strlen(disp_no), disp_no, 0, NULL);
                } else {
                    inaddrx.s_addr = inet_addr(host);
                    real_xauth = XauGetAuthByAddr(family, 4, (const char *) &inaddrx.s_addr, 
                                                  strlen(disp_no), disp_no, 0, NULL);
                }
            }
        }
        if (host) free(host);
        if (rest) free(rest);
        if ( !real_xauth ) {
            fwdx_sent_xauth[channel] = 1;
            return(0);
        }

        if ( !strncmp(real_xauth->name,"MIT-MAGIC-COOKIE-1",real_xauth->name_length) ) {
            char msg[64];

            name_len = 18;
            data_len = 16;

            if ( data[0] == 0x42 ) {
                msg[0] = 0x42; /* MSB order */
                msg[1] = msg[2] = 0;
                msg[3] = 0x0B;
                msg[4] = msg[5] = 0;
                msg[6] = (name_len >> 8);
                msg[7] = (name_len & 0xFF);
                msg[8] = (data_len >> 8);
                msg[9] = (data_len & 0xFF);
            } else {
                msg[0] = 0x6c; /* LSB order */
                msg[1] = 0;
                msg[2] = 0x0B;
                msg[3] = msg[4] = msg[5] = 0;
                msg[6] = (name_len & 0xFF);
                msg[7] = (name_len >> 8);
                msg[8] = (data_len & 0xFF);
                msg[9] = (data_len >> 8);
            }
            msg[10] = msg[11] = 0;
            memcpy(&msg[12],real_xauth->name,18);
            msg[30] = msg[31] = 0;
            memcpy(&msg[32],real_xauth->data,16);

            if (fwdx_redirect(channel,(char *)msg,48) < 0) {
                fwdx_sent_xauth[channel] = 1;
                return(-1);
            } else {
                fwdx_sent_xauth[channel] = 1;
                return(12);     
            }
#ifdef FWDX_XDM
        } else if ( !strncmp(real_xauth->name,"XDM-AUTHORIZATION-1",
			     real_xauth->name_length) ) {
            unsigned char msg[64], xdm_data[24];
	    time_t time_now;

            name_len = 19;
            data_len = 24;

            if ( data[0] == 0x42 ) {
                msg[0] = 0x42; /* MSB order */
                msg[1] = msg[2] = 0;
                msg[3] = 0x0B;
                msg[4] = msg[5] = 0;
                msg[6] = (name_len >> 8);
                msg[7] = (name_len & 0xFF);
                msg[8] = (data_len >> 8);
                msg[9] = (data_len & 0xFF);
            } else {
                msg[0] = 0x6c; /* LSB order */
                msg[1] = 0;
                msg[2] = 0x0B;
                msg[3] = msg[4] = msg[5] = 0;
                msg[6] = (name_len & 0xFF);
                msg[7] = (name_len >> 8);
                msg[8] = (data_len & 0xFF);
                msg[9] = (data_len >> 8);
            }
            msg[10] = msg[11] = 0;
            memcpy(&msg[12], real_xauth->name, 19);
            msg[31] = 0;

	    /* make the DES encrypted data block, first the "authenticator" from
	     * the .Xauthority file */
	    memset(xdm_data, 0, sizeof(xdm_data));
	    memcpy(xdm_data, real_xauth->data, 8);
	    /* then either the peer's ip address / port number or the process id
	     * plus a "serial number" */
	    if (family == FamilyLocal) {
		unsigned int pid = getpid();
		xdm_data[8] = pid >> 24;
		xdm_data[9] = pid >> 16;
		xdm_data[10] = pid >> 8;
		xdm_data[11] = pid; 
		xdm_data[12] = xdm_auth_serial >> 8;
		xdm_data[13] = xdm_auth_serial;
		xdm_auth_serial++;
	    } else if (family == FamilyInternet) {
		struct sockaddr_in saddr;
		int saddr_len = sizeof(saddr);
		getsockname(fwdx_sockets[channel], (struct sockaddr *)&saddr, &saddr_len);
		/* members of saddr has network byte order in memory */
		xdm_data[8] = saddr.sin_addr.s_addr;
		xdm_data[9] = saddr.sin_addr.s_addr >> 8;
		xdm_data[10] = saddr.sin_addr.s_addr >> 16;
		xdm_data[11] = saddr.sin_addr.s_addr >> 24;
		xdm_data[12] = saddr.sin_port;
		xdm_data[13] = saddr.sin_port >> 8;
	    }
	    /* and add current time */
	    time_now = time(NULL);
	    xdm_data[14] = time_now >> 24;
	    xdm_data[15] = time_now >> 16;
	    xdm_data[16] = time_now >> 8;
	    xdm_data[17] = time_now;

	    XdmcpWrap(xdm_data, &real_xauth->data[8], &msg[32], 24);

            if (fwdx_redirect(channel, (char *)msg, 56) < 0) {
                fwdx_sent_xauth[channel] = 1;
                return(-1);
            } else {
                fwdx_sent_xauth[channel] = 1;
                return(12);     
            }
#endif /* FWDX_XDM */
        } else {
            fwdx_sent_xauth[channel] = 1;
            return(0);        /* we do not know how to handle this type yet */
        }
    }

  auth_err:
    return(-1);
}

int fwdx_redirect(unsigned short channel, unsigned char *data, int len)
{
    int n = 0;
    
    if (fwdx_sockets && (channel < num_channels) && (fwdx_sockets[channel] >= 0)) {
	while (n < len) {
	    int r = write(fwdx_sockets[channel], data + n, len - n);
	    if (r < 0) {
	    	if (errno != EWOULDBLOCK && errno != EINTR) {
		    unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_CLOSE }, *p;
		    fwdx_close_channel(channel);
		    p = fwdx_add_quoted_twobyte(sb + 4, channel);
	    	    sprintf(p, "%c%c", IAC, SE);	/* safe */
	    	    p += 2;
		    if (p - sb < NETROOM()) {
		    	ring_supply_data(&netoring, sb, p - sb);
		    	printsub('>', sb + 2, p - sb - 2);
	    	    }
		    return -1;
		}
	    }
	    else
	    	n += r;
	}
    }
    return 0;
}

void fwdx_cleanup(void)
{
    int c;
    
    if (fwdx_sockets) {
    	for (c = 0; c < num_channels; c++)
	    if (fwdx_sockets[c] > -1)
	    	close(fwdx_sockets[c]);
    	free(fwdx_sockets);
	fwdx_sockets = NULL;
    }
    if (fwdx_sent_xauth) {
    	free(fwdx_sent_xauth);
	fwdx_sent_xauth = NULL;
    }
    if (fwdx_sbdata) {
    	free(fwdx_sbdata);
	fwdx_sbdata = NULL;
    }
    if (real_xauth) {
    	XauDisposeAuth(real_xauth);
	real_xauth = NULL;
    }
}

#endif /* FWD_X */
