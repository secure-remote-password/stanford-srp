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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef FWD_X

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) Peter 'Luna' Runestig 1999, 2000 <peter@runestig.com>.\n";
#endif /* not lint */

#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include "telnetd.h"
#include "Xauth.h"

#ifdef FWDX_UNIX_SOCK
# ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#  include <dirent.h>
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

#ifdef HAVE_SRP
#include <t_pwd.h>
#endif /* HAVE_SRP */

#ifdef KRB5
#include <krb5.h>
#endif /* KRB5 */

#ifdef TLS
#define SEND  tls_send
#define WRITE tls_write
#define READ  tls_read
#else
#define SEND  send
#define WRITE write
#define READ  read
#endif

#ifdef FWDX_XDM
void XdmcpUnwrap(
     unsigned char  *input,
     unsigned char  *wrapper,
     unsigned char  *output,
     int             bytes);
#endif /* FWDX_XDM */

#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif /* MAXPATHLEN */

extern int net; /* the socket */

unsigned char buffer[BUFSIZ], fwdx_options[255], *fwdx_sbdata = NULL;
int fwdx_listen_sock = -1, *fwdx_sockets = NULL, fwdx_sbdata_size = sizeof(buffer) * 2 + 10;
unsigned char **fwdx_blocked_data = NULL;
int * fwdx_blocked_len=NULL;
int xclient_byteorder_msb = -1, *authorized_channels = NULL, srand_done = 0;
int fwdx_disable_flag = 0, xauth_cookie_disable_flag = 0;
unsigned short num_channels = 0;
char *fwdx_xauthfile = NULL, fwdx_display[18] = ""; /* XXX.XXX.XXX.XXX:X is the largest */
Xauth xauth_cookie;

#ifdef FWDX_UNIX_SOCK
char *fwdx_unix_sock_name = NULL;
#endif /* FWDX_UNIX_SOCK */

#ifdef FWDX_XDM
Xauth xauth_xdm;
int xauth_xdm_disable_flag = 0;
#endif /* FWDX_XDM */

void fwdx_init(void)
{
    memset(fwdx_options, 0, sizeof(fwdx_options));
    memset(&xauth_cookie, 0, sizeof(xauth_cookie));
#ifdef FWDX_XDM
    memset(&xauth_xdm, 0, sizeof(xauth_xdm));
#endif /* FWDX_XDM */
}

int fwdx_listen_inet(void)
/* returns the display number (tcp port - 6000) or -1 if error */
{
    unsigned int n;
    struct sockaddr_in saddr = { AF_INET }, my_saddr;
    int len = sizeof(my_saddr), err, ret = -1;

    fwdx_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (fwdx_listen_sock < 0)
    	return -1;

    /* set up the listening ip address */
    saddr.sin_addr.s_addr = ntohl(INADDR_ANY);  /* last resort setup: listen on all addrs */
#ifdef FWDX_LOOPBACK
    /* use the loopback ip address (127.0.0.1) */
    saddr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
#else
    /* only listen on same ip address as the telnet client is connected to */
    err = getsockname(net, (struct sockaddr *) &my_saddr, &len);
    if (err == 0)
	saddr.sin_addr.s_addr = my_saddr.sin_addr.s_addr;
#endif /* FWDX_LOOPBACK */
    
    /* loop through the X ports and pick the first available one */
    for (n = 6001; n < 6256; n++) {
	saddr.sin_port = htons((u_short) n);
	if (bind(fwdx_listen_sock, (struct sockaddr *) &saddr, sizeof(saddr)) == 0) {
	    if (listen(fwdx_listen_sock, 10) == 0) {
	    	ret = n - 6000;
		break;
	    }
	}
    }
    if (ret == -1) {	/* didn't find a free display (!) */
	close(fwdx_listen_sock);
	fwdx_listen_sock = -1;
    } else {		/* ei okei */
	/* build the client's $DISPLAY */
	char *buf = inet_ntoa(saddr.sin_addr);
	if (buf == NULL)
	    buf = "127.0.0.1";
/*	char buf[16] = "";*/
/*	inet_ntop(AF_INET, &saddr.sin_addr.s_addr, buf, sizeof(buf));*/
	snprintf(fwdx_display, sizeof(fwdx_display), "%s:%d", buf, ret);
	setenv("DISPLAY", fwdx_display, 1);
    }
    return ret;
}

#ifdef FWDX_UNIX_SOCK
#ifndef SUN_LEN
#define SUN_LEN(ptr) \
	(((size_t) (((struct sockaddr_un *) 0)->sun_path) + strlen((ptr)->sun_path)))
#endif /* !SUN_LEN */
int fwdx_listen_unix(char *prefix)
/* returns the display number (/tmp/.X11-unix/Xn) or -1 if error */
{
    unsigned int n;
    struct sockaddr_un saddr = { AF_UNIX };
    int len, ret = -1;

    if (!(fwdx_unix_sock_name = malloc(30)))
	return -1;
    fwdx_listen_sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fwdx_listen_sock < 0)
    	return -1;

    /* loop through the X ports and pick the first available one */
    for (n = 1; n < 256; n++) {
	snprintf(fwdx_unix_sock_name, 30, "%s%d", prefix, n);
	strncpy(saddr.sun_path, fwdx_unix_sock_name, sizeof(saddr.sun_path));
	if (bind(fwdx_listen_sock, (struct sockaddr *) &saddr,
#ifdef SUN_LEN
		 SUN_LEN(&saddr)
#else
		 sizeof(saddr)
#endif
		 ) == 0) {
	    if (listen(fwdx_listen_sock, 10) == 0) {
	    	ret = n;
		break;
	    }
	}
    }
    if (ret == -1) {	/* didn't find a free display (!) */
	close(fwdx_listen_sock);
	fwdx_listen_sock = -1;
    } else {		/* ei okei */
	/* build the client's $DISPLAY */
	snprintf(fwdx_display, sizeof(fwdx_display), ":%d", ret);
	if (setenv("DISPLAY", fwdx_display, 1) < 0)
	    return -1;
	/* change permission mask to 600 */
	chmod(fwdx_unix_sock_name, S_IRUSR | S_IWUSR);
    }
    return ret;
}
#endif /* FWDX_UNIX_SOCK */

int fwdx_listen(void)
/* returns the display number or -1 if error */
{
#ifdef FWDX_UNIX_SOCK
    /* first, check if the '/tmp/.X11-unix' directory exists. if it doesn't,
     * maybe the system doesn't support X with unix domain sockets after all,
     * and we should try using inet sockets instead.
     */
    DIR *dir;
    if ((dir = opendir("/tmp/.X11-unix")) != NULL) {
	closedir(dir);
	return fwdx_listen_unix("/tmp/.X11-unix/X");
    } else if ((dir = opendir("/var/spool/sockets/X11")) != NULL) {	/* HP-UX */
	closedir(dir);
	return fwdx_listen_unix("/var/spool/sockets/X11/");
    } else
	return fwdx_listen_inet();
#else
    return fwdx_listen_inet();
#endif /* FWDX_UNIX_SOCK */
}

void fwdx_disable_xauth_type(char *optarg)
{
#ifdef HAVE_STRICMP
#  define STRCMP stricmp
#else
#  ifdef HAVE_STRCASECMP
#    define STRCMP strcasecmp
#  else
#    define STRCMP strcmp
#  endif
#endif
    
    if (!STRCMP(optarg, "MIT-MAGIC-COOKIE-1"))
	xauth_cookie_disable_flag = 1;
#ifdef FWDX_XDM
    else if (!STRCMP(optarg, "XDM-AUTHORIZATION-1"))
	xauth_xdm_disable_flag = 1;
#endif /* FWDX_XDM */
}

void fwdx_close_channel(unsigned short channel)
{
    if (fwdx_sockets && channel < num_channels) {
    	if (fwdx_sockets[channel] != -1)
    	    close(fwdx_sockets[channel]);
	fwdx_sockets[channel] = -1;
        authorized_channels[channel] = 0;
        if ( fwdx_blocked_data[channel] ) {
            free(fwdx_blocked_data[channel]);
            fwdx_blocked_data[channel] = NULL;
        }
    }
}

unsigned int fwdx_random(void)
{
    int n;
    unsigned int rv;
    FILE *rf;
    
#ifdef HAVE_SRP
    t_random((unsigned char *) &rv, sizeof(unsigned int));
    return rv;
#elif defined(TLS)
    if (RAND_bytes(&rv, sizeof(unsigned int)) > 0)
	return rv;
#elif defined(KRB5)
    {
        extern krb5_context telnet_context;
        krb5_data d;
        krb5_error_code code;

        d.data = (char *)&rv;
        d.length = sizeof(unsigned int);
        code = krb5_c_random_make_octets(telnet_context, &d);
        if ( !code )
            return(rv);
    }
#else /* KRB5 */
    rf = fopen("/dev/urandom", "rb");
    if (rf) {
	int rc = fread(&rv, 1, sizeof(rv), rf);
	fclose(rf);
	if (rc == sizeof(rv))
	    return rv;
    }
#endif
    return rv;
}

int create_fake_mit_magic_cookie_xauth()
{
    unsigned int c;

    xauth_cookie.name = "MIT-MAGIC-COOKIE-1";
    xauth_cookie.name_length = strlen(xauth_cookie.name);
    xauth_cookie.data = malloc(16);
    xauth_cookie.data_length = 16;
    if (!xauth_cookie.data)
	return 1;

    if ( !srand_done ) {
	srand(fwdx_random());
        srand_done = 1;
    }
    for (c = 0; c < xauth_cookie.data_length; c++)
    	xauth_cookie.data[c] = (unsigned char)rand();
    return 0;
}

#ifdef FWDX_XDM
static const unsigned char odd_parity[256]={
  1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
};

int create_fake_xdm_authorization_xauth()
{
    unsigned int c;

    xauth_xdm.name = "XDM-AUTHORIZATION-1";
    xauth_xdm.name_length = strlen(xauth_xdm.name);
    xauth_xdm.data = malloc(16);
    xauth_xdm.data_length = 16;
    if (!xauth_xdm.data)
	return 1;

    if ( !srand_done ) {
	srand(fwdx_random());
        srand_done = 1;
    }
    for (c = 0; c < xauth_xdm.data_length; c++)
    	xauth_xdm.data[c] = (unsigned char)rand();
    /* DES keys are 8 bytes, 56-bits.  MSB of each byte is odd parity bit */
    for (c = 0; c < 8 ; c++)
    	xauth_xdm.data[c] = odd_parity[xauth_xdm.data[c]];
    return 0;
}
#endif /* FWDX_XDM */

/* returns the number of bytes of 'data' that were absorbed */
/* by the authorize procedure.                              */
int fwdx_authorize(int channel, unsigned char * data, int len)
{
    /* XXX maybe we should have some retry handling if not the whole first
     * authorization packet arrives complete
     */
    
    if (!authorized_channels[channel]) {
        int name_len, data_len;

        if (len < 12)
            return -1;

        /* Parse the lengths of variable-length fields. */
        if (data[0] == 0x42) {		/* byte order MSB first. */
	    xclient_byteorder_msb = 1;
            if ( data[1] != 0x00 ||
                 data[2] != 0x00 ||
                 data[3] != 0x0B ||
                 data[4] != 0x00 ||
                 data[5] != 0x00 )
                return -2;             /* Not an Xauth msg */
            name_len = (data[6] << 8) + data[7];
            data_len = (data[8] << 8) + data[9];
        } else if (data[0] == 0x6c) {	/* Byte order LSB first. */
	    xclient_byteorder_msb = 0;
            if ( /*data[1] != 0x00 ||*/ /* XXX data[1] is 123 (I think) on Solaris 8! */
                 data[2] != 0x0B ||
                 data[3] != 0x00 ||
                 data[4] != 0x00 ||
                 data[5] != 0x00 )
                return -3;             /* Not an Xauth msg */

            name_len = data[6] + (data[7] << 8);
            data_len = data[8] + (data[9] << 8);
        } else {
            /* bad byte order byte */
            return -4;
        }

	/* we demand _some_ X authorization */
	if (!name_len || !data_len)
	    return -5;

        /* Check if the whole packet is in buffer. */
        if (len < 12 + ((name_len + 3) & ~3) + ((data_len + 3) & ~3))
            return -6;

        /* XXX - this code needs to be changed to handle multiple */
        /* authentication types. */

        /* Check if authentication protocol matches. */
        if (name_len == xauth_cookie.name_length &&
             memcmp(data + 12, xauth_cookie.name, name_len) == 0) 
        {
            /* MIT-MAGIC-COOKIES-1 */

            /* Check if authentication data matches our cookie data. */
            if (data_len != xauth_cookie.data_length ||
                 memcmp(data + 12 + ((name_len + 3) & ~3),
                         xauth_cookie.data, xauth_cookie.data_length) != 0) {
                /* auth data does not match cookie data */
                return -7;
            }
        }
#ifdef FWDX_XDM
        else if (name_len == xauth_xdm.name_length &&
             memcmp(data + 12, xauth_xdm.name, name_len) == 0) 
        {
            /* XDM-AUTHORIZATION-1 */
	    unsigned char output[24];	/* 192 bits */
	    struct sockaddr_in saddr;
	    int saddr_len = sizeof(saddr);
	    time_t time_here, time_there;
            
	    if (data_len != 24)		/* 192 bits */
		return -8;
	    XdmcpUnwrap(data + 12 + ((name_len + 3) & ~3), &xauth_xdm.data[8],
			output, 24);

	    /* in 'output' we now have: 8 byte "authenticator" (should match the
	     * first 8 byte in xauth_xdm.data), 4 byte peer address, 2 byte peer
	     * port and 10 byte "current time in seconds" (4 bytes time and 6 byte
	     * zero padding to make it 10 byte), all network byte order */
	    /* first, check authenticator: */
	    if (memcmp(output, xauth_xdm.data, 8))
		return -9;

#ifdef FWDX_UNIX_SOCK /* XXX How is this _really_ been done with local sockets? */
	    if (fwdx_unix_sock_name == NULL) {  /* using inet sock anyway */
#endif /* FWDX_UNIX_SOCK */
	    /* then, check peer's ip addr / port */
	    getpeername(fwdx_sockets[channel], (struct sockaddr *)&saddr, &saddr_len);
	    /* members of saddr has network byte order in memory */
	    if (memcmp(output + 8, &saddr.sin_addr.s_addr, 4) ||
		memcmp(output + 12, &saddr.sin_port, 2))
		return -10;
#ifdef FWDX_UNIX_SOCK
	    }
#endif /* FWDX_UNIX_SOCK */
	    
	    /* and then, check the current time value. since it's all on the
	     * same machine, it should be fairly alike */
	    time_here = time(NULL);
	    time_there = (output[14] << 24) + (output[15] << 16) +
		(output[16] << 8) + output[17];
	    if ((time_there - time_here > 10) || (time_here - time_there > 10))
		return -11;
        }
#endif /* FWDX_XDM */
        else {
            /* authentication protocol is not supported */
            return -12;
        }

        /* X authentication data has been verified        */
        authorized_channels[channel] = 1;

        /* Send a null xauth message to the telnet client */
        {
            char xauth_dummy[12];
            memset(xauth_dummy,0,12);
            if (data[0] == 0x42) {
                xauth_dummy[0] = 0x42;      /* MSB order */
                xauth_dummy[3] = 0x0b;      /* Xauth data */
            } else {
                xauth_dummy[0] = 0x6c;      /* LSB order */
                xauth_dummy[2] = 0x0b;      /* Xauth data */
            }
            fwdx_forward(channel, xauth_dummy, 12);
        }
        return(12 + ((name_len + 3) & ~3) + ((data_len + 3) & ~3));
    }
    return(0);
}

int fwdx_write_xauthfile(void)
{
    int dpynum, scrnum, family;
    char myhost[300], *host, *rest = NULL;
    FILE *file;
    struct sockaddr_in saddr;
    int saddr_len;
    struct hostent *hi;
    unsigned long haddr;

    if (!fwdx_display && !fwdx_xauthfile)
    	return 1;
    if (!parse_displayname(fwdx_display, &family, &host, &dpynum, &scrnum, &rest))
    	return 2;
    if (rest) free(rest);
    
    if (family != FamilyInternet
#ifdef FWDX_UNIX_SOCK
		&& family != FamilyLocal
#endif /* FWDX_UNIX_SOCK */
	    				)
    	return 3;

    if (!(file = fopen(fwdx_xauthfile, "wb")))
    	return 8;

    /* X connections to localhost:1 is actually treated as local unix sockets,
     * see the 'xauth' man page.
     */

    /* MIT-MAGIC-COOKIE-1 */
    if (!xauth_cookie_disable_flag) {
	
	create_fake_mit_magic_cookie_xauth();

	/* the display number is written as a string, not numeric */
	if (!(xauth_cookie.number = malloc(5)))
	    return 7;
	snprintf(xauth_cookie.number, 5, "%u", dpynum);
	xauth_cookie.number_length = strlen(xauth_cookie.number);

#ifdef FWDX_UNIX_SOCK
	if (fwdx_unix_sock_name == NULL) {  /* using inet sock anyway */
#endif /* FWDX_UNIX_SOCK */
	/* First store an Internet Cookie */
	xauth_cookie.family = FamilyInternet;

	saddr_len = sizeof(saddr);
	if (!getsockname(0, (struct sockaddr *)&saddr,&saddr_len)) {
	    xauth_cookie.address_length = 4;
	    if (!(xauth_cookie.address = malloc(xauth_cookie.address_length)))
		return 6;
	    haddr = (unsigned long) saddr.sin_addr.s_addr;
	    memcpy(xauth_cookie.address, &haddr, xauth_cookie.address_length);
	}

	if (!XauWriteAuth(file, &xauth_cookie))
	    return 9;
	free(xauth_cookie.address);
#ifdef FWDX_UNIX_SOCK
	}
#endif /* FWDX_UNIX_SOCK */

	/* And then a second time as a FamilyLocal */
	xauth_cookie.family = FamilyLocal;

	if (gethostname(myhost, sizeof(myhost) - 1))
	    return 5;
	xauth_cookie.address_length = strlen(myhost);
	if (!(xauth_cookie.address = malloc(xauth_cookie.address_length)))
            return 6;
        memcpy(xauth_cookie.address, myhost, xauth_cookie.address_length);

	if (!XauWriteAuth(file, &xauth_cookie))
	    return 9;

    }

#ifdef FWDX_XDM
    /* XDM-AUTHORIZATION-1 */
    if (!xauth_xdm_disable_flag) {

	create_fake_xdm_authorization_xauth();

	/* the display number is written as a string, not numeric */
	if (!(xauth_xdm.number = malloc(5)))
	    return 7;
	snprintf(xauth_xdm.number, 5, "%u", dpynum);
	xauth_xdm.number_length = strlen(xauth_xdm.number);

#ifdef FWDX_UNIX_SOCK
	if (fwdx_unix_sock_name == NULL) {  /* using inet sock anyway */
#endif /* FWDX_UNIX_SOCK */
	/* First store an Internet Cookie */
	xauth_xdm.family = FamilyInternet;

	saddr_len = sizeof(saddr);
	if (!getsockname(0, (struct sockaddr *)&saddr,&saddr_len)) {
	    xauth_xdm.address_length = 4;
	    if (!(xauth_xdm.address = malloc(xauth_xdm.address_length)))
		return 6;
	    haddr = (unsigned long) saddr.sin_addr.s_addr;
	    memcpy(xauth_xdm.address, &haddr, xauth_xdm.address_length);
	}

	if (!XauWriteAuth(file, &xauth_xdm))
	    return 9;
	free(xauth_xdm.address);
#ifdef FWDX_UNIX_SOCK
	}
#endif /* FWDX_UNIX_SOCK */

	/* And then a second time as a FamilyLocal */
	xauth_xdm.family = FamilyLocal;

	if (gethostname(myhost, sizeof(myhost) - 1))
	    return 5;
	xauth_xdm.address_length = strlen(myhost);
	if (!(xauth_xdm.address = malloc(xauth_xdm.address_length)))
            return 6;
        memcpy(xauth_xdm.address, myhost, xauth_xdm.address_length);

	if (!XauWriteAuth(file, &xauth_xdm))
	    return 9;

    }
#endif /* FWDX_XDM */

    fclose(file);
    setenv("XAUTHORITY", fwdx_xauthfile, 1);
    return 0;
}

int fwdx_setup_xauth()
{
    int xauthfd;
    
    /* Setup to always have a local .Xauthority. */
    fwdx_xauthfile = malloc(MAXPATHLEN);
    if (!fwdx_xauthfile)
	return 5;
    snprintf(fwdx_xauthfile, MAXPATHLEN, "/tmp/XauthXXXXXX");
    if ((xauthfd = mkstemp(fwdx_xauthfile)) != -1)
    	/* we change file ownership later, when we know who is to be owner! */
	close(xauthfd);
    else {
	free(fwdx_xauthfile);
	fwdx_xauthfile = NULL;
	return 6;
    }
    /* we must have the subshell's new DISPLAY env var to write xauth to xauthfile */
    if (strlen(fwdx_display))
    	if (fwdx_write_xauthfile())
	    return 7;

    return 0;
}

void fwdx_set_xauthfile_owner(int uid, int gid)
{
    if (!fwdx_xauthfile)
    	return;
    chown(fwdx_xauthfile, uid, gid);
#ifdef FWDX_UNIX_SOCK
    if (fwdx_unix_sock_name)
	chown(fwdx_unix_sock_name, uid, gid);
#endif /* FWDX_UNIX_SOCK */
}

void fwdx_do_client_options(unsigned char *sp, int len)
/* called with 'len' option bytes, starting at 'sp' */
{
    if (len == 1 && *sp == 0)
    	return;
    /* we don't support any more options, so we skip the rest */
}

int add_to_nob(unsigned char *data, int len)
/* adds data to netobuf with overflow check */
{
    int nob_room = netobuf + netobuf_size - nfrontp;

    if (len <= nob_room) {
	memmove(nfrontp, data, len);
	nfrontp += len;
	return len;
    } else {
	memmove(nfrontp, data, nob_room);
	nfrontp += nob_room;
        syslog(LOG_ERR, "Attempt to overwrite netobuf occured");
	return nob_room;
    }

}

void fwdx_send_options(void)
{
    unsigned char sb[255] = { IAC, SB, TELOPT_FORWARD_X, FWDX_OPTIONS }, *p = sb + 4;

    *p = 0;                     /* No options are currently defined */
    p++;
    sprintf(p, "%c%c", IAC, SE);	/* safe */
    p += 2;
    add_to_nob(sb, p - sb);
    DIAG(TD_OPTIONS, printsub('>', sb + 2, p - sb - 2););
}

unsigned char *fwdx_add_quoted_channel(unsigned char *p, unsigned short channel)
/* adds the IAC quoted representation of 'channel' at buffer pointer 'p',
 * returning pointer to new buffer position. NO OVERFLOW CHECK!
 */
{
    *p++ = (unsigned char)((channel >> 8) & 0xFF);
    if (*(p - 1) == 0xFF)
    	*p++ = 0xFF;
    *p++ = (unsigned char)(channel & 0xFF);
    if (*(p - 1) == 0xFF)
    	*p++ = 0xFF;
    return p;
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
	    	    unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_CLOSE };
		    fwdx_sbdata_size = 0;
	    	    fwdx_close_channel(channel);
		    p = fwdx_add_quoted_channel(sb + 4, channel);
	    	    sprintf(p, "%c%c", IAC, SE);	/* safe */
	    	    p += 2;
		    add_to_nob(sb, p - sb);
	    	    DIAG(TD_OPTIONS, printsub('>', sb + 2, sizeof(sb) - 2););
   		    netflush();
		    return;
		    }

	    p = fwdx_sbdata;
	    sprintf(p, "%c%c%c%c", IAC, SB, TELOPT_FORWARD_X, FWDX_DATA);  /* safe */
	    p += 4;
	    p = fwdx_add_quoted_channel(p, channel);
	    for (c = 0; c < len; c++) {
	    	*p++ = data[c];
	    	if (data[c] == 0xFF)
		    *p++ = 0xFF;
	    }
	    sprintf(p, "%c%c", IAC, SE);	/* safe */
	    p += 2;
	    
	    left = p - fwdx_sbdata;	/* how much left to send */
	    while (left) {
	    	obsize = netobuf_size - (nfrontp - netobuf); /* how much space in netobuf */
		if (left > obsize) {
		    memmove(nfrontp, fwdx_sbdata + idx, obsize);
		    nfrontp += obsize;
		    idx += obsize;
		    left -= obsize;
		} else {
		    memmove(nfrontp, fwdx_sbdata + idx, left);
		    nfrontp += left;
		    left = 0;
		}
		netflush();
	    }
	    DIAG(TD_OPTIONS, printsub('>', fwdx_sbdata + 2, p - fwdx_sbdata - 2););
	}	
}

void fwdx_send_xauth_error_to_xclient(socket, string)
    int socket; char *string;
{
    unsigned char msg[255];
    int msglen, n, len = strlen(string);

    if (xclient_byteorder_msb < 0)
	return;		/* unexpected */
    memset(msg, 0, sizeof(msg));
    /* maximize string length to (say) 200 */
    if (len > 200)
	len = 200;
    msglen = (8 + len + 3) & ~3;	/* total message length in even 4-byte blocks units */
    n = (msglen - 8) / 4;		/* length in 4-byte units of "additional data" */

    /* fill in the error message */
    /* for documentation about this, see page 113 in
     * "X Window System Protocol / X Consortion Standard / X Version 11, Release 6.4"
     * available at ftp://ftp.x.org/pub/R6.4/xc/doc/hardcopy/XProtocol/proto.PS.gz */
    msg[0] = 0;		/* 0 means "error" */
    msg[1] = (unsigned char) len;
    if (xclient_byteorder_msb) {
	msg[3] = 11;	/* protocol-major-version */
	msg[6] = n >> 8;
	msg[7] = n & 0xFF;
    } else {
	msg[2] = 11;	/* protocol-major-version */
	msg[6] = n & 0xFF;
	msg[7] = n >> 8;
    }
    
    memcpy(msg + 8, string, len);
    write(socket, msg, msglen);
}

void fwdx_check_sockets(fd_set *ibits, fd_set *obits)
{
    unsigned short c;

    if (fwdx_sockets) {
    	for (c = 0; c < num_channels; c++) {
	    if (fwdx_sockets[c] > -1) {
                int r = 1;
                if (FD_ISSET(fwdx_sockets[c], ibits)) {
                    r = read(fwdx_sockets[c], buffer, sizeof(buffer));
                    if (r > 0) {
                        int r2 = fwdx_authorize(c, buffer, r);
                        if (r2 >= 0) {
                            if (r - r2 > 0)
                                fwdx_forward(c, &buffer[r2], r-r2);
                        } else {
                            /* fwdx_authorize() failed */
			    char errmsg[50];
			    snprintf(errmsg, sizeof(errmsg), "Forward X authentication error %d", -r2);
                            fwdx_send_xauth_error_to_xclient(fwdx_sockets[c], errmsg);
                            r = -1;
                        }
                    } 
                } else if (FD_ISSET(fwdx_sockets[c], obits)) {
                    r = fwdx_redirect(c,fwdx_blocked_data[c],fwdx_blocked_len[c]);
                    if (r >= 0) {
                        unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_XON }, *p;
                        p = fwdx_add_quoted_channel(sb + 4, c);
                        sprintf(p, "%c%c", IAC, SE);	/* safe */
                        p += 2;
                        add_to_nob(sb, p - sb);
                        DIAG(TD_OPTIONS, printsub('>', sb + 2, sizeof(sb) - 2););
                        netflush();

                        free(fwdx_blocked_data[c]);
                        fwdx_blocked_data[c]=NULL;
                        fwdx_blocked_len[c]=0;
                        r = 1;
                    }
                }

                if (r <= 0 && errno != EWOULDBLOCK) {
                    unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_CLOSE }, *p;
                    fwdx_close_channel(c);
                    p = fwdx_add_quoted_channel(sb + 4, c);
                    sprintf(p, "%c%c", IAC, SE);	/* safe */
                    p += 2;
                    add_to_nob(sb, p - sb);
                    DIAG(TD_OPTIONS, printsub('>', sb + 2, sizeof(sb) - 2););
                    netflush();
                }
	    }
        }
    }

    if (fwdx_listen_sock > -1 && FD_ISSET(fwdx_listen_sock, ibits)) {
	unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_OPEN }, *p;
    	struct sockaddr_in saddr;
	int slen = sizeof(saddr), on = 1;
	
	if (fwdx_sockets)
	    fwdx_sockets = realloc(fwdx_sockets, (num_channels + 1) * sizeof(int));
	else
	    fwdx_sockets = malloc(sizeof(int));
	if (!fwdx_sockets)
	    return;

	if (authorized_channels)
	    authorized_channels = realloc(authorized_channels,
					  (num_channels + 1) * sizeof(int));
	else
	    authorized_channels = malloc(sizeof(int));
	if (!authorized_channels)
	    return;
        authorized_channels[num_channels] = 0;

	if (fwdx_blocked_len)
	    fwdx_blocked_len = realloc(fwdx_blocked_len, (num_channels + 1) * sizeof(int));
	else
	    fwdx_blocked_len = malloc(sizeof(int));
	if (!fwdx_blocked_len)
	    return;
        fwdx_blocked_len[num_channels] = 0;

	if (fwdx_blocked_data)
	    fwdx_blocked_data = realloc(fwdx_blocked_data,
					(num_channels + 1) * sizeof(char *));
	else
	    fwdx_blocked_data = malloc(sizeof(char *));
	if (!fwdx_blocked_data)
	    return;
        fwdx_blocked_data[num_channels] = NULL;

	fwdx_sockets[num_channels] = accept(fwdx_listen_sock,
					    (struct sockaddr *) &saddr, &slen);
	if (fwdx_sockets[num_channels] < 0)
	    return;

        /* Set socket to non-blocking I/O */
        ioctl(fwdx_sockets[num_channels],FIONBIO,&on);

	p = fwdx_add_quoted_channel(sb + 4, num_channels);
	sprintf(p, "%c%c", IAC, SE);	/* safe */
	p += 2;
	/* send it off */
	add_to_nob(sb, p - sb);
	DIAG(TD_OPTIONS, printsub('>', sb + 2, sizeof(sb) - 2););
	netflush();
	num_channels++;
    }
}

int fwdx_max_socket(int nfd)
/* return the highest value socket number */
{
    int c, rv = nfd;

    if (fwdx_listen_sock > rv)
	rv = fwdx_listen_sock;
    if (fwdx_sockets)
    	for (c = 0; c < num_channels; c++)
	    if (fwdx_sockets[c] > rv)
		rv = fwdx_sockets[c];
    return rv;
}

void fwdx_init_fd_set(fd_set *ibits, fd_set *obits)
{
    int c;
    
    if (fwdx_listen_sock > -1)
    	FD_SET(fwdx_listen_sock, ibits);
    if (fwdx_sockets) {
    	for (c = 0; c < num_channels; c++) {
	    if (fwdx_sockets[c] > -1) {
                if (fwdx_blocked_data[c] == NULL)
                    FD_SET(fwdx_sockets[c], ibits);
                else
                    FD_SET(fwdx_sockets[c], obits);
            }
        }
    }
}

int fwdx_redirect(unsigned short channel, unsigned char *data, int len)
{
    int n = 0;
    
    if (fwdx_sockets && (channel < num_channels) && (fwdx_sockets[channel] >= 0)) {
	while (n < len) {
	    int r = write(fwdx_sockets[channel], data + n, len - n);
	    if (r < 0) {
                /* Try to handle EWOULDBLOCK.  If we can't handle it */
                /* treat it as a fatal error.                        */
	    	if (errno == EWOULDBLOCK) {
                    if ( fwdx_blocked_data[channel] == NULL ) {
                        unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_XOFF }, *p;
                        p = fwdx_add_quoted_channel(sb + 4, channel);
                        sprintf(p, "%c%c", IAC, SE);	/* safe */
                        p += 2;
                        add_to_nob(sb, p - sb);
                        DIAG(TD_OPTIONS, printsub('>', sb + 2, sizeof(sb) - 2););
                        netflush();

                        fwdx_blocked_data[channel] = malloc(len-n);
                        if ( fwdx_blocked_data[channel] ) {
                            memcpy(fwdx_blocked_data[channel],data+n,len-n);
                            fwdx_blocked_len[channel] = len-n;
                            return(0);
                        }
                    } else if ( fwdx_blocked_data[channel] == data ) {
                        return(0);
                    } else {
                        fwdx_blocked_data[channel] = 
                            realloc(fwdx_blocked_data[channel],fwdx_blocked_len[channel]+len-n);
                        if ( fwdx_blocked_data[channel] ) {
                            memcpy(fwdx_blocked_data[channel]+fwdx_blocked_len[channel],data,len-n);
                            fwdx_blocked_len[channel] += len-n;
                            return(0);
                        }
                    }
                }
                
                if (errno != EINTR) {
		    unsigned char sb[10] = { IAC, SB, TELOPT_FORWARD_X, FWDX_CLOSE }, *p;
		    fwdx_close_channel(channel);
		    p = fwdx_add_quoted_channel(sb + 4, channel);
		    sprintf(p, "%c%c", IAC, SE);	/* safe */
		    p += 2;
		    add_to_nob(sb, p - sb);
		    DIAG(TD_OPTIONS, printsub('>', sb + 2, sizeof(sb) - 2););
		    netflush();
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
    
    if (fwdx_listen_sock > -1)
    	close(fwdx_listen_sock);
    if (fwdx_sockets) {
    	for (c = 0; c < num_channels; c++)
	    if (fwdx_sockets[c] > -1)
	    	close(fwdx_sockets[c]);
    	free(fwdx_sockets);
	fwdx_sockets = NULL;
    }
    if (authorized_channels) {
    	free(authorized_channels);
	authorized_channels = NULL;
    }
    if (fwdx_blocked_data) {
    	for (c = 0; c < num_channels; c++)
	    if (fwdx_blocked_data[c] != NULL)
                free(fwdx_blocked_data[c]);
        free(fwdx_blocked_data);
	fwdx_blocked_data = NULL;
    }
    if (fwdx_blocked_len) {
    	free(fwdx_blocked_len);
	fwdx_blocked_len = NULL;
    }
    if (fwdx_sbdata) {
    	free(fwdx_sbdata);
	fwdx_sbdata = NULL;
    }
    if (fwdx_xauthfile) {
    	unlink(fwdx_xauthfile);
    	free(fwdx_xauthfile);
	fwdx_xauthfile = NULL;
    }
    if (xauth_cookie.address)	free(xauth_cookie.address);
    if (xauth_cookie.number)	free(xauth_cookie.number);
    if (xauth_cookie.data)	free(xauth_cookie.data);
    memset(&xauth_cookie, 0, sizeof(xauth_cookie));

#ifdef FWDX_XDM
    if (xauth_xdm.address)	free(xauth_cookie.address);
    if (xauth_xdm.number)	free(xauth_xdm.number);
    if (xauth_xdm.data)		free(xauth_xdm.data);
    memset(&xauth_xdm, 0, sizeof(xauth_xdm));
#endif /* FWDX_XDM */
#ifdef FWDX_UNIX_SOCK
    if (fwdx_unix_sock_name) {
    	unlink(fwdx_unix_sock_name);
    	free(fwdx_unix_sock_name);
	fwdx_unix_sock_name = NULL;
    }
#endif /* FWDX_UNIX_SOCK */
}

#endif /* FWD_X */
