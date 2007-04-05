/*
 * Copyright (c) 1999 - 2001 Peter 'Luna' Runestig <peter@runestig.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Incorporated into the SRP Telnet distribution 10/19/2000 by
 * Tom Wu <tjw@cs.stanford.edu>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef TLS

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) Peter 'Luna' Runestig 1999 - 2001 <peter@runestig.com>.\n";
#endif /* not lint */

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#ifdef TLS_KRB5
#include <openssl/kssl.h>
#endif /* TLS_KRB5 */
#ifdef TLS_SESSION_FILE_CACHE
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/pem.h>
#endif /* TLS_SESSION_FILE_CACHE */
#include "ring.h"
#include "externs.h"

#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif /* MAXPATHLEN */

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) 0xffffffff)
#endif

#define MODE_ECHO		0x0200
#define MODE_EDIT		0x01
#define DEFAULTCIPHERLIST	"ALL:!EXP"

extern int	net;	/* the socket */
extern int	tin;	/* stdin */
extern char	*hostname;
#define SOCK_TO_SSL(s)		\
    ( tls_active ? ssl : NULL )

void	NetNonblockingIO(int fd, int onoff);
void	tls_cleanup(void);
void	tls_shutdown(void);
char	*strcasestr(const char *haystack, const char *needle);
char	*file_fullpath(char *fn);
int	x509rc_read_filenames(void);

int	tls_enabled = 1;
int 	tls_active = 0;
int	tls_debug = 0;
int 	tls_suspend_iacs = 0;
int 	tls_reset_state = 0;
int	tls_anon = 0;
int	verify_error_flag = 0, x509rc_override = 0;
BIO	*bout = NULL;
BIO	*sbio = NULL;
SSL 	*ssl = NULL;
SSL_CTX	*ssl_ctx = NULL;
SSL_METHOD *ssl_meth = NULL;
X509_STORE *crl_store = NULL;
char	*tls_key_file = NULL;
char	*tls_cert_file = NULL;
char	*tls_capath_dir = NULL;
char	*tls_cafile_file = NULL;
char	*tls_crl_file = NULL;
char	*tls_crl_dir = NULL;
char	*tls_rand_file = NULL;
char	*tls_hostname = NULL;	/* hostname used by user to connect */
char	tls_cipher_list[255] = DEFAULTCIPHERLIST;

#ifdef TLS_KRB5
#ifndef KRB5_SERVICE_NAME
#define KRB5_SERVICE_NAME  "host"
#endif
#endif 

void tls_set_cipher_list(char *list)
{
    snprintf(tls_cipher_list, sizeof(tls_cipher_list), "%s", list);
}

SSL_METHOD *tls_get_method()
{
  if(ssl_meth == NULL)
    ssl_meth = SSLv23_client_method();
  return ssl_meth;
}

void tls_optarg(char *optarg)
{
    char *p;

    if ((p = strchr(optarg, '='))) {
    	*p++ = 0;
	if (!strcmp(optarg, "cert")) {
	    tls_cert_file = strdup(p);
	    x509rc_override = 1;
	}
	else if (!strcmp(optarg, "key"))
	    tls_key_file = strdup(p);
	else if (!strcmp(optarg, "CAfile"))
	    tls_cafile_file = strdup(p);
	else if (!strcmp(optarg, "CApath"))
	    tls_capath_dir = strdup(p);
	else if (!strcmp(optarg, "crlfile"))
	    tls_crl_file = strdup(p);
	else if (!strcmp(optarg, "crldir"))
	    tls_crl_dir = strdup(p);
	else if (!strcmp(optarg, "cipher"))
	    tls_set_cipher_list(p);
    }
}

char **tls_get_SAN_objs(SSL *s, int type)
/* returns NULL or an array of malloc'ed objects of type `type' from the server's
 * subjectAltName, remember to free() them all!
 */
{
#define NUM_SAN_OBJS 50
    static char *objs[NUM_SAN_OBJS];
    char **rv = NULL;
    X509 *server_cert = NULL;
    int i, j;
    X509_EXTENSION *ext = NULL;
    STACK_OF(GENERAL_NAME) *ialt = NULL;
    GENERAL_NAME *gen = NULL;

    memset(objs, 0, sizeof(objs));
    if (server_cert = SSL_get_peer_certificate(s)) {
    	if ((i = X509_get_ext_by_NID(server_cert, NID_subject_alt_name, -1)) < 0)
	    goto eject;
	if (!(ext = X509_get_ext(server_cert, i)))
	    goto eject;
	/*X509V3_add_standard_extensions();*/
	if (!(ialt = X509V3_EXT_d2i(ext)))
	    goto eject;
	rv = objs;
	for (i = 0, j = 0; i < sk_GENERAL_NAME_num(ialt) && j < NUM_SAN_OBJS - 2; i++) {
	    gen = sk_GENERAL_NAME_value(ialt, i);
	    if (gen->type == type) {
		if(!gen->d.ia5 || !gen->d.ia5->length)
		    continue;
		objs[j] = malloc(gen->d.ia5->length + 1);
		if (objs[j]) {
		    memcpy(objs[j], gen->d.ia5->data, gen->d.ia5->length);
		    objs[j][gen->d.ia5->length] = 0;
		    j++;
		}
	    }
	    GENERAL_NAME_free(gen);
	}
	/*X509V3_EXT_cleanup();*/
    }
eject:
    if (ialt)		sk_GENERAL_NAME_free(ialt);
    if (server_cert)	X509_free(server_cert);
    return rv;
}

char *x509v3_subjectAltName_oneline(SSL *s, char *buf, int len)
{
    X509 *server_cert = NULL;
    X509_EXTENSION *ext = NULL;
    BIO *mem = NULL;
    char *data = NULL, *rv = NULL;

    if (server_cert = SSL_get_peer_certificate(s)) {
	int i, data_len = 0, ok;
    	if ((i = X509_get_ext_by_NID(server_cert, NID_subject_alt_name, -1)) < 0)
	    goto eject;
	if (!(ext = X509_get_ext(server_cert, i)))
	    goto eject;
	if (!(mem = BIO_new(BIO_s_mem())))
	    goto eject;
	
	ok = X509V3_EXT_print(mem, ext, 0, 0);
	if (ok)
	    data_len = BIO_get_mem_data(mem, &data);
	if (data) {
	    /* the 'data' returned is not '\0' terminated */
	    if (buf) {
		memcpy(buf, data, data_len < len ? data_len : len);
		buf[data_len < len ? data_len : len - 1] = 0;
		rv = buf;
		goto eject;
	    } else {
		char *b = malloc(data_len + 1);
		if (b) {
		    memcpy(b, data, data_len);
		    b[data_len] = 0;
		}
		rv = b;
		goto eject;
	    }
	} else
	    goto eject;
    }
eject:
    if (server_cert)	X509_free(server_cert);
    if (mem)		BIO_free(mem);
    return rv;
}

char *tls_get_commonName(SSL *s)
{
    static char name[256];
    int err = 0;
    X509 *server_cert;
    
    if (server_cert = SSL_get_peer_certificate(s)) {
    	err = X509_NAME_get_text_by_NID(X509_get_subject_name(server_cert),
		NID_commonName, name, sizeof(name));
	X509_free(server_cert);
    }
    if (err > 0)
    	return name;
    else
    	return NULL;
}

/* if we are using OpenSSL 0.9.6 or newer, we want to use X509_NAME_print_ex()
 * instead of X509_NAME_oneline().
 */
char *x509_name_oneline(X509_NAME *n, char *buf, int len)
{
#if OPENSSL_VERSION_NUMBER < 0x000906000
    return X509_NAME_oneline(n, buf, len);
#else
    BIO *mem = BIO_new(BIO_s_mem());
    char *data = NULL;
    int data_len = 0, ok;
    
    ok = X509_NAME_print_ex(mem, n, 0, XN_FLAG_ONELINE);
    if (ok)
	data_len = BIO_get_mem_data(mem, &data);
    if (data) {
	/* the 'data' returned is not '\0' terminated */
	if (buf) {
	    memcpy(buf, data, data_len < len ? data_len : len);
	    buf[data_len < len ? data_len : len - 1] = 0;
	    BIO_free(mem);
	    return buf;
	} else {
	    char *b = malloc(data_len + 1);
	    if (b) {
		memcpy(b, data, data_len);
		b[data_len] = 0;
	    }
	    BIO_free(mem);
	    return b;
	}
    } else {
	BIO_free(mem);
	return NULL;
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x000906000 */
}

int
tls_is_krb5(void)
{
#ifdef TLS_KRB5
    char buf[128];
    SSL_CIPHER * cipher;

    if (cipher = SSL_get_current_cipher(ssl)) {
        if (SSL_CIPHER_description(cipher,buf,sizeof(buf))) {
            if (strstr(buf,"Au=KRB5") != NULL)
                return(1);                  /* krb5 */
        }
    }
#endif /* TLS_KRB5 */
    return(0);                          /* not krb5 */
}

char *tls_get_issuer_name(SSL *s)
{
    static char name[256];
    X509 *server_cert;

    if (server_cert = SSL_get_peer_certificate(s)) {
	char *n = x509_name_oneline(X509_get_issuer_name(server_cert), name, sizeof(name));
	X509_free(server_cert);
	return n;
    }
    else {
/*    	fprintf(stderr, "WARNING: No certificate from server!\r\n");*/
	return NULL;
    }
}

char *tls_get_subject_name(SSL *s)
{
    static char name[256];
    X509 *server_cert;

    if (server_cert = SSL_get_peer_certificate(s)) {
	char *n = x509_name_oneline(X509_get_subject_name(server_cert), name, sizeof(name));
	X509_free(server_cert);
	return n;
    }
    else
	return NULL;
}

char read_char(void)
{
    char inl[10];
    /*
    NetNonblockingIO(0, 0);
    fgets(inl, sizeof(inl), stdin);
    NetNonblockingIO(0, 1);
    */
    read_string(inl, sizeof(inl), "");
    return *inl;
}

/* this one is (very much!) based on work by Ralf S. Engelschall <rse@engelschall.com>.
 * comments by Ralf.
 */
int verify_crl(int ok, X509_STORE_CTX *ctx)
{
    X509_OBJECT obj;
    X509_NAME *subject;
    X509_NAME *issuer;
    X509 *xs;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    X509_STORE_CTX store_ctx;
    long serial;
    int i, n, rc;
    char *cp;

    /*
     * Unless a revocation store for CRLs was created we
     * cannot do any CRL-based verification, of course.
     */
    if (!crl_store)
        return ok;

    /*
     * Determine certificate ingredients in advance
     */
    xs      = X509_STORE_CTX_get_current_cert(ctx);
    subject = X509_get_subject_name(xs);
    issuer  = X509_get_issuer_name(xs);

    /*
     * OpenSSL provides the general mechanism to deal with CRLs but does not
     * use them automatically when verifying certificates, so we do it
     * explicitly here. We will check the CRL for the currently checked
     * certificate, if there is such a CRL in the store.
     *
     * We come through this procedure for each certificate in the certificate
     * chain, starting with the root-CA's certificate. At each step we've to
     * both verify the signature on the CRL (to make sure it's a valid CRL)
     * and it's revocation list (to make sure the current certificate isn't
     * revoked).  But because to check the signature on the CRL we need the
     * public key of the issuing CA certificate (which was already processed
     * one round before), we've a little problem. But we can both solve it and
     * at the same time optimize the processing by using the following
     * verification scheme (idea and code snippets borrowed from the GLOBUS
     * project):
     *
     * 1. We'll check the signature of a CRL in each step when we find a CRL
     *    through the _subject_ name of the current certificate. This CRL
     *    itself will be needed the first time in the next round, of course.
     *    But we do the signature processing one round before this where the
     *    public key of the CA is available.
     *
     * 2. We'll check the revocation list of a CRL in each step when
     *    we find a CRL through the _issuer_ name of the current certificate.
     *    This CRLs signature was then already verified one round before.
     *
     * This verification scheme allows a CA to revoke its own certificate as
     * well, of course.
     */

    /*
     * Try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity.
     */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, crl_store, NULL, NULL);
    rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl = obj.data.crl;
    if (rc > 0 && crl != NULL) {
        /*
         * Verify the signature on this CRL
         */
        if (X509_CRL_verify(crl, X509_get_pubkey(xs)) <= 0) {
            fprintf(stderr, "Invalid signature on CRL!\r\n");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }

        /*
         * Check date of CRL to make sure it's not expired
         */
        i = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));
        if (i == 0) {
            fprintf(stderr, "Found CRL has invalid nextUpdate field.\r\n");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }
        if (i < 0) {
            fprintf(stderr, "Found CRL is expired - revoking all certificates until you get updated CRL.\r\n");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }
        X509_OBJECT_free_contents(&obj);
    }

    /*
     * Try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation.
     */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, crl_store, NULL, NULL);
    rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl = obj.data.crl;
    if (rc > 0 && crl != NULL) {
        /*
         * Check if the current certificate is revoked by this CRL
         */
        n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
        for (i = 0; i < n; i++) {
            revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
            if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(xs)) == 0) {
                serial = ASN1_INTEGER_get(revoked->serialNumber);
                cp = x509_name_oneline(issuer, NULL, 0);
                fprintf(stderr,
		    "Certificate with serial %ld (0x%lX) revoked per CRL from issuer %s\r\n",
                        serial, serial, cp ? cp : "(ERROR)");
                if (cp) free(cp);

                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
                X509_OBJECT_free_contents(&obj);
                return 0;
            }
        }
        X509_OBJECT_free_contents(&obj);
    }
    return ok;
}

void print_x509_v_error(int error)
{
    switch (error) {
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	    fprintf(stderr, "WARNING: Server's certificate is self signed.\r\n");
	    break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	    fprintf(stderr, "WARNING: Server's certificate has expired.\r\n");
	    break;
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	    fprintf(stderr,
		"WARNING: Server's certificate issuer's certificate isn't available locally.\r\n");
	    break;
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	    fprintf(stderr, "WARNING: Unable to verify leaf signature.\r\n");
	    break;
	case X509_V_ERR_CERT_REVOKED:
	    fprintf(stderr, "WARNING: Certificate revoked.\r\n");
	    break;
	case X509_V_ERR_CRL_HAS_EXPIRED:
	    fprintf(stderr, "WARNING: CRL has expired.\r\n");
	    break;
	default:
	    fprintf(stderr,
		"WARNING: Error %d while verifying server's certificate.\r\n", error);
	    break;
    }
}

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    int prev_error = 0;
/*    fprintf(stderr, "depth = %d, error = %d, ok = %d\n", ctx->error_depth, ctx->error, ok);*/
/* TODO: Make up my mind on what errors to accept or not. */
#ifdef TLS_KRB5
    if (tls_is_krb5())
        return 1;
#endif /* TLS_KRB5 */

    if (!ok) {
    	verify_error_flag = 1;
    	print_x509_v_error(prev_error = ctx->error);
    }
    /* since the CRL check isn't included in the OpenSSL automatic certificate
     * check, we must call verify_crl() after we first check what errors the
     * automatic check might have found, otherwise they might be lost.
     */
    ok = verify_crl(ok, ctx);
    if (!ok) {
    	verify_error_flag = 1;
	if (ctx->error != prev_error)
	    print_x509_v_error(ctx->error);
    }
    ok = 1;
    return ok;
}

/* From OpenSSL's s_cb.c */
long debug_callback(BIO *bio, int cmd, const char *argp, int argi,
	     long argl, long ret)
{
	BIO *out;

	/*
	out=(BIO *)BIO_get_callback_arg(bio);
	if (out == NULL) return(ret);
	*/
	out = bout;

	if (cmd == (BIO_CB_READ|BIO_CB_RETURN))
		{
		BIO_printf(out,"read from %08X [%08lX] (%d bytes => %ld (0x%X))\n",
			bio,argp,argi,ret,ret);
		BIO_dump(out,argp,(int)ret);
		return(ret);
		}
	else if (cmd == (BIO_CB_WRITE|BIO_CB_RETURN))
		{
		BIO_printf(out,"write to %08X [%08lX] (%d bytes => %ld (0x%X))\n",
			bio,argp,argi,ret,ret);
		BIO_dump(out,argp,(int)ret);
		}
	return(ret);
}

void state_debug_callback(SSL *s, int where, int ret)
{
	char *str;
	int w;

	w=where& ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT) str="SSL_connect";
	else if (w & SSL_ST_ACCEPT) str="SSL_accept";
	else str="undefined";

	if (where & SSL_CB_LOOP)
		{
		printf("%s:%s\r\n",str,SSL_state_string_long(s));
		}
	else if (where & SSL_CB_ALERT)
		{
		str=(where & SSL_CB_READ)?"read":"write";
		printf("SSL3 alert %s:%s:%s\r\n",
			str,
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret));
		}
	else if (where & SSL_CB_EXIT)
		{
		if (ret == 0)
			printf("%s:failed in %s\r\n",
				str,SSL_state_string_long(s));
		else if (ret < 0)
			{
			printf("%s:error in %s\r\n",
				str,SSL_state_string_long(s));
			}
		}
}

/* A dummy method that dumps to stdout and does the right CR/LF mappings */
static int out_write(BIO *b, const char *in, int inl)
{
  int i;
  int lastch;

  if(in) {
    lastch = (int) b->ptr;	/* Stash the last char in the ptr field */
    for(i = inl; i > 0; --i, ++in) {
      if(*in == '\n' && lastch != '\r')
	putchar('\r');
      putchar((lastch = *in));
    }
    b->ptr = (void *) lastch;
  }
  else
    return 0;
}

static int out_read(BIO *b, char *out, int outl)
{
  return 0;
}

static long out_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  return 1L;
}

static int out_gets(BIO *b, char *buf, int size)
{
  return 0;
}

static int out_puts(BIO *b, const char *str)
{
  if(str)
    return out_write(b, str, strlen(str));
  else
    return 0;
}

static int out_new(BIO *b)
{
  b->init = 1;
  b->ptr = NULL;
  return 1;
}

static int out_free(BIO *b)
{
  return 1;
}

static BIO_METHOD method_stdout = {
  BIO_TYPE_FILE,
  "Standard output",
  out_write,
  out_read,
  out_puts,
  out_gets,
  out_ctrl,
  out_new,
  out_free,
  NULL
};

int seed_PRNG(void)
{
    char stackdata[1024];
    static char rand_file[300];
    FILE *fh;
    
#if OPENSSL_VERSION_NUMBER >= 0x00905100
    if (RAND_status())
	return 0;     /* PRNG already good seeded */
#endif
    /* if the device '/dev/urandom' is present, OpenSSL uses it by default.
     * check if it's present, else we have to make random data ourselfs.
     */
    if ((fh = fopen("/dev/urandom", "r"))) {
	fclose(fh);
	return 0;
    }
    if (RAND_file_name(rand_file, sizeof(rand_file)))
	tls_rand_file = rand_file;
    else
	return 1;
    if (!RAND_load_file(rand_file, 1024)) {
	/* no .rnd file found, create new seed */
	unsigned int c;
	c = time(NULL);
	RAND_seed(&c, sizeof(c));
	c = getpid();
	RAND_seed(&c, sizeof(c));
	RAND_seed(stackdata, sizeof(stackdata));
    }
#if OPENSSL_VERSION_NUMBER >= 0x00905100
    if (!RAND_status())
	return 2;   /* PRNG still badly seeded */
#endif
    return 0;
}

#ifdef TLS_SESSION_FILE_CACHE
char *sfc_filename = NULL;

char *make_sfc_filename(int sock)
{
    struct sockaddr_in saddr;
    int saddr_len = sizeof(saddr);
    DIR *dir;
    char path[MAXPATHLEN], *home;
    static char filename[MAXPATHLEN];

    home = getenv("HOME");
    if (home == NULL)
	return NULL;
    snprintf(path, sizeof(path), "%s/.tls_sfc", home);
    dir = opendir(path);
    /* if the ~/.tls_sfc dir doesn't exist, we consider this function disabled */
    if (dir == NULL)
	return NULL;
    closedir(dir);
    if (getpeername(sock, (struct sockaddr *)&saddr, &saddr_len) != 0)
	return NULL;
    /* the file name is based on the hexadecimal representation of the peer's
     * ip address, with `oss' (from `OpenSsl Session') as a prefix.
     * example: connected to 127.0.0.1 -> `oss7F000001'
     */
    snprintf(filename, sizeof(filename), "%s/oss%08X", path, htonl(saddr.sin_addr.s_addr));
    return filename;
}

int session_timed_out(SSL_SESSION *s)
{
    if (SSL_SESSION_get_time(s) + SSL_SESSION_get_timeout(s) < time(NULL))
	return 1;
    else
	return 0;
}

int tls_sfc_client_load(SSL *s)
{
    FILE *file;
    
    if (s == NULL)
	return 1;
    sfc_filename = make_sfc_filename(net);
    if (sfc_filename == NULL)
	return 2;
    file = fopen(sfc_filename, "r");
    if (file) {
	SSL_SESSION *sess;
	fchmod(fileno(file), S_IRUSR | S_IWUSR);
	sess = PEM_read_SSL_SESSION(file, NULL, NULL, NULL);
	if (sess) {
	    /* ``refresh'' the session timeout */
/*XXX		    SSL_SESSION_set_time(sess, time(NULL)); */
	    if (session_timed_out(sess))
		unlink(sfc_filename);
	    else
		SSL_set_session(s, sess);
	    /* dec the ref counter in sess so it will eventually be freed */
	    SSL_SESSION_free(sess);
	}
	fclose(file);
    }
    return 0;
}

int tls_sfc_client_save(SSL *s)
{
    FILE *file;
    
    if (s == NULL)
	return 1;
    if (sfc_filename == NULL)
	return 2;
    file = fopen(sfc_filename, "w");
    if (file) {
	SSL_SESSION *sess;
	sess = SSL_get_session(s);
	if (sess)
	    PEM_write_SSL_SESSION(file, sess);
	fclose(file);
    }
    return 0;
}
#endif /* TLS_SESSION_FILE_CACHE */

int tls_init(void)
{
    int err;
#ifdef ZLIB
    COMP_METHOD * comp;
#endif

    SSL_load_error_strings();
    SSL_library_init();
#ifdef ZLIB
    comp = COMP_zlib();
    if (comp && comp->type != NID_undef)
        SSL_COMP_add_compression_method(0xE0, COMP_zlib());  /* EAY's ZLIB */
#endif /* ZLIB */

    /*bout = BIO_new_fp(stdout, BIO_NOCLOSE);*/
    bout = BIO_new(&method_stdout);
    ssl_ctx = SSL_CTX_new(tls_get_method());
    if (!ssl_ctx) {
	fprintf(stderr, "SSL_CTX_new() %s\r\n",
		(char *)ERR_error_string(ERR_get_error(), NULL));
	return 1;
    }
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);

    /* set up the CApath if defined */
    if (tls_capath_dir || tls_cafile_file) {
        printf("Setting verify path \n");
        if (!SSL_CTX_load_verify_locations(ssl_ctx,tls_cafile_file,tls_capath_dir)) {
	    fprintf(stderr,"WARNING: can't set CApath/CAfile verify locations\n");
	}
    }
    else
	SSL_CTX_set_default_verify_paths(ssl_ctx);

    if(tls_debug)
      SSL_CTX_set_info_callback(ssl_ctx, state_debug_callback);

    /* set up the CRL */
    if ((tls_crl_file || tls_crl_dir) && (crl_store = X509_STORE_new()))
	X509_STORE_load_locations(crl_store, tls_crl_file, tls_crl_dir);
    
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
	fprintf(stderr, "SSL_new() %s\r\n",
		(char *)ERR_error_string(ERR_get_error(), NULL));
	return 5;
    }
#ifdef TLS_SESSION_FILE_CACHE
    /* I would love to hear the story on why I must use the
     * SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG option to get this working...
     */
    SSL_set_options(ssl, SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);
    tls_sfc_client_load(ssl);
#endif /* TLS_SESSION_FILE_CACHE */
    
    SSL_set_cipher_list(ssl, tls_cipher_list);
    /*SSL_set_fd(ssl, net);*/
    sbio = BIO_new_socket(net, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    if (seed_PRNG())
	fprintf(stderr, "Wasn't able to properly seed the PRNG!\r\n");
#ifdef TLS_KRB5
    ssl->kssl_ctx = kssl_ctx_new();
    if (ssl->kssl_ctx) {
        printf("setting krb5 service ticket to %s/%s\r\n",
                KRB5_SERVICE_NAME,hostname);
        kssl_ctx_setstring(ssl->kssl_ctx, KSSL_SERVER, hostname);
        kssl_ctx_setstring(ssl->kssl_ctx, KSSL_SERVICE, KRB5_SERVICE_NAME);
    }
#endif /* TLS_KRB5 */
    return 0;
}

int show_hostname_warning(char *s1, char *s2)
{
    char inp;
    
    fprintf(stderr,
	"WARNING: Hostname (\"%s\") and server's certificate (\"%s\") don't match, continue? (Y/N) ",
	s1, s2);
    inp = read_char();
    if (!( inp == 'y' || inp == 'Y' ))
	return 1;
    else
	return 0;
}

int star_stricmp(const char *str, const char *star_str)
/* wildcard compares string `str' with a pattern string `star_str' which may
 * contain ONE wildcard star, '*', case-insensitive. there's probably better
 * ways to do this...
 */
{
    char *str_copy = strdup(str);
    char *star_str_copy = strdup(star_str);
    char *star;
    int rv = -1;

    if (str_copy == NULL || star_str_copy == NULL)
	goto eject;
    star = strchr(star_str_copy, '*');
    if (star) {
	int str_len = strlen(str_copy);
	int star_str_len = strlen(star_str_copy);
	int star_idx = star - star_str_copy;
	
	/* first check a few special cases */
	if (star_str_len > str_len + 1)
	    /* `star_str' is too long to ever match */
	    goto eject;
	else if (star_str_len == str_len + 1) {
	    if (*star_str_copy == '*')
		/* possible "*foo" == "foo" case */
		memmove(star_str_copy, star_str_copy + 1, star_str_len);
	    else if (star_str_copy[star_str_len - 1] == '*')
		/* possible "foo*" == "foo" case */
		star_str_copy[star_str_len - 1] = '\0';
	    else {
		/* possible "f*oo" == "foo" case */
		memmove(star_str_copy + star_idx, star_str_copy + star_idx + 1,
			star_str_len - star_idx);
	    }
	} else {
	    int diff = str_len - star_str_len;
	    /* remove the chars from `str_copy' that the star ``wildcards'' */
	    memmove(str_copy + star_idx, str_copy + star_idx + diff + 1,
		    str_len - star_idx - diff);
	    /* remove the '*' from `star_str_copy' */
	    memmove(star_str_copy + star_idx, star_str_copy + star_idx + 1,
		    star_str_len - star_idx);
	}
    }
    rv = strcasecmp(str_copy, star_str_copy);
eject:
    if (str_copy)	free(str_copy);
    if (star_str_copy)	free(star_str_copy);
    return rv;
}

int dNSName_cmp(const char *host, const char *dNSName)
{
    int c1 = 0, c2 = 0, num_comp, rv = -1;
    char *p, *p1, *p2, *host_copy, *dNSName_copy;

    /* first we count the number of domain name components in both parameters.
     * they should be equal many, or it's not a match
     */
    p = (char *) host;
    while ((p = strchr(p, '.'))) {
	c1++;
	p++;
    }
    p = (char *) dNSName;
    while ((p = strchr(p, '.'))) {
	c2++;
	p++;
    }
    if (c1 != c2)
	return -1;
    num_comp = c1;

    host_copy = strdup(host);
    dNSName_copy = strdup(dNSName);
    if (host_copy == NULL || dNSName_copy == NULL)
	goto eject;
    /* make substrings by replacing '.' with '\0' */
    p = dNSName_copy;
    while ((p = strchr(p, '.'))) {
	*p = '\0';
	p++;
    }
    p = host_copy;
    while ((p = strchr(p, '.'))) {
	*p = '\0';
	p++;
    }

    /* compare each component */
    p1 = host_copy;
    p2 = dNSName_copy;
    for (; num_comp; num_comp--) {
	if (star_stricmp(p1, p2))
	    /* failed match */
	    goto eject;
	p1 += strlen(p1) + 1;
	p2 += strlen(p2) + 1;
    }
    /* match ok */
    rv = 0;

eject:
    if (dNSName_copy)	free(dNSName_copy);
    if (host_copy)	free(host_copy);
    return rv;
}

int check_server_name(SSL *s)
/* returns 0 if hostname and server's cert matches, else 1 */
{
    char **dNSName, *commonName;
    unsigned char **ipAddress;
    struct in_addr ia;

    /* first we check if `tls_hostname' is in fact an ip address */
    if ((ia.s_addr = inet_addr(tls_hostname)) != INADDR_NONE) {
	ipAddress = (unsigned char **) tls_get_SAN_objs(s, GEN_IPADD);
	if (ipAddress) {
	    int i = 0, rv;
	    char *server_ip = "UNKNOWN";
	    
	    for (i = 0; ipAddress[i]; i++)
		if (*(unsigned long *)ipAddress[i] == ia.s_addr)
		    return 0;
	    
	    if (ipAddress[i - 1]) {
		ia.s_addr = *(unsigned long *)ipAddress[i - 1];
		server_ip = inet_ntoa(ia);
	    }
	    rv = show_hostname_warning(tls_hostname, server_ip);
	    for (i = 0; ipAddress[i]; i++)
		free(ipAddress[i]);
	    return rv;
	} else
	    return show_hostname_warning(tls_hostname, "NO IP IN CERT");
    }
    
    /* look for dNSName(s) in subjectAltName in the server's certificate */
    dNSName = tls_get_SAN_objs(s, GEN_DNS);
    if (dNSName) {
	int i = 0, rv;
	for (i = 0; dNSName[i]; i++) {
	    if (!dNSName_cmp(tls_hostname, dNSName[i]))
		return 0;
	}
	rv = show_hostname_warning(tls_hostname, dNSName[i - 1] ? dNSName[i - 1] : "UNKNOWN");
	for (i = 0; dNSName[i]; i++)
	    free(dNSName[i]);
	return rv;
    } else if ((commonName = tls_get_commonName(s))) {
	/* so the server didn't have any dNSName's, check the commonName */
	if (!dNSName_cmp(tls_hostname, commonName))
	    return 0;
	else
	    return show_hostname_warning(tls_hostname, commonName);
    } else
	return 1;
}

int tls_try(void)
{
    int err;
    char *subject, *issuer, *subjectAltName, inp;

    /* let's see if we are going to use any client certificate */
    x509rc_read_filenames();
    if (tls_cert_file) {
    	char *key_file = tls_key_file;
	if (!key_file)
	    key_file = tls_cert_file;
    	err = SSL_use_certificate_file(ssl, file_fullpath(tls_cert_file),
				       SSL_FILETYPE_PEM);
    	if (err <= 0) {
            fprintf(stderr, "SSL_use_certificate_file(\"%s\") %s\r\n",
		    file_fullpath(tls_cert_file),
		    (char *)ERR_error_string(ERR_get_error(), NULL));
            return 1;
    	}
    	err = SSL_use_PrivateKey_file(ssl, file_fullpath(key_file),
				      SSL_FILETYPE_PEM);
    	if (err <= 0) {
            fprintf(stderr, "SSL_use_PrivateKey_file(\"%s\") %s\r\n",
		    file_fullpath(key_file),
		    (char *)ERR_error_string(ERR_get_error(), NULL));
            return 2;
    	}
    	if (!SSL_check_private_key(ssl)) {
    	    fprintf(stderr, "Private key don't match the certificate public key!\r\n");
	    return 3;
    	}
    }

    if(tls_debug) {
      ssl->debug = 1;
      BIO_set_callback(sbio, debug_callback);
    }

    /* it seems SSL_connect() don't like non-blocking sockets, or...? */
    NetNonblockingIO(net, 0);
    fprintf(stderr, "[ Negotiating SSL/TLS session ... ]\r\n");
    err = SSL_connect(ssl);
    NetNonblockingIO(net, 1);
    if (err == 1) {
    	if (verify_error_flag) {
	    fprintf(stderr,
		"WARNING: Errors while verifying the server's certificate chain, continue? (Y/N) ");
	    inp = read_char();
	    if (!( inp == 'y' || inp == 'Y' ))
	    	quit();
	}
	tls_active = 1;
	fprintf(stderr, "[ Cipher: %s (%d bits) ]\r\n", SSL_get_cipher(ssl),
		SSL_get_cipher_bits(ssl, NULL));
	if (subject = tls_get_subject_name(ssl))
	    fprintf(stderr, "[ Subject: %s ]\r\n", subject);
	else {
#ifdef AUTHENTICATION	/* Special case - we use the tls_anon flag */
#ifdef TLS_KRB5
            if (!tls_is_krb5())
#endif /* TLS_KRB5 */
                tls_anon = 1;
	    if(tls_anon)
	      fprintf(stderr, "[ Attempting to verify TLS session parameters... ]\r\n");
	    return 0;
#else
	    fprintf(stderr,
	        "WARNING: Server didn't provide a certificate, continue? (Y/N) ");
	    inp = read_char();
	    if (!( inp == 'y' || inp == 'Y' ))
	    	quit();
#endif /* !AUTHENTICATION */
	}
	if ((subjectAltName = x509v3_subjectAltName_oneline(ssl, NULL, 0))) {
	    fprintf(stderr, "[ X509v3 Subject Alternative Name: %s ]\r\n", subjectAltName);
	    free(subjectAltName);
	}
	if (issuer = tls_get_issuer_name(ssl))
	    fprintf(stderr, "[ Issuer: %s ]\r\n", issuer);
	if (check_server_name(ssl)) {
	    /* the host name on the command line didn't match with the server's
	     * cert, and the user didn't ansver `Y' to the question.
	     */
	    quit();
	}
	return 0;
    }
    else {   /* TLS connection failed */
	fprintf(stderr, "SSL_connect() = %d, %s\r\n", err,
		(char *)ERR_error_string(ERR_get_error(), NULL));
	tls_shutdown();
	tls_cleanup();
	return 5;
    }
    return 6;
}

void tls_shutdown(void)
{
    if (tls_active) {
    	SSL_shutdown(ssl);
    	tls_active = 0;
    }
}

void tls_cleanup(void)
{
    if (crl_store) {
    	X509_STORE_free(crl_store);
	crl_store = NULL;
    }
    if (ssl) {
#ifdef TLS_SESSION_FILE_CACHE
	tls_sfc_client_save(ssl);
#endif /* TLS_SESSION_FILE_CACHE */
	SSL_free(ssl);
	ssl = NULL;
    }
    if (ssl_ctx) {
	SSL_CTX_free(ssl_ctx);
	ssl_ctx = NULL;
    }
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();	/* release the stuff allocated by SSL_library_init() */
    if (tls_cert_file) {
    	free(tls_cert_file);
	tls_cert_file = NULL;
    }
    if (tls_key_file) {
    	free(tls_key_file);
	tls_key_file = NULL;
    }
    if (tls_crl_file) {
    	free(tls_crl_file);
	tls_crl_file = NULL;
    }
    if (tls_crl_dir) {
    	free(tls_crl_dir);
	tls_crl_dir = NULL;
    }
    if (tls_capath_dir) {
    	free(tls_capath_dir);
	tls_capath_dir = NULL;
    }
    if (tls_cafile_file) {
    	free(tls_cafile_file);
	tls_cafile_file = NULL;
    }
    if (tls_hostname) {
    	free(tls_hostname);
	tls_hostname = NULL;
    }
    if (tls_rand_file)
	RAND_write_file(tls_rand_file);
    /* Apparently, SSL_free frees "sbio" too */
    if (sbio) {
	/*BIO_free(sbio);*/
	sbio = NULL;
    }
    if (bout) {
	BIO_free(bout);
	bout = NULL;
    }
}

void handle_ssl_error(int error, char *where)
{
    switch (error) {
    	case SSL_ERROR_NONE:
	    return;
	case SSL_ERROR_SSL:
	    fprintf(stderr, "unhandled SSL_ERROR_SSL in %s\r\n", where);
	    break;
	case SSL_ERROR_WANT_READ:
	    fprintf(stderr, "unhandled SSL_ERROR_WANT_READ in %s\r\n", where);
	    break;
	case SSL_ERROR_WANT_WRITE:
	    fprintf(stderr, "unhandled SSL_ERROR_WANT_WRITE in %s\r\n", where);
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    fprintf(stderr, "unhandled SSL_ERROR_WANT_X509_LOOKUP in %s\r\n", where);
	    break;
	case SSL_ERROR_SYSCALL:
	    fprintf(stderr, "unhandled SSL_ERROR_SYSCALL in %s\r\n", where);
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    fprintf(stderr, "unhandled SSL_ERROR_ZERO_RETURN in %s\r\n", where);
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    fprintf(stderr, "unhandled SSL_ERROR_WANT_CONNECT in %s\r\n", where);
	    break;
	default:
	    fprintf(stderr, "unhandled SSL_ERROR %d in %s\r\n", error, where);
	    break;
    }
}

ssize_t tls_read(int fd, void *buf, size_t count)
{
    if (tls_active) {
	ssize_t c = SSL_read(ssl, buf, count);
	if (c < 0) {
	    int err = SSL_get_error(ssl, c);
	    /* read(2) returns only the generic error number -1 */
	    c = -1;
	    switch (err) {
	    	case SSL_ERROR_WANT_READ:
		    /* simulate an EINTR in case OpenSSL wants to read more */
		    errno = EINTR;
		    break;
		case SSL_ERROR_SYSCALL:
		    /* don't know what this is about */
		    break;
		default:
		    handle_ssl_error(err, "tls_read()");
		    break;
	    }
	}
	return c;
    }
    else
	return read(fd, buf, count);
}

int tls_recv(int s, void *buf, size_t len, int flags)
{
    if (tls_active)
	return (int)tls_read(s, buf, len);
    else
	return recv(s, buf, len, flags);
}

ssize_t tls_write(int fd, const void *buf, size_t count)
{
    if (tls_active) {
    	ssize_t c = SSL_write(ssl, buf, count);
	if (c < 0) {
	    int err = SSL_get_error(ssl, c);
	    /* write(2) returns only the generic error number -1 */
	    c = -1;
	    switch (err) {
	        case SSL_ERROR_WANT_WRITE:
	    	    /* simulate an EINTR in case OpenSSL wants to write more */
		    errno = EINTR;
		    break;
		case SSL_ERROR_SYSCALL:
		    /* don't know what this is about */
		    break;
		default:
		    handle_ssl_error(err, "tls_write()");
		    break;
	    }
	}
	return c;
    }	
    else
	return write(fd, buf, count);
}

int tls_send(int s, const void *msg, size_t len, int flags)
{
    if (tls_active)
	return (int)tls_write(s, msg, len);
    else
	return send(s, msg, len, flags);
}

int tls_pending(void)
{
    if (tls_active)
        return SSL_pending(ssl);
    else 
        return 0;
}

/*
 * Interface to obtain SSL/TLS client/server Finished messages.
 * Author: Tom Wu <tjw@CS.Stanford.EDU>
 *
 * The "len" argument is the maximum available space in the buffer;
 * each function will return the actual number of bytes copied.
 * Currently, only OpenSSL 0.9.5 or newer supports the direct
 * interface; these functions may be expanded to cover earlier
 * versions if demanded.
 */

#if OPENSSL_VERSION_NUMBER < 0x000905100
#error "Please upgrade to OpenSSL 0.9.5 or newer"
#endif

/* We are the client, so the server is the peer */
int tls_get_client_finished(void *buf, size_t len)
{
  if(tls_active)
    return SSL_get_finished(ssl, buf, len);
  else
    return 0;
}

int tls_get_server_finished(void *buf, size_t len)
{
  if(tls_active)
    return SSL_get_peer_finished(ssl, buf, len);
  else
    return 0;
}

char *strcasestr(const char *haystack, const char *needle)
{
    char *Haystack, *Needle, *p;

    if (!(Haystack = malloc(strlen(haystack) + 1)))
    	return NULL;
    if (!(Needle = malloc(strlen(needle) + 1))) {
    	free(Haystack);
	return NULL;
    }
    strcpy(Haystack, haystack);
    for (p = Haystack; *p; p++)
    	*p = toupper(*p);
    strcpy(Needle, needle);
    for (p = Needle; *p; p++)
    	*p = toupper(*p);
    p = strstr(Haystack, Needle);
    if (p)
    	p = (char *)haystack + (p - Haystack);
    else
    	p = NULL;
    free(Haystack);
    free(Needle);
    return p;
}

char *file_fullpath(char *fn)
{
    static char fp[256];
    FILE *file;
    char *dir;
    
    /* check if it is a full path already */
    if (strchr(fn, '/'))
    	return fn;
    /* check if it is in current dir */
    if ((file = fopen(fn, "r"))) {
    	fclose(file);
	return fn;
    }
    if (!(dir = getenv(X509_get_default_cert_dir_env())))	/* $SSL_CERT_DIR */
    	dir = (char *)X509_get_default_cert_dir();
    snprintf(fp, sizeof(fp), "%s/%s", dir, fn);
    if ((file = fopen(fp, "r"))) {
    	fclose(file);
	return fp;
    }
    dir = (char *)X509_get_default_private_dir();
    snprintf(fp, sizeof(fp), "%s/%s", dir, fn);
    if ((file = fopen(fp, "r"))) {
    	fclose(file);
	return fp;
    }
    return fn;	/* here fn is proven wrong, but we return it anyway */
}

char *glob_tilde(char *s)
/* very simple ~ expansion */
{
    char *h, *r;

    if (s == NULL)
	return NULL;
    if (*s != '~')
	return s;
    if (!(h = getenv("HOME")))
	return s;
    if (!(r = malloc(strlen(h) + strlen(s))))
	return s;
    sprintf(r, "%s%s", h, s + 1);
    free(s);
    return r;
}

int x509rc_read_filenames(void)
{
    char filename[MAXPATHLEN], s1[256], s2[MAXPATHLEN], s3[MAXPATHLEN],
	 line[sizeof(s1) + sizeof(s2) + sizeof(s3) + 50], format[50], *home = NULL,
	 *p, *host = NULL;
    int rv = 0;
    FILE *file;

    if (x509rc_override)	/* cert already specified on command line */
	return 0;
    if (!tls_hostname)
	return 1;
    host = strdup(tls_hostname);
    if (host == NULL)
	return 2;
    for (p = host; *p; p++)
	*p = tolower(*p);
    home = getenv("HOME");
    if (home == NULL)
	return 3;
    snprintf(filename, sizeof(filename), "%s/.x509rc", home);
    file = fopen(filename, "r");
    if (file == NULL)
	return 4;
    
    /* create the sscanf() format string */
    snprintf(format, sizeof(format), "%%%ds %%%ds %%%ds", sizeof(s1) - 1,
	     sizeof(s2) - 1, sizeof(s3) - 1);

    while (fgets(line, sizeof(line), file)) {
	int c;
	if ((p = strchr(line, '#')))	/* truncate at comment */
	    *p = 0;
	c = sscanf(line, format, &s1, &s2, &s3);
	if (c < 2)
	    continue;
	for (p = s1; *p; p++)
	    *p = tolower(*p);
	/* check for exact host name match */
	if (!strcmp(s1, host)) {
	    if (tls_cert_file)
		free(tls_cert_file);
	    tls_cert_file = glob_tilde(strdup(s2));
	    if (c > 2) {
		if (tls_key_file)
		    free(tls_key_file);
		tls_key_file = glob_tilde(strdup(s3));
	    }
	    goto cleanup;
	}
	/* check for a "prefix" match */
	if (*s1 == '.') {
	    int hlen = strlen(host);
	    int slen = strlen(s1);
	    if (hlen > slen + 1 && !strcmp(s1 + 1, host + hlen - slen + 1)) {
		if (tls_cert_file)
		    free(tls_cert_file);
		tls_cert_file = glob_tilde(strdup(s2));
		if (c > 2) {
		    if (tls_key_file)
			free(tls_key_file);
		    tls_key_file = glob_tilde(strdup(s3));
		}
	    }
	}
    }

  cleanup:
    fclose(file);
    if (host) free(host);
    return rv;
}

/* TLS commands */

int
tls_enable(void)
{
  if(tls_active)
    printf("TLS session already active\n");
  else {
    tls_enabled = 1;
    printf("TLS enabled\n");
  }
  return 1;
}

int
tls_disable(void)
{
  if(tls_active)
    printf("TLS session already active - cannot disable\n");
  else {
    tls_enabled = 0;
    printf("TLS disabled\n");
  }
  return 1;
}

int
tls_status(void)
{
  char *subject, *issuer;

  if(!tls_enabled) {
    printf("TLS: disabled\n");
    return 1;
  }

  printf("TLS: enabled\n");
  if(tls_active) {
    switch(ssl->version) {
    case TLS1_VERSION: printf("TLSv1 session is active\n"); break;
    case SSL3_VERSION: printf("SSLv3 session is active\n"); break;
    case SSL2_VERSION: /* Error! */
    default: printf("Unknown session type - possible security problem!\n");
    }
  }
  else {
    printf("TLS not currently active\n");
    return 1;
  }

  printf("TLS cipher: %s (%d bits)\r\n", SSL_get_cipher(ssl),
	 SSL_get_cipher_bits(ssl, NULL));
  subject = tls_get_subject_name(ssl);
  if(subject) {
    printf("Server DN: %s\n", subject);
    issuer = tls_get_issuer_name(ssl);
    if(issuer)
      printf("Issuer DN: %s\n", issuer);
  }
  else if(tls_anon)
    printf("TLS anonymous session parameters NOT verified\n");
  else
    printf("TLS using authenticated DH key exchange\n");
}

int
tls_cipher(char *newlist)
{
    snprintf(tls_cipher_list, sizeof(tls_cipher_list), "%s", newlist);
    printf("TLS cipher list set to \"%s\".\n", tls_cipher_list);
}

int
tls_protocol(char *proto)
{
  if(strcmp(proto, "?") == 0 || strcasecmp(proto, "help") == 0) {
    printf("Usage: tls protocol <proto>\n");
    printf("Supported protocols:  SSLv3, TLSv1\n");
  }
  else if(strcasecmp(proto, "tlsv1") == 0 || strcasecmp(proto, "tls1") == 0) {
    ssl_meth = TLSv1_client_method();
    printf("Setting protocol to %s\n", proto);
  }
  else if(strcasecmp(proto, "sslv3") == 0 || strcasecmp(proto, "ssl3") == 0) {
    ssl_meth = SSLv3_client_method();
    printf("Setting protocol to %s\n", proto);
  }
  else
    printf("%s: invalid protocol specification\n", proto);

  return 1;
}

int
tls_list(void)
{
  const char *p;
  int i = 0;
  SSL *tssl;
  SSL_CTX *tctx = NULL;

  if(tls_active)
    tssl = ssl;
  else {
    OpenSSL_add_ssl_algorithms();
    tctx = SSL_CTX_new(tls_get_method());
    tssl = SSL_new(tctx);
    SSL_set_cipher_list(tssl, tls_cipher_list);
  }

  while((p = SSL_get_cipher_list(tssl, i)) != NULL) {
    if(i % 3 == 0 && i != 0)
      printf("\n");
    printf("%-26s", p);
    ++i;
  }
  printf("\n");

  if(tctx) {
    SSL_CTX_free(tctx);
    SSL_free(tssl);
  }
}

int
tls_setdebug(on)
     int on;
{
  if(on < 0)
    tls_debug ^= 1;
  else
    tls_debug = on;
  if(tls_active) {
    ssl->debug = tls_debug;
    if(tls_debug) {
      BIO_set_callback(sbio, debug_callback);
      SSL_CTX_set_info_callback(ssl_ctx, state_debug_callback);
    }
    else {
      BIO_set_callback(sbio, NULL);
      SSL_CTX_set_info_callback(ssl_ctx, NULL);
    }
  }
  printf("TLS debugging %s\n", tls_debug ? "enabled" : "disabled");
  return(1);
}

#endif /* TLS */
