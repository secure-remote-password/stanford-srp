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

#ifdef TLS

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) Peter 'Luna' Runestig 1999, 2000 <peter@runestig.com>.\n";
#endif /* not lint */

#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef TLS_KRB5
#include <openssl/kssl.h>
#include <krb5.h>
#endif /* TLS_KRB5 */
#ifdef TLS_SESSION_FILE_CACHE
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <openssl/pem.h>
#endif /* TLS_SESSION_FILE_CACHE */
#include "tls_dh.h"

#ifdef FWD_X
#include "fwdxutil.h"
#endif
#if OPENSSL_VERSION_NUMBER < 0x00905100
/* ASN1_BIT_STRING_cmp was renamed in 0.9.5 */
#define M_ASN1_BIT_STRING_cmp ASN1_BIT_STRING_cmp
#endif

#define DEFRSACERTFILE		"telnetd-rsa.pem"
#define DEFRSACERTCHAINFILE	"telnetd-rsa-chain.pem"
#define DEFRSAKEYFILE		"telnetd-rsa-key.pem" 
#define DEFDSACERTFILE		"telnetd-dsa.pem"
#define DEFDSACERTCHAINFILE	"telnetd-dsa-chain.pem"
#define DEFDSAKEYFILE		"telnetd-dsa-key.pem" 
#define DEFCRLFILE		"telnetd-crl.pem"
#define DEFDHPARAMFILE		"telnetd-dhparam.pem"
#define DEFAULTCIPHERLIST       "ALL:!EXP"

extern int net; /* the socket */

char	*file_fullpath(char *fn);
int	x509_to_user(X509 *peer_cert, char *userid, int len);
void	tls_shutdown(void);

int 	tls_active = 0;
int 	tls_follows_from_client = 0;
int	tls_required = 0;
int	tls_anon = 0;
SSL 	*ssl = NULL;
SSL_CTX	*ssl_ctx = NULL;
X509_STORE *crl_store = NULL;
char 	*tls_rsa_key_file = NULL;
char	*tls_rsa_cert_file = NULL;
char	*tls_rsa_cert_chain_file = NULL;
char 	*tls_dsa_key_file = NULL;
char	*tls_dsa_cert_file = NULL;
char	*tls_dsa_cert_chain_file = NULL;
char	*tls_crl_file = NULL;
char	*tls_crl_dir = NULL;
char	*tls_dhparam_file = NULL;
char	*tls_rand_file = NULL;
char	*tls_cipher_list = NULL;
DH	*tmp_dh = NULL;
RSA	*tmp_rsa = NULL;

/* we need this so we don't mix static and malloc'ed strings */
void tls_set_defaults(void)
{
    if (tls_rsa_key_file = malloc(strlen(DEFRSAKEYFILE) + 1))
    	strcpy(tls_rsa_key_file, DEFRSAKEYFILE);
    if (tls_rsa_cert_file = malloc(strlen(DEFRSACERTFILE) + 1))
    	strcpy(tls_rsa_cert_file, DEFRSACERTFILE);
    if (tls_rsa_cert_chain_file = malloc(strlen(DEFRSACERTCHAINFILE) + 1))
    	strcpy(tls_rsa_cert_chain_file, DEFRSACERTCHAINFILE);
    if (tls_dsa_key_file = malloc(strlen(DEFDSAKEYFILE) + 1))
    	strcpy(tls_dsa_key_file, DEFDSAKEYFILE);
    if (tls_dsa_cert_file = malloc(strlen(DEFDSACERTFILE) + 1))
    	strcpy(tls_dsa_cert_file, DEFDSACERTFILE);
    if (tls_dsa_cert_chain_file = malloc(strlen(DEFDSACERTCHAINFILE) + 1))
    	strcpy(tls_dsa_cert_chain_file, DEFDSACERTCHAINFILE);
    if (tls_crl_file = malloc(strlen(DEFCRLFILE) + 1))
    	strcpy(tls_crl_file, DEFCRLFILE);
    if (tls_crl_dir = malloc(strlen(X509_get_default_cert_area()) + 5))
    	sprintf(tls_crl_dir, "%s/crl", X509_get_default_cert_area());  /* safe */
    if (tls_dhparam_file = malloc(strlen(DEFDHPARAMFILE) + 1))
    	strcpy(tls_dhparam_file, DEFDHPARAMFILE);
    if (tls_cipher_list = malloc(strlen(DEFAULTCIPHERLIST) + 1))
    	strcpy(tls_cipher_list, DEFAULTCIPHERLIST);
}

DH *tmp_dh_cb(SSL *ssl, int is_export, int keylength)
{
    FILE *fp;

    if (!tmp_dh) {
    	/* first try any 'tls_dhparam_file', else use built-in dh params */
    	if (tls_dhparam_file && (fp = fopen(tls_dhparam_file, "r"))) {
	    tmp_dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
	    fclose(fp);
	    if (tmp_dh)
	    	return tmp_dh;
	}
	switch (keylength) {
	    case 512:	return tmp_dh = get_dh512();
	    case 768:	return tmp_dh = get_dh768();
	    case 1024:	return tmp_dh = get_dh1024();
	    case 1536:	return tmp_dh = get_dh1536();
	    case 2048:	return tmp_dh = get_dh2048();
	    default:	return tmp_dh = get_dh1024();
	}
    }
    else
    	return tmp_dh;
}

#ifndef NO_RSA
RSA *tmp_rsa_cb(SSL *s, int is_export, int keylength)
{
    if (!tmp_rsa)
	tmp_rsa = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    return tmp_rsa;
}
#endif /* NO_RSA */

void tls_optarg(char *optarg)
{
    char *p;

    if (p = strchr(optarg, '=')) {
    	*p++ = 0;
	if (!strcmp(optarg, "cert") || !strcmp(optarg, "rsacert")) {
	    if (tls_rsa_cert_file)
	    	free(tls_rsa_cert_file);
	    if (tls_rsa_cert_file = malloc(strlen(p) + 1))
	    	strcpy(tls_rsa_cert_file, p);
	}
	else if (!strcmp(optarg, "chain") || !strcmp(optarg, "rsachain")) {
	    if (tls_rsa_cert_chain_file)
	    	free(tls_rsa_cert_chain_file);
	    if (tls_rsa_cert_chain_file = malloc(strlen(p) + 1))
	    	strcpy(tls_rsa_cert_chain_file, p);
	}
	else if (!strcmp(optarg, "key") || !strcmp(optarg, "rsakey")) {
	    if (tls_rsa_key_file)
	    	free(tls_rsa_key_file);
	    if (tls_rsa_key_file = malloc(strlen(p) + 1))
	    	strcpy(tls_rsa_key_file, p);
	}
	else if (!strcmp(optarg, "dsacert")) {
	    if (tls_dsa_cert_file)
	    	free(tls_dsa_cert_file);
	    if (tls_dsa_cert_file = malloc(strlen(p) + 1))
	    	strcpy(tls_dsa_cert_file, p);
	}
	else if (!strcmp(optarg, "dsachain")) {
	    if (tls_dsa_cert_chain_file)
	    	free(tls_dsa_cert_chain_file);
	    if (tls_dsa_cert_chain_file = malloc(strlen(p) + 1))
	    	strcpy(tls_dsa_cert_chain_file, p);
	}
	else if (!strcmp(optarg, "dsakey")) {
	    if (tls_dsa_key_file)
	    	free(tls_dsa_key_file);
	    if (tls_dsa_key_file = malloc(strlen(p) + 1))
	    	strcpy(tls_dsa_key_file, p);
	}
	else if (!strcmp(optarg, "dhparam")) {
	    if (tls_dhparam_file)
	    	free(tls_dhparam_file);
	    if (tls_dhparam_file = malloc(strlen(p) + 1))
	    	strcpy(tls_dhparam_file, p);
	}
	else if (!strcmp(optarg, "crlfile")) {
	    if (tls_crl_file)
	    	free(tls_crl_file);
	    if (tls_crl_file = malloc(strlen(p) + 1))
	    	strcpy(tls_crl_file, p);
	}
	else if (!strcmp(optarg, "crldir")) {
	    if (tls_crl_dir)
	    	free(tls_crl_dir);
	    if (tls_crl_dir = malloc(strlen(p) + 1))
	    	strcpy(tls_crl_dir, p);
	}
	else if (!strcmp(optarg, "cipher")) {
	    if (tls_cipher_list)
	    	free(tls_cipher_list);
	    if ((tls_cipher_list = malloc(strlen(p) + 1)))
	    	strcpy(tls_cipher_list, p);
	}
    }
    else if (!strcmp(optarg, "tls-required"))
    	tls_required = 1;
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

    if (!tls_active)
        return(0);

    cipher = SSL_get_current_cipher(ssl);
    if (cipher && SSL_CIPHER_description(cipher,buf,sizeof(buf))) {
        if (strstr(buf,"Au=KRB5") != NULL)
            return(1);                  /* krb5 */
    }
#endif /* TLS_KRB5 */
    return(0);                          /* not krb5 */
}

char *tls_get_subject_name(SSL *ssl)
{
    static char name[256];
    X509 *cert;

    if ((cert = SSL_get_peer_certificate(ssl))) {
	char *n = x509_name_oneline(X509_get_subject_name(cert), name, sizeof(name));
	X509_free(cert);
	return n;
    }
    else
	return NULL;
}

/* check_file() expands 'file' to an existing full path or NULL if not found */
void check_file(char **file)
{
    char *p;
    
    if (*file) {
    	p = file_fullpath(*file);
	if (p == *file)	/* same pointer returned from file_fullpath() */
	    return;
	free(*file);
	if (p) {
	    *file = malloc(strlen(p) + 1);
	    strcpy(*file, p);
	}
	else
	    *file = NULL;
    }
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

#ifdef TLS_KRB5
    if (tls_is_krb5()) 
        return ok;
#endif /* TLS_KRB5 */

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
            fprintf(stderr, "Invalid signature on CRL!\n");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }

        /*
         * Check date of CRL to make sure it's not expired
         */
        i = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));
        if (i == 0) {
            fprintf(stderr, "Found CRL has invalid nextUpdate field.\n");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }
        if (i < 0) {
            fprintf(stderr,
		"Found CRL is expired - revoking all certificates until you get updated CRL.\n");
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
                syslog(LOG_INFO,
		    "Certificate with serial %ld (0x%lX) revoked per CRL from issuer %s",
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

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
/*    fprintf(stderr, "depth = %d, error = %d, ok = %d\n", ctx->error_depth, ctx->error, ok);*/
/* TODO: Make up my mind on what to accept or not. Also what to syslog. */
/* TODO: The client has a little different verify_callback(), should it be
 *       like that here too?
 */
#ifdef TLS_KRB5 
    if (tls_is_krb5())
        return 1;
#endif /* TLS_KRB5 */

    ok =  verify_crl(ok, ctx);
    if (!ok) {
    	switch (ctx->error) {
	    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	    	syslog(LOG_INFO, "Error: Client's certificate is self signed.");
		ok = 0;
		break;
	    case X509_V_ERR_CERT_HAS_EXPIRED:
	    	syslog(LOG_INFO, "Error: Client's certificate has expired.");
		ok = 0;
		break;
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	    	syslog(LOG_INFO,
		    "Error: Client's certificate issuer's certificate isn't available locally.");
		ok = 0;
		break;
	    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	    	syslog(LOG_INFO, "Error: Unable to verify leaf signature.");
		ok = 0;
		break;
	    case X509_V_ERR_CERT_REVOKED:
	    	syslog(LOG_INFO, "Error: Certificate revoked.");
		ok = 0;
		break;
	    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		/* XXX this is strange. we get this error for certain clients (ie Jeff's
		 * K95) when all is ok. I think it's because the client is actually sending
		 * the whole CA cert. this must be figured out, but we let it pass for now.
		 * if the CA cert isn't available locally, we will fail anyway.
		 */
	    	syslog(LOG_INFO, "Warning: Self signed certificate in chain.");
		ok = 1;
		break;
	    default:
	    	syslog(LOG_INFO,
		    "Error: Error %d while verifying server's certificate.", ctx->error);
		ok = 0;
	    	break;
	}
    }
    return ok;
}

int seed_PRNG(void)
{
    char stackdata[1024];
    static char rand_file[200];
    FILE *fh;
    
#if OPENSSL_VERSION_NUMBER >= 0x00905100
    if (RAND_status())
	return 0;     /* PRNG already good seeded */
#endif
    /* if the device '/dev/urandom' is present, OpenSSL uses it by default.
     * check if it's present, else we have to make random data ourselfs.
     */
    if (fh = fopen("/dev/urandom", "r")) {
	fclose(fh);
	return 0;
    }
    /* the telnetd's rand file is (openssl-dir)/.rnd */
    snprintf(rand_file, sizeof(rand_file), "%s/.rnd", X509_get_default_cert_area());
    tls_rand_file = rand_file;
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

#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif

#define TLS_SFC_MAX_FILES	100
struct sockaddr_in peer_saddr;

FILE *make_sfc_file(void)
{
    DIR *dir;
    char filename[MAXPATHLEN];
    int n, fd;

    dir = opendir(TLS_SFC_DIR);
    /* if the TLS_SFC_DIR dir doesn't exist, we consider this function disabled */
    if (dir == NULL)
	return NULL;
    closedir(dir);
    if (peer_saddr.sin_addr.s_addr == 0)
	return NULL;
    /* the file name is based on the hexadecimal representation of the peer's
     * ip address, with `oss' (from `OpenSsl Session') as a prefix and a index
     * number as a postfix.
     * example: connected to 127.0.0.1 -> `oss7F000001.1'
     */
    /* try to create a file withing the range of TLS_SFC_MAX_FILES */
    for (n = 1; n <= TLS_SFC_MAX_FILES; n++) {
	snprintf(filename, sizeof(filename), "%s/oss%08X.%d",
		 TLS_SFC_DIR, htonl(peer_saddr.sin_addr.s_addr), n);
	/* fopen() doesn't seem to be able to do this atomically, but
	 * this open() call fails if `filename' exist.
	 */
	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
	    if (errno != EEXIST)
		return NULL;	     /* some other error */
	} else
	    return fdopen(fd, "w");  /* success! */
    }
    return NULL;
}

int session_timed_out(SSL_SESSION *s)
{
    if (SSL_SESSION_get_time(s) + SSL_SESSION_get_timeout(s) < time(NULL))
	return 1;
    else
	return 0;
}

int tls_sfc_server_load(SSL_CTX *sc)
{
    int saddr_len = sizeof(peer_saddr), match_len;
    FILE *file;
    DIR *dir;
    struct dirent *de;
    char filename[MAXPATHLEN], match[16];
    
    if (sc == NULL)
	return 1;
    memset(&peer_saddr, 0, sizeof(peer_saddr));
    if (getpeername(net, (struct sockaddr *)&peer_saddr, &saddr_len) != 0)
	return 2;
    dir = opendir(TLS_SFC_DIR);
    /* if the TLS_SFC_DIR dir doesn't exist, we consider this function disabled */
    if (dir == NULL)
	return 0;
    snprintf(match, sizeof(match), "oss%08X", htonl(peer_saddr.sin_addr.s_addr));
    match_len = strlen(match);
    /* search the dir for files matching the peer's ip address */
    while ((de = readdir(dir))) {
	if (!strncmp(de->d_name, match, match_len)) {
	    snprintf(filename, sizeof(filename), "%s/%s", TLS_SFC_DIR, de->d_name);
	    file = fopen(filename, "r");
	    if (file) {
		SSL_SESSION *sess;
		sess = PEM_read_SSL_SESSION(file, NULL, NULL, NULL);
		if (sess) {
		    /* ``refresh'' the session timeout */
/*XXX		    SSL_SESSION_set_time(sess, time(NULL)); */
		    if (session_timed_out(sess))
			/* a safer way to delete the old file perhaps? */
			unlink(filename);
		    else
			SSL_CTX_add_session(sc, sess);
		    /* dec the ref counter in sess so it will eventually be freed */
		    SSL_SESSION_free(sess);
		}
		fclose(file);
	    }
	}
    }
    closedir(dir);
    return 0;
}

int tls_sfc_new_session_cb(SSL * ssl, SSL_SESSION * sess)
{
    FILE *file;
    file = make_sfc_file();
    if (file) {
        PEM_write_SSL_SESSION(file, sess);
        fclose(file);
    }
    return 0;
}

#endif /* TLS_SESSION_FILE_CACHE */

#ifdef TLS_KRB5
#ifndef KRB5_SERVICE_NAME
#define KRB5_SERVICE_NAME    "host"
#endif 
#ifndef KRB5_KEYTAB
#define KRB5_KEYTAB          "/etc/krb5.keytab"
#endif
#endif 

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
    if (seed_PRNG())
	syslog(LOG_INFO, "Wasn't able to properly seed the PRNG!\r\n");
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
	fprintf(stderr, "SSL_CTX_new() %s\n",
		(char *)ERR_error_string(ERR_get_error(), NULL));
	return 1;
    }
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_default_verify_paths(ssl_ctx);

    /* let's find out which files are available */
    check_file(&tls_rsa_cert_file);
    check_file(&tls_rsa_cert_chain_file);
    check_file(&tls_rsa_key_file);
    check_file(&tls_dsa_cert_file);
    check_file(&tls_dsa_cert_chain_file);
    check_file(&tls_dsa_key_file);
    check_file(&tls_crl_file);
    check_file(&tls_dhparam_file);
    if (!tls_rsa_cert_file && !tls_rsa_cert_chain_file &&
		!tls_dsa_cert_file && !tls_dsa_cert_chain_file) {
#ifdef AUTHENTICATION
	tls_anon = 1;
#else
    	fprintf(stderr, "No certificate files found!\n");
	return 2;
#endif /* AUTHENTICATION */
    }
#ifndef NO_RSA
    if (!tls_rsa_key_file)
    	tls_rsa_key_file = tls_rsa_cert_file;
#endif
    if (!tls_dsa_key_file)
    	tls_dsa_key_file = tls_dsa_cert_file;

#ifndef NO_RSA    
    if (tls_rsa_cert_file) {
	err = SSL_CTX_use_certificate_file(ssl_ctx, tls_rsa_cert_file, X509_FILETYPE_PEM);
	if (err <= 0) {
	    fprintf(stderr, "SSL_CTX_use_certificate_file(%s) %s\n", tls_rsa_cert_file,
		(char *)ERR_error_string(ERR_get_error(), NULL));
	    return 3;
	}
	if (!tls_rsa_key_file)
	    tls_rsa_key_file = tls_rsa_cert_file;
    }
    /* if you are using a chain file, the server's cert is supposed to be included
     * first in the file, and takes presence over a cert file.
     */
    if (tls_rsa_cert_chain_file) {
	err = SSL_CTX_use_certificate_chain_file(ssl_ctx, tls_rsa_cert_chain_file);
	if (err <= 0) {
	    fprintf(stderr, "SSL_CTX_use_certificate_chain_file(%s) %s\n",
		    tls_rsa_cert_chain_file,
		    (char *)ERR_error_string(ERR_get_error(), NULL));
	    return 4;
	}
	if (!tls_rsa_key_file || tls_rsa_key_file == tls_rsa_cert_file)
	    tls_rsa_key_file = tls_rsa_cert_chain_file;
    }
    if (tls_rsa_key_file) {
	err = SSL_CTX_use_PrivateKey_file(ssl_ctx, tls_rsa_key_file, X509_FILETYPE_PEM);
	if (err <= 0) {
	    fprintf(stderr, "SSL_CTX_use_PrivateKey_file(%s) %s\n", tls_rsa_key_file,
	    	(char *)ERR_error_string(ERR_get_error(), NULL));
	    return 5;
	}
    }
#endif /* NO_RSA */
    if (tls_dsa_cert_file) {
	err = SSL_CTX_use_certificate_file(ssl_ctx, tls_dsa_cert_file, X509_FILETYPE_PEM);
	if (err <= 0) {
	    fprintf(stderr, "SSL_CTX_use_certificate_file(%s) %s\n", tls_dsa_cert_file,
		(char *)ERR_error_string(ERR_get_error(), NULL));
	    return 6;
	}
	if (!tls_dsa_key_file)
	    tls_dsa_key_file = tls_dsa_cert_file;
    }
    if (tls_dsa_cert_chain_file) {
	err = SSL_CTX_use_certificate_chain_file(ssl_ctx, tls_dsa_cert_chain_file);
	if (err <= 0) {
	    fprintf(stderr, "SSL_CTX_use_certificate_chain_file(%s) %s\n",
		    tls_dsa_cert_chain_file,
		    (char *)ERR_error_string(ERR_get_error(), NULL));
	    return 7;
	}
	if (!tls_dsa_key_file || tls_dsa_key_file == tls_dsa_cert_file)
	    tls_dsa_key_file = tls_dsa_cert_chain_file;
    }
    if (tls_dsa_key_file) {
	err = SSL_CTX_use_PrivateKey_file(ssl_ctx, tls_dsa_key_file, X509_FILETYPE_PEM);
	if (err <= 0) {
	    fprintf(stderr, "SSL_CTX_use_PrivateKey_file(%s) %s\n", tls_dsa_key_file,
	    	(char *)ERR_error_string(ERR_get_error(), NULL));
	    return 8;
	}
    }
    SSL_CTX_set_tmp_rsa_callback(ssl_ctx, tmp_rsa_cb);
    SSL_CTX_set_tmp_dh_callback(ssl_ctx, tmp_dh_cb);

    /* set up the CRL */
    if ((tls_crl_file || tls_crl_dir) && (crl_store = X509_STORE_new()))
	X509_STORE_load_locations(crl_store, tls_crl_file, tls_crl_dir);
    
#ifdef TLS_SESSION_FILE_CACHE
    SSL_CTX_set_session_id_context(ssl_ctx, (const unsigned char *) "1", 1);
    tls_sfc_server_load(ssl_ctx);
    SSL_CTX_sess_set_new_cb(ssl_ctx, tls_sfc_new_session_cb);
#endif /* TLS_SESSION_FILE_CACHE */
    if (tls_cipher_list)
	SSL_CTX_set_cipher_list(ssl_ctx, tls_cipher_list);
    else
	syslog(LOG_NOTICE, "NULL tls_cipher_list!");

    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
	fprintf(stderr, "SSL_new() %s\n",
		(char *)ERR_error_string(ERR_get_error(), NULL));
	return 9;
    }
    SSL_set_fd(ssl, net);

#ifdef TLS_KRB5
    ssl->kssl_ctx = kssl_ctx_new();
    kssl_ctx_setstring(ssl->kssl_ctx, KSSL_SERVICE, KRB5_SERVICE_NAME);
    kssl_ctx_setstring(ssl->kssl_ctx, KSSL_KEYTAB,  KRB5_KEYTAB);
#endif /* TLS_KRB5 */

    return 0;
}

char *
tls_userid_from_client_cert(void)
{
    static char cn[256];
    static char *r = cn;
    static int again = 0;
    int err;
    X509 *client_cert;

    if (!tls_active)
    	return NULL;

    if (again)
    	return r;
    again = 1;
    if (client_cert = SSL_get_peer_certificate(ssl)) {
    	/* call the custom function */
	err = x509_to_user(client_cert, cn, sizeof(cn));
	X509_free(client_cert);
	if (err)
	    return r = NULL;
	else
	    return r;
    }
#ifdef TLS_KRB5
    else if (tls_is_krb5()) {
        krb5_context kcontext = NULL;
        krb5_principal user = NULL;
        krb5_error_code code;

        r = NULL;

        if (ssl->kssl_ctx == NULL)
            goto k5_cleanup;

        if (ssl->kssl_ctx->client_princ == NULL)
            goto k5_cleanup;

        code = krb5_init_context(&kcontext);
        if (code) goto k5_cleanup;

        code = krb5_parse_name(kcontext,ssl->kssl_ctx->client_princ,&user);
        if (code) goto k5_cleanup;
        
        code = krb5_aname_to_localname(kcontext, user, sizeof(cn), cn);
        if (code == 0) r = cn;

      k5_cleanup:
        if (user)        krb5_free_principal(kcontext, user);
        if (kcontext)    krb5_free_context(kcontext);
    }
#endif /* TLS_KRB5 */
    else
	r = NULL;
    return r;
}

int tls_is_user_valid(char *user)
/* check if clients cert is in "user"'s ~/.tlslogin file */
{
    char buf[512];
    int r = 0;
    FILE *fp;
    X509 *client_cert, *file_cert;
    struct passwd *pwd;

    if (!tls_active)
    	return 0;

    if (!user)
	return 0;

#ifdef TLS_KRB5
    if ( tls_is_krb5() )
    {
        krb5_context kcontext = NULL;
        krb5_principal princ = NULL;
        krb5_error_code code;

        if (ssl->kssl_ctx == NULL)
            goto k5_cleanup;

        if (ssl->kssl_ctx->client_princ == NULL)
            goto k5_cleanup;

        code = krb5_init_context(&kcontext);
        if (code) goto k5_cleanup;

        code = krb5_parse_name(kcontext,ssl->kssl_ctx->client_princ,&princ);
        if (code) goto k5_cleanup;
        
        r = krb5_kuserok(kcontext, princ, user);

      k5_cleanup:
        if (princ)       krb5_free_principal(kcontext, princ);
        if (kcontext)    krb5_free_context(kcontext);
        return(r);
    }
#endif /* TLS_KRB5 */

    if (!(pwd = getpwnam(user)))
     	return 0;
    snprintf(buf, sizeof(buf), "%s/.tlslogin", pwd->pw_dir);
    if (!(fp = fopen(buf, "r")))
    	return 0;
    if (!(client_cert = SSL_get_peer_certificate(ssl))) {
    	fclose(fp);
	return 0;
    }
    while (file_cert = PEM_read_X509(fp, NULL, NULL, NULL)) {
	if (!M_ASN1_BIT_STRING_cmp(client_cert->signature, file_cert->signature))
	    r = 1;
	X509_free(file_cert);
	if (r)
	    break;
    }
    X509_free(client_cert);
    fclose(fp);
    return r;
}

int tls_start(void)
{
    int err;
    char *subject;
	
    err = SSL_accept(ssl);
    if (err < 1) {
	syslog(LOG_INFO, "SSL_accept() %s\n", (char *)ERR_error_string(ERR_get_error(), NULL));
	tls_shutdown();
	return 1;
    }
/*    fprintf(stdout, "SSL_get_verify_result() = %d\n", SSL_get_verify_result(ssl));*/
    tls_active = 1;
    syslog(LOG_INFO, "TLS connection using cipher %s (%d bits)", SSL_get_cipher(ssl),
    	SSL_get_cipher_bits(ssl, NULL));
    subject = tls_get_subject_name(ssl);
    if (subject)
	syslog(LOG_NOTICE, "Client: %s", subject);
    return 0;
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
	SSL_free(ssl);
	ssl = NULL;
    }
    if (ssl_ctx) {
	SSL_CTX_free(ssl_ctx);
	ssl_ctx = NULL;
    }
    if (tmp_dh) {
	DH_free(tmp_dh);
	tmp_dh = NULL;
    }
    if (tmp_rsa) {
	RSA_free(tmp_rsa);
	tmp_rsa = NULL;
    }
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();	/* release the stuff allocated by SSL_library_init() */
    if (tls_rsa_key_file) {
    	if (tls_rsa_key_file != tls_rsa_cert_file)
	    free(tls_rsa_key_file);
	tls_rsa_key_file = NULL;
    }
    if (tls_rsa_cert_file) {
    	free(tls_rsa_cert_file);
	tls_rsa_cert_file = NULL;
    }
    if (tls_rsa_cert_chain_file) {
    	free(tls_rsa_cert_chain_file);
	tls_rsa_cert_chain_file = NULL;
    }
    if (tls_dsa_key_file) {
    	if (tls_dsa_key_file != tls_dsa_cert_file)
	    free(tls_dsa_key_file);
	tls_dsa_key_file = NULL;
    }
    if (tls_dsa_cert_file) {
    	free(tls_dsa_cert_file);
	tls_dsa_cert_file = NULL;
    }
    if (tls_dsa_cert_chain_file) {
    	free(tls_dsa_cert_chain_file);
	tls_dsa_cert_chain_file = NULL;
    }
    if (tls_dhparam_file) {
    	free(tls_dhparam_file);
	tls_dhparam_file = NULL;
    }
    if (tls_crl_file) {
    	free(tls_crl_file);
	tls_crl_file = NULL;
    }
    if (tls_crl_dir) {
    	free(tls_crl_dir);
	tls_crl_dir = NULL;
    }
    if (tls_cipher_list) {
    	free(tls_cipher_list);
	tls_cipher_list = NULL;
    }
    if (tls_rand_file)
	RAND_write_file(tls_rand_file);
}

void handle_ssl_error(int error, char *where)
{
    switch (error) {
    	case SSL_ERROR_NONE:
	    return;
	case SSL_ERROR_SSL:
	    syslog(LOG_INFO, "unhandled SSL_ERROR_SSL in %s", where);
	    break;
	case SSL_ERROR_WANT_READ:
	    syslog(LOG_INFO, "unhandled SSL_ERROR_WANT_READ in %s", where);
	    break;
	case SSL_ERROR_WANT_WRITE:
	    syslog(LOG_INFO, "unhandled SSL_ERROR_WANT_WRITE in %s", where);
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    syslog(LOG_INFO, "unhandled SSL_ERROR_WANT_X509_LOOKUP in %s", where);
	    break;
	case SSL_ERROR_SYSCALL:
	    syslog(LOG_INFO, "unhandled SSL_ERROR_SYSCALL in %s", where);
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    syslog(LOG_INFO, "unhandled SSL_ERROR_ZERO_RETURN in %s", where);
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    syslog(LOG_INFO, "unhandled SSL_ERROR_WANT_CONNECT in %s", where);
	    break;
	default:
	    syslog(LOG_INFO, "unhandled SSL_ERROR %d in %s", error, where);
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

int tls_using_client_auth(void)
{
    X509 *cert;

#ifdef TLS_KRB5
    if (tls_is_krb5()) {
        return 1;
    } else
#endif /* TLS_KRB5 */
    if ((cert = SSL_get_peer_certificate(ssl))) {
      X509_free(cert);
      return 1;
    }
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
#error "Please upgrade to OpenSSL 0.9.5 or later"
#endif

/* We are the server, so the client is the peer */
int tls_get_client_finished(void *buf, size_t len)
{
  if(tls_active)
    return SSL_get_peer_finished(ssl, buf, len);
  else
    return 0;
}

int tls_get_server_finished(void *buf, size_t len)
{
  if(tls_active)
    return SSL_get_finished(ssl, buf, len);
  else
    return 0;
}

char *file_fullpath(char *fn)
{
    static char fp[256];
    FILE *file;
    char *dir;
    
    /* check if it is a full path already */
    if (strchr(fn, '/')) {
	if (file = fopen(fn, "r")) {
	    fclose(file);
	    return fn;
	}
	else
	    return NULL;
    }
    /* check if it is in current dir */
    if (file = fopen(fn, "r")) {
    	fclose(file);
	return fn;
    }
    if (!(dir = getenv(X509_get_default_cert_dir_env())))	/* $SSL_CERT_DIR */
    	dir = (char *)X509_get_default_cert_dir();
    snprintf(fp, sizeof(fp), "%s/%s", dir, fn);
    if (file = fopen(fp, "r")) {
    	fclose(file);
	return fp;
    }
    dir = (char *)X509_get_default_private_dir();
    snprintf(fp, sizeof(fp), "%s/%s", dir, fn);
    if (file = fopen(fp, "r")) {
    	fclose(file);
	return fp;
    }
    return NULL;
}

#endif /* TLS */
