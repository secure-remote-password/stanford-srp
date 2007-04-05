/*
 * Copyright (c) 1983, 1993
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
 *
 *	@(#)telnet.h	8.2 (Berkeley) 12/15/93
 */

 /* 
   Updated on 19/03/1999 to support current state of Telnet Internet-Drafts
   by Jeffrey Altman (The Kermit Project at Columbia University) 
   jaltman@columbia.edu
 */

#ifndef _TELNET_H_
#define	_TELNET_H_

/*
 * Definitions for the TELNET protocol.
 */
#define	IAC	255		/* interpret as command: */
#define	DONT	254		/* you are not to use option */
#define	DO	253		/* please, you use option */
#define	WONT	252		/* I won't use option */
#define	WILL	251		/* I will use option */
#define	SB	250		/* interpret as subnegotiation */
#define	GA	249		/* you may reverse the line */
#define	EL	248		/* erase the current line */
#define	EC	247		/* erase the current character */
#define	AYT	246		/* are you there */
#define	AO	245		/* abort output--but let prog finish */
#define	IP	244		/* interrupt process--permanently */
#define	BREAK	243		/* break */
#define	DM	242		/* data mark--for connect. cleaning */
#define	NOP	241		/* nop */
#define	SE	240		/* end sub negotiation */
#define EOR     239             /* end of record (transparent mode) */
#define	ABORT	238		/* Abort process */
#define	SUSP	237		/* Suspend process */
#define	xEOF	236		/* End of file: EOF is already used... */

#define SYNCH	242		/* for telfunc calls */

#ifdef TELCMDS
char *telcmds[] = {
	"EOF", "SUSP", "ABORT", "EOR",
	"SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
	"EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC", 0,
};
#else
extern char *telcmds[];
#endif

#define	TELCMD_FIRST	xEOF
#define	TELCMD_LAST	IAC
#define	TELCMD_OK(x)	((unsigned int)(x) <= TELCMD_LAST && \
			 (unsigned int)(x) >= TELCMD_FIRST)
#define	TELCMD(x)	telcmds[(x)-TELCMD_FIRST]

/* telnet options */
#define TELOPT_BINARY	0	/* 8-bit data path */
#define TELOPT_ECHO	1	/* echo */
#define	TELOPT_RCP	2	/* prepare to reconnect */
#define	TELOPT_SGA	3	/* suppress go ahead */
#define	TELOPT_NAMS	4	/* approximate message size */
#define	TELOPT_STATUS	5	/* give status */
#define	TELOPT_TM	6	/* timing mark */
#define	TELOPT_RCTE	7	/* remote controlled transmission and echo */
#define TELOPT_NAOL 	8	/* negotiate about output line width */
#define TELOPT_NAOP 	9	/* negotiate about output page size */
#define TELOPT_NAOCRD	10	/* negotiate about CR disposition */
#define TELOPT_NAOHTS	11	/* negotiate about horizontal tabstops */
#define TELOPT_NAOHTD	12	/* negotiate about horizontal tab disposition */
#define TELOPT_NAOFFD	13	/* negotiate about formfeed disposition */
#define TELOPT_NAOVTS	14	/* negotiate about vertical tab stops */
#define TELOPT_NAOVTD	15	/* negotiate about vertical tab disposition */
#define TELOPT_NAOLFD	16	/* negotiate about output LF disposition */
#define TELOPT_XASCII	17	/* extended ascic character set */
#define	TELOPT_LOGOUT	18	/* force logout */
#define	TELOPT_BM	19	/* byte macro */
#define	TELOPT_DET	20	/* data entry terminal */
#define	TELOPT_SUPDUP	21	/* supdup protocol */
#define	TELOPT_SUPDUPOUTPUT 22	/* supdup output */
#define	TELOPT_SNDLOC	23	/* send location */
#define	TELOPT_TTYPE	24	/* terminal type */
#define	TELOPT_EOR	25	/* end or record */
#define	TELOPT_TUID	26	/* TACACS user identification */
#define	TELOPT_OUTMRK	27	/* output marking */
#define	TELOPT_TTYLOC	28	/* terminal location number */
#define	TELOPT_3270REGIME 29	/* 3270 regime */
#define	TELOPT_X3PAD	30	/* X.3 PAD */
#define	TELOPT_NAWS	31	/* window size */
#define	TELOPT_TSPEED	32	/* terminal speed */
#define	TELOPT_LFLOW	33	/* remote flow control */
#define TELOPT_LINEMODE	34	/* Linemode option */
#define TELOPT_XDISPLOC	35	/* X Display Location */
#define TELOPT_OLD_ENVIRON 36	/* Old - Environment variables */
#define	TELOPT_AUTHENTICATION 37/* Authentication (RFC 2941) */
#define	TELOPT_ENCRYPT	38	/* Encryption option (RFC 2946) */
#define TELOPT_NEW_ENVIRON 39	/* New - Environment variables (RFC 1572) */
#define TELOPT_3270E    40      /* 3270 Extended (RFC 2355) */
#define TELOPT_XAUTH    41      /* ??? (Earhart) */
#define TELOPT_CHARSET  42      /* Character-set (RFC 2066) */
#define TELOPT_RSP      43      /* Remote Serial Port (Barnes) */
#define TELOPT_COM_PORT 44      /* Com Port Control (RFC 2217) */
#define TELOPT_SLE      45      /* Suppress Local Echo (Atmar) - rejected */
#define TELOPT_START_TLS 46     /* Start TLS Authentication/Encryption */
#define TELOPT_KERMIT   47      /* Kermit (Altman) (RFC 2840) */
#define TELOPT_SEND_URL 48      /* Send URL */
#define TELOPT_FORWARD_X 49	/* Forward X (Altman) */
#define TELOPT_PRAGMA_LOGON 138 /* Encrypted Logon option (PragmaSys) */
#define TELOPT_SSPI_LOGON 139   /* MS SSPI Logon option (PragmaSys) */
#define TELOPT_PRAGMA_HEARTBEAT 140 /* Server Heartbeat option (PragmaSys) */
#define TELOPT_IBM_SAK 200      /* IBM Secure Attention Key (not registered)*/

#define	TELOPT_EXOPL	255	/* extended-options-list */

#define	NTELOPTS (1+TELOPT_FORWARD_X) /* ignore knowledge of non-seq opts */
#ifdef TELOPTS
char *telopts[NTELOPTS+1] = {
	"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
	"STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP",
	"NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS",
	"NAOVTD", "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
	"DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT",
	"SEND LOCATION", "TERMINAL TYPE", "END OF RECORD",
	"TACACS UID", "OUTPUT MARKING", "TTYLOC",
	"3270 REGIME", "X.3 PAD", "NAWS", "TSPEED", "LFLOW",
	"LINEMODE", "XDISPLOC", "OLD-ENVIRON", "AUTHENTICATION",
	"ENCRYPT", "NEW-ENVIRON","TN3270E","XAUTH","CHARSET", 
	"REMOTE SERIAL PORT", "COM PORT CONTROL", "SUPPRESS LOCAL ECHO",
	"START TLS", "KERMIT", "SEND-URL", "FORWARD X",
	0,
};
#define	TELOPT_FIRST	TELOPT_BINARY
#define	TELOPT_LAST	TELOPT_FORWARD_X
#define	TELOPT_OK(x)	((unsigned int)(x) <= TELOPT_LAST)
#define	TELOPT(x)	telopts[(x)-TELOPT_FIRST]
#endif

/* sub-option qualifiers */
#define	TELQUAL_IS	0	/* option is... */
#define	TELQUAL_SEND	1	/* send option */
#define	TELQUAL_INFO	2	/* ENVIRON: informational version of IS */
#define	TELQUAL_REPLY	2	/* AUTHENTICATION: client version of IS */
#define	TELQUAL_NAME	3	/* AUTHENTICATION: client version of IS */

#define	LFLOW_OFF		0	/* Disable remote flow control */
#define	LFLOW_ON		1	/* Enable remote flow control */
#define	LFLOW_RESTART_ANY	2	/* Restart output on any char */
#define	LFLOW_RESTART_XON	3	/* Restart output only on XON */

/*
 * LINEMODE suboptions
 */

#define	LM_MODE		1
#define	LM_FORWARDMASK	2
#define	LM_SLC		3

#define	MODE_EDIT	0x01
#define	MODE_TRAPSIG	0x02
#define	MODE_ACK	0x04
#define MODE_SOFT_TAB	0x08
#define MODE_LIT_ECHO	0x10

#define	MODE_MASK	0x1f

/* Not part of protocol, but needed to simplify things... */
#define MODE_FLOW		0x0100
#define MODE_ECHO		0x0200
#define MODE_INBIN		0x0400
#define MODE_OUTBIN		0x0800
#define MODE_FORCE		0x1000

#define	SLC_SYNCH	1
#define	SLC_BRK		2
#define	SLC_IP		3
#define	SLC_AO		4
#define	SLC_AYT		5
#define	SLC_EOR		6
#define	SLC_ABORT	7
#define	SLC_EOF		8
#define	SLC_SUSP	9
#define	SLC_EC		10
#define	SLC_EL		11
#define	SLC_EW		12
#define	SLC_RP		13
#define	SLC_LNEXT	14
#define	SLC_XON		15
#define	SLC_XOFF	16
#define	SLC_FORW1	17
#define	SLC_FORW2	18

#define	NSLC		18

/*
 * For backwards compatability, we define SLC_NAMES to be the
 * list of names if SLC_NAMES is not defined.
 */
#define	SLC_NAMELIST	"0", "SYNCH", "BRK", "IP", "AO", "AYT", "EOR", \
			"ABORT", "EOF", "SUSP", "EC", "EL", "EW", "RP", \
			"LNEXT", "XON", "XOFF", "FORW1", "FORW2", 0,
#ifdef	SLC_NAMES
char *slc_names[] = {
	SLC_NAMELIST
};
#else
extern char *slc_names[];
#define	SLC_NAMES SLC_NAMELIST
#endif

#define	SLC_NAME_OK(x)	((unsigned int)(x) <= NSLC)
#define SLC_NAME(x)	slc_names[x]

#define	SLC_NOSUPPORT	0
#define	SLC_CANTCHANGE	1
#define	SLC_VARIABLE	2
#define	SLC_DEFAULT	3
#define	SLC_LEVELBITS	0x03

#define	SLC_FUNC	0
#define	SLC_FLAGS	1
#define	SLC_VALUE	2

#define	SLC_ACK		0x80
#define	SLC_FLUSHIN	0x40
#define	SLC_FLUSHOUT	0x20

#define	OLD_ENV_VAR	1
#define	OLD_ENV_VALUE	0
#define	NEW_ENV_VAR	0
#define	NEW_ENV_VALUE	1
#define	ENV_ESC		2
#define ENV_USERVAR	3

/*
 * AUTHENTICATION suboptions (RFC 2941)
 */

/*
 * Who is authenticating who ...
 */
#define	AUTH_WHO_CLIENT		0	/* Client authenticating server */
#define	AUTH_WHO_SERVER		1	/* Server authenticating client */
#define	AUTH_WHO_MASK		1

/*
 * amount of authentication done
 */
#define	AUTH_HOW_ONE_WAY	0
#define	AUTH_HOW_MUTUAL		2
#define	AUTH_HOW_MASK		2

/*
 * should we be encrypting?
 */
#define AUTH_ENCRYPT_OFF	     0
#define AUTH_ENCRYPT_USING_TELOPT    4
#define AUTH_ENCRYPT_ON		     AUTH_ENCRYPT_USING_TELOPT
#define AUTH_ENCRYPT_AFTER_EXCHANGE 16
#define AUTH_ENCRYPT_START_TLS      20
#define AUTH_ENCRYPT_MASK	    20

/*
 * will we be forwarding?
 */
#define INI_CRED_FWD_OFF	0
#define INI_CRED_FWD_ON		8
#define INI_CRED_FWD_MASK	8

/*
 * Authentication types
 *
 * AUTHTYPE values are assigned by the Internet Assigned
 * Numbers Authority under authority of the Internet Engineering
 * Task Force.  AUTHTYPE value requests may be made of IANA only
 * after an Internet-Draft describing its usage is submitted to
 * the IETF.  
 *
 *   IETF: http://www.ietf.org/
 *   IANA: http://www.iana.org/
 */

#define	AUTHTYPE_NULL		0
#define	AUTHTYPE_KERBEROS_V4	1
#define	AUTHTYPE_KERBEROS_V5	2
#define	AUTHTYPE_SPX		3
#define	AUTHTYPE_MINK		4
#define	AUTHTYPE_SRP		5
#define AUTHTYPE_RSA            6
#define AUTHTYPE_SSL            7
#define AUTHTYPE_LOKI          10
#define AUTHTYPE_SSA           11
#define AUTHTYPE_KEA_SJ        12
#define AUTHTYPE_KEA_INTEG     13
#define AUTHTYPE_DSS           14
#define AUTHTYPE_NTLM          15
#define	AUTHTYPE_CNT	       16

#define	AUTHTYPE_TEST		99

#ifdef	AUTH_NAMES
char *authtype_names[] = {
    "NULL",                     /* RFC 2941 */
    "KERBEROS_V4",              /* RFC 1411 */ 
    "KERBEROS_V5",              /* RFC 2942 */ 
    "SPX",                      /* RFC 1412 */ 
    "MINK/unassigned_4", 
    "SRP",                      /* RFC 2944 */
    "RSA",                      /* RFC 1409 */ 
    "SSL",                      /* tjh/not assigned by IANA */
    "IANA_8", 
    "IANA_9",                   /* Microsoft/not assigned by IANA */
    "LOKI",                     /* RFC 1409 */ 
    "SSA",                      /* Schoch */
    "KEA_SJ",                   /* RFC 2951 */
    "KEA_SJ_INTEG",             /* RFC 2951 */
    "DSS",                      /* RFC 2943 */
    "NTLM",                     /* Kahn <louisk@microsoft.com> */
    0
};
#else
extern char *authtype_names[];
#endif

#define	AUTHTYPE_NAME_OK(x)	((unsigned int)(x) < AUTHTYPE_CNT)
#define	AUTHTYPE_NAME(x)	authtype_names[x]

/*
 * ENCRYPTion suboptions (RFC 2946)
 */
#define	ENCRYPT_IS		0	/* I pick encryption type ... */
#define	ENCRYPT_SUPPORT		1	/* I support encryption types ... */
#define	ENCRYPT_REPLY		2	/* Initial setup response */
#define	ENCRYPT_START		3	/* Am starting to send encrypted */
#define	ENCRYPT_END		4	/* Am ending encrypted */
#define	ENCRYPT_REQSTART	5	/* Request you start encrypting */
#define	ENCRYPT_REQEND		6	/* Request you send encrypting */
#define	ENCRYPT_ENC_KEYID	7
#define	ENCRYPT_DEC_KEYID	8
#define	ENCRYPT_CNT		9

/*
 * Encryption types
 *
 * ENCTYPE values are assigned by the Internet Assigned
 * Numbers Authority under authority of the Internet Engineering
 * Task Force.  ENCTYPE value requests may be made of IANA only
 * after an Internet-Draft describing its usage is submitted to
 * the IETF.  
 *
 *   IETF: http://www.ietf.org/
 *   IANA: http://www.iana.org/
 */

#define	ENCTYPE_ANY		0
#define	ENCTYPE_DES_CFB64	1	/* RFC 2952 */
#define	ENCTYPE_DES_OFB64	2	/* RFC 2953 */
#define ENCTYPE_DES3_CFB64      3	/* RFC 2947 */
#define ENCTYPE_DES3_OFB64      4	/* RFC 2948 */
#define	ENCTYPE_CAST5_40_CFB64	8	/* RFC 2950 */
#define	ENCTYPE_CAST5_40_OFB64	9	/* RFC 2949 */
#define	ENCTYPE_CAST128_CFB64	10	/* RFC 2950 */
#define	ENCTYPE_CAST128_OFB64	11	/* RFC 2949 */
#define	ENCTYPE_CNT		12

#ifdef	ENCRYPT_NAMES
char *encrypt_names[] = {
	"IS", "SUPPORT", "REPLY", "START", "END",
	"REQUEST-START", "REQUEST-END", "ENC-KEYID", "DEC-KEYID",
	0,
};
char *enctype_names[] = {
	"ANY", "DES_CFB64",  "DES_OFB64",  "DES3_CFB64",  "DES3_OFB64",
        "UNKNOWN", "UNKNOWN",  "UNKNOWN",  "CAST5_40_CFB64",  "CAST5_40_OFB64",
	"CAST128_CFB64",  "CAST128_OFB64",  0,
};
int enctype_bits[] = {
	0, 56, 56, 168, 168, 0, 0, 0, 40, 40, 128, 128, 0
};
#else
extern char *encrypt_names[];
extern char *enctype_names[];
extern int enctype_bits[];
#endif


#define	ENCRYPT_NAME_OK(x)	((unsigned int)(x) < ENCRYPT_CNT)
#define	ENCRYPT_NAME(x)		encrypt_names[x]

#define	ENCTYPE_NAME_OK(x)	((unsigned int)(x) < ENCTYPE_CNT)
#define	ENCTYPE_NAME(x)		enctype_names[x]
#define ENCTYPE_BITS(x)		enctype_bits[x]

/*
 * START TLS suboptions
 */
#define TLS_FOLLOWS		1

/*
 * FORWARD X suboptions
 */
#define FWDX_SCREEN		0
#define FWDX_OPEN		1
#define FWDX_CLOSE		2
#define FWDX_DATA		3
#define FWDX_OPTIONS		4
#define FWDX_OPT_DATA		5
#define FWDX_XOFF               6
#define FWDX_XON                7

#define FWDX_OPT_NONE		0

#endif /* !_TELNET_H_ */
