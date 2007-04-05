
/*  A Bison parser, made from ftpcmd.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	A	257
#define	B	258
#define	C	259
#define	E	260
#define	F	261
#define	I	262
#define	L	263
#define	N	264
#define	P	265
#define	R	266
#define	S	267
#define	T	268
#define	SP	269
#define	CRLF	270
#define	COMMA	271
#define	STRING	272
#define	NUMBER	273
#define	USER	274
#define	PASS	275
#define	ACCT	276
#define	REIN	277
#define	QUIT	278
#define	PORT	279
#define	PASV	280
#define	TYPE	281
#define	STRU	282
#define	MODE	283
#define	RETR	284
#define	STOR	285
#define	APPE	286
#define	MLFL	287
#define	MAIL	288
#define	MSND	289
#define	MSOM	290
#define	MSAM	291
#define	MRSQ	292
#define	MRCP	293
#define	ALLO	294
#define	REST	295
#define	RNFR	296
#define	RNTO	297
#define	ABOR	298
#define	DELE	299
#define	CWD	300
#define	LIST	301
#define	NLST	302
#define	SITE	303
#define	STAT	304
#define	HELP	305
#define	NOOP	306
#define	MKD	307
#define	RMD	308
#define	PWD	309
#define	CDUP	310
#define	STOU	311
#define	SMNT	312
#define	SYST	313
#define	SIZE	314
#define	MDTM	315
#define	AUTH	316
#define	ADAT	317
#define	PROT	318
#define	PBSZ	319
#define	CCC	320
#define	UMASK	321
#define	IDLE	322
#define	CHMOD	323
#define	LEXERR	324

#line 42 "ftpcmd.y"


#ifndef lint
static char sccsid[] = "@(#)ftpcmd.y	5.24 (Berkeley) 2/25/91";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/ftp.h>
#include <signal.h>
#include <setjmp.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern	char *auth_type;

unsigned int maxbuf, actualbuf;
unsigned char *ucbuf;

#if defined(STDARG) || (defined(__STDC__) && ! defined(VARARGS)) || defined(HAVE_STDARG_H)
extern reply(int, char *, ...);
extern lreply(int, char *, ...);
#endif

static int kerror;	/* XXX needed for all auth types */
#ifdef KERBEROS
extern	struct sockaddr_in his_addr, ctrl_addr;
#include <krb.h>
extern AUTH_DAT kdata;
extern Key_schedule schedule;
extern MSG_DAT msg_data;
#endif /* KERBEROS */
#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
extern gss_ctx_id_t gcontext;
#endif

#ifndef unix
#ifdef _AIX
#define unix
#endif
#ifdef __hpux
#define unix
#endif
#endif

#ifndef NBBY
#ifdef linux
#define NBBY 8
#endif
#ifdef __pyrsoft
#ifdef MIPSEB
#define NBBY 8
#endif
#endif
#endif

extern	struct sockaddr_in data_dest;
extern	int logged_in;
extern	struct passwd *pw;
extern	int guest;
extern	int logging;
extern	int type;
extern	int form;
extern	int debug;
extern	int timeout;
extern	int maxtimeout;
extern  int pdata;
extern	char hostname[], remotehost[];
extern	char proctitle[];
extern	char *globerr;
extern	int usedefault;
extern  int transflag;
extern  char tmpline[];
char	**ftpglob();

off_t	restart_point;

static	int cmd_type;
static	int cmd_form;
static	int cmd_bytesz;
char	cbuf[FTP_BUFSIZ]; /* was 512 */
char	*fromname;

/* bison needs these decls up front */
extern jmp_buf errcatch;

#define	CMD	0	/* beginning of command */
#define	ARGS	1	/* expect miscellaneous arguments */
#define	STR1	2	/* expect SP followed by STRING */
#define	STR2	3	/* expect STRING */
#define	OSTR	4	/* optional SP then STRING */
#define	ZSTR1	5	/* SP then optional STRING */
#define	ZSTR2	6	/* optional STRING after SP */
#define	SITECMD	7	/* SITE command */
#define	NSTR	8	/* Number followed by a string */

struct tab {
	char	*name;
	short	token;
	short	state;
	short	implemented;	/* 1 if command is implemented */
	char	*help;
};
struct tab cmdtab[];
struct tab sitetab[];

#line 165 "ftpcmd.y"
typedef union { int num; char *str; } YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		228
#define	YYFLAG		-32768
#define	YYNTBASE	71

#define YYTRANSLATE(x) ((unsigned)(x) <= 324 ? yytranslate[x] : 87)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
    17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
    27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
    37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
    47,    48,    49,    50,    51,    52,    53,    54,    55,    56,
    57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
    67,    68,    69,    70
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     4,     7,    12,    17,    22,    26,    31,    34,
    39,    44,    49,    54,    59,    68,    74,    80,    86,    90,
    96,   100,   106,   112,   115,   121,   126,   129,   133,   139,
   142,   147,   150,   156,   162,   166,   170,   175,   182,   188,
   196,   206,   211,   218,   224,   227,   233,   239,   244,   249,
   252,   255,   261,   266,   268,   269,   271,   273,   285,   287,
   289,   291,   293,   295,   297,   299,   301,   305,   307,   311,
   313,   315,   319,   322,   324,   326,   328,   330,   332,   334,
   336,   338,   340
};

static const short yyrhs[] = {    -1,
    71,    72,     0,    71,    73,     0,    20,    15,    74,    16,
     0,    21,    15,    75,    16,     0,    25,    15,    77,    16,
     0,    26,    86,    16,     0,    64,    15,    79,    16,     0,
    66,    16,     0,    65,    15,    18,    16,     0,    27,    15,
    80,    16,     0,    28,    15,    81,    16,     0,    29,    15,
    82,    16,     0,    40,    15,    19,    16,     0,    40,    15,
    19,    15,    12,    15,    19,    16,     0,    30,    86,    15,
    83,    16,     0,    31,    86,    15,    83,    16,     0,    32,
    86,    15,    83,    16,     0,    48,    86,    16,     0,    48,
    86,    15,    18,    16,     0,    47,    86,    16,     0,    47,
    86,    15,    18,    16,     0,    50,    86,    15,    83,    16,
     0,    50,    16,     0,    45,    86,    15,    83,    16,     0,
    43,    15,    83,    16,     0,    44,    16,     0,    46,    86,
    16,     0,    46,    86,    15,    83,    16,     0,    51,    16,
     0,    51,    15,    18,    16,     0,    52,    16,     0,    53,
    86,    15,    83,    16,     0,    54,    86,    15,    83,    16,
     0,    55,    86,    16,     0,    56,    86,    16,     0,    49,
    15,    51,    16,     0,    49,    15,    51,    15,    18,    16,
     0,    49,    15,    67,    86,    16,     0,    49,    15,    67,
    86,    15,    85,    16,     0,    49,    15,    69,    86,    15,
    85,    15,    83,    16,     0,    49,    15,    68,    16,     0,
    49,    15,    68,    15,    19,    16,     0,    57,    86,    15,
    83,    16,     0,    59,    16,     0,    60,    86,    15,    83,
    16,     0,    61,    86,    15,    83,    16,     0,    62,    15,
    18,    16,     0,    63,    15,    18,    16,     0,    24,    16,
     0,     1,    16,     0,    42,    86,    15,    83,    16,     0,
    41,    15,    76,    16,     0,    18,     0,     0,    18,     0,
    19,     0,    19,    17,    19,    17,    19,    17,    19,    17,
    19,    17,    19,     0,    10,     0,    14,     0,     5,     0,
     5,     0,    13,     0,    11,     0,     6,     0,     3,     0,
     3,    15,    78,     0,     6,     0,     6,    15,    78,     0,
     8,     0,     9,     0,     9,    15,    76,     0,     9,    76,
     0,     7,     0,    12,     0,    11,     0,    13,     0,     4,
     0,     5,     0,    84,     0,    18,     0,    19,     0,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   198,   199,   204,   207,   212,   217,   226,   231,   238,   242,
   268,   303,   315,   327,   331,   335,   342,   349,   356,   361,
   368,   373,   380,   387,   391,   398,   409,   413,   418,   425,
   429,   444,   448,   455,   462,   467,   472,   476,   480,   490,
   505,   519,   525,   539,   546,   570,   587,   609,   613,   618,
   623,   628,   640,   649,   652,   656,   659,   662,   675,   679,
   683,   689,   693,   697,   701,   707,   712,   717,   722,   727,
   731,   736,   742,   749,   753,   757,   763,   767,   771,   777,
   816,   819,   844
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","A","B",
"C","E","F","I","L","N","P","R","S","T","SP","CRLF","COMMA","STRING","NUMBER",
"USER","PASS","ACCT","REIN","QUIT","PORT","PASV","TYPE","STRU","MODE","RETR",
"STOR","APPE","MLFL","MAIL","MSND","MSOM","MSAM","MRSQ","MRCP","ALLO","REST",
"RNFR","RNTO","ABOR","DELE","CWD","LIST","NLST","SITE","STAT","HELP","NOOP",
"MKD","RMD","PWD","CDUP","STOU","SMNT","SYST","SIZE","MDTM","AUTH","ADAT","PROT",
"PBSZ","CCC","UMASK","IDLE","CHMOD","LEXERR","cmd_list","cmd","rcmd","username",
"password","byte_size","host_port","form_code","prot_code","type_code","struct_code",
"mode_code","pathname","pathstring","octal_number","check_login", NULL
};
#endif

static const short yyr1[] = {     0,
    71,    71,    71,    72,    72,    72,    72,    72,    72,    72,
    72,    72,    72,    72,    72,    72,    72,    72,    72,    72,
    72,    72,    72,    72,    72,    72,    72,    72,    72,    72,
    72,    72,    72,    72,    72,    72,    72,    72,    72,    72,
    72,    72,    72,    72,    72,    72,    72,    72,    72,    72,
    72,    73,    73,    74,    75,    75,    76,    77,    78,    78,
    78,    79,    79,    79,    79,    80,    80,    80,    80,    80,
    80,    80,    80,    81,    81,    81,    82,    82,    82,    83,
    84,    85,    86
};

static const short yyr2[] = {     0,
     0,     2,     2,     4,     4,     4,     3,     4,     2,     4,
     4,     4,     4,     4,     8,     5,     5,     5,     3,     5,
     3,     5,     5,     2,     5,     4,     2,     3,     5,     2,
     4,     2,     5,     5,     3,     3,     4,     6,     5,     7,
     9,     4,     6,     5,     2,     5,     5,     4,     4,     2,
     2,     5,     4,     1,     0,     1,     1,    11,     1,     1,
     1,     1,     1,     1,     1,     1,     3,     1,     3,     1,
     1,     3,     2,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     0
};

static const short yydefact[] = {     1,
     0,     0,     0,     0,     0,     0,    83,     0,     0,     0,
    83,    83,    83,     0,     0,    83,     0,     0,    83,    83,
    83,    83,     0,    83,     0,     0,    83,    83,    83,    83,
    83,     0,    83,    83,     0,     0,     0,     0,     0,     2,
     3,    51,     0,    55,    50,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,    27,     0,     0,
     0,     0,     0,    24,     0,     0,    30,    32,     0,     0,
     0,     0,     0,    45,     0,     0,     0,     0,     0,     0,
     9,    54,     0,    56,     0,     0,     0,     7,    66,    68,
    70,    71,     0,    74,    76,    75,     0,    78,    79,    77,
     0,     0,     0,     0,     0,    57,     0,     0,    81,     0,
    80,     0,     0,    28,     0,    21,     0,    19,     0,    83,
     0,    83,     0,     0,     0,     0,    35,    36,     0,     0,
     0,     0,     0,    62,    65,    64,    63,     0,     0,     4,
     5,     0,     6,     0,     0,     0,    73,    11,    12,    13,
     0,     0,     0,     0,    14,    53,     0,    26,     0,     0,
     0,     0,     0,    37,     0,     0,    42,     0,     0,    31,
     0,     0,     0,     0,     0,    48,    49,     8,    10,     0,
    61,    59,    60,    67,    69,    72,    16,    17,    18,     0,
    52,    25,    29,    22,    20,     0,     0,    39,     0,     0,
    23,    33,    34,    44,    46,    47,     0,     0,    38,    82,
     0,    43,     0,     0,     0,    40,     0,     0,    15,     0,
     0,    41,     0,     0,     0,    58,     0,     0
};

static const short yydefgoto[] = {     1,
    40,    41,    83,    85,   107,    87,   184,   138,    93,    97,
   101,   110,   111,   211,    47
};

static const short yypact[] = {-32768,
    36,   -13,   -10,    -2,    26,    60,-32768,    79,    92,    99,
-32768,-32768,-32768,   105,   106,-32768,   107,    35,-32768,-32768,
-32768,-32768,   108,   109,    10,   110,-32768,-32768,-32768,-32768,
-32768,   111,-32768,-32768,   113,   114,   115,   116,   117,-32768,
-32768,-32768,     0,     1,-32768,   118,   119,   100,    62,     4,
   121,   123,   125,   124,   126,   127,   128,-32768,   129,    18,
    29,    89,     3,-32768,   132,   130,-32768,-32768,   134,   135,
   136,   137,   139,-32768,   140,   141,   133,   142,     9,   143,
-32768,-32768,   146,-32768,   147,   148,   150,-32768,   144,   149,
-32768,    40,   151,-32768,-32768,-32768,   152,-32768,-32768,-32768,
   153,   128,   128,   128,    95,-32768,   154,   128,-32768,   155,
-32768,   128,   128,-32768,   156,-32768,   157,-32768,    97,-32768,
   101,-32768,   128,   160,   128,   128,-32768,-32768,   128,   128,
   128,   161,   162,-32768,-32768,-32768,-32768,   163,   164,-32768,
-32768,   138,-32768,     2,     2,   126,-32768,-32768,-32768,-32768,
   165,   166,   167,   112,-32768,-32768,   168,-32768,   169,   170,
   171,   172,   173,-32768,   103,   174,-32768,   158,   176,-32768,
   178,   179,   180,   181,   182,-32768,-32768,-32768,-32768,   183,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,   175,
-32768,-32768,-32768,-32768,-32768,   185,   184,-32768,   186,   184,
-32768,-32768,-32768,-32768,-32768,-32768,   187,   188,-32768,-32768,
   189,-32768,   193,   192,   194,-32768,   128,   195,-32768,   196,
   198,-32768,   197,   200,   199,-32768,   204,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,   -88,-32768,   -11,-32768,-32768,-32768,
-32768,  -102,-32768,   -68,    19
};


#define	YYLAST		218


static const short yytable[] = {   151,
   152,   153,    42,   147,    43,   157,   181,    98,    99,   159,
   160,   182,    44,   134,   135,   183,   100,    82,    84,   136,
   169,   137,   171,   172,    66,    67,   173,   174,   175,    51,
    52,    53,   113,   114,    56,   227,     2,    59,    60,    61,
    62,    45,    65,   115,   116,    69,    70,    71,    72,    73,
    58,    75,    76,   119,   146,     3,     4,   186,   106,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    94,   120,
   121,   122,    95,    96,    46,    14,    15,    16,    17,    18,
    19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
    29,    30,    31,    48,    32,    33,    34,    35,    36,    37,
    38,    39,    89,   117,   118,    90,    49,    91,    92,   154,
   155,   163,   164,    50,   220,   166,   167,   197,   198,    54,
    55,    57,    63,   190,    64,    68,    74,    77,    78,    79,
    80,   213,    81,   185,    88,   102,    86,   103,   165,   104,
   168,   108,   105,   112,   106,   109,   123,   124,   125,   126,
   132,   127,   128,   129,   130,   131,   180,     0,   144,   133,
   139,   140,   141,   145,   142,   143,   148,   149,   150,   156,
   158,     0,   200,   161,   162,   170,   176,   177,   178,   179,
   187,   188,   189,   191,   192,   193,   194,   195,     0,   208,
   196,   201,   199,   202,   203,   204,   205,   206,     0,   207,
   209,   212,   210,   228,   216,   214,   215,   217,   218,   219,
     0,   222,     0,   221,   223,   224,   225,   226
};

static const short yycheck[] = {   102,
   103,   104,    16,    92,    15,   108,     5,     4,     5,   112,
   113,    10,    15,     5,     6,    14,    13,    18,    18,    11,
   123,    13,   125,   126,    15,    16,   129,   130,   131,    11,
    12,    13,    15,    16,    16,     0,     1,    19,    20,    21,
    22,    16,    24,    15,    16,    27,    28,    29,    30,    31,
    16,    33,    34,    51,    15,    20,    21,   146,    19,    24,
    25,    26,    27,    28,    29,    30,    31,    32,     7,    67,
    68,    69,    11,    12,    15,    40,    41,    42,    43,    44,
    45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
    55,    56,    57,    15,    59,    60,    61,    62,    63,    64,
    65,    66,     3,    15,    16,     6,    15,     8,     9,    15,
    16,    15,    16,    15,   217,    15,    16,    15,    16,    15,
    15,    15,    15,    12,    16,    16,    16,    15,    15,    15,
    15,   200,    16,   145,    16,    15,    19,    15,   120,    15,
   122,    15,    19,    15,    19,    18,    15,    18,    15,    15,
    18,    16,    16,    15,    15,    15,    19,    -1,    15,    18,
    18,    16,    16,    15,    17,    16,    16,    16,    16,    16,
    16,    -1,    15,    18,    18,    16,    16,    16,    16,    16,
    16,    16,    16,    16,    16,    16,    16,    16,    -1,    15,
    18,    16,    19,    16,    16,    16,    16,    16,    -1,    17,
    16,    16,    19,     0,    16,    19,    19,    15,    17,    16,
    -1,    16,    -1,    19,    17,    19,    17,    19
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/lib/bison.simple"
/* This file comes from bison-1.28.  */

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

#ifndef YYSTACK_USE_ALLOCA
#ifdef alloca
#define YYSTACK_USE_ALLOCA
#else /* alloca not defined */
#ifdef __GNUC__
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi) || (defined (__sun) && defined (__i386))
#define YYSTACK_USE_ALLOCA
#include <alloca.h>
#else /* not sparc */
/* We think this test detects Watcom and Microsoft C.  */
/* This used to test MSDOS, but that is a bad idea
   since that symbol is in the user namespace.  */
#if (defined (_MSDOS) || defined (_MSDOS_)) && !defined (__TURBOC__)
#if 0 /* No need for malloc.h, which pollutes the namespace;
	 instead, just don't use alloca.  */
#include <malloc.h>
#endif
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
/* I don't know what this was needed for, but it pollutes the namespace.
   So I turned it off.   rms, 2 May 1997.  */
/* #include <malloc.h>  */
 #pragma alloca
#define YYSTACK_USE_ALLOCA
#else /* not MSDOS, or __TURBOC__, or _AIX */
#if 0
#ifdef __hpux /* haible@ilog.fr says this works for HPUX 9.05 and up,
		 and on HPUX 10.  Eventually we can turn this on.  */
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#endif /* __hpux */
#endif
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc */
#endif /* not GNU C */
#endif /* alloca not defined */
#endif /* YYSTACK_USE_ALLOCA not defined */

#ifdef YYSTACK_USE_ALLOCA
#define YYSTACK_ALLOC alloca
#else
#define YYSTACK_ALLOC malloc
#endif

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Define __yy_memcpy.  Note that the size argument
   should be passed with type unsigned int, because that is what the non-GCC
   definitions require.  With GCC, __builtin_memcpy takes an arg
   of type size_t, but it can handle unsigned int.  */

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (to, from, count)
     char *to;
     char *from;
     unsigned int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *to, char *from, unsigned int count)
{
  register char *t = to;
  register char *f = from;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 217 "/usr/lib/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
#ifdef YYPARSE_PARAM
int yyparse (void *);
#else
int yyparse (void);
#endif
#endif

int
yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;
  int yyfree_stacks = 0;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  if (yyfree_stacks)
	    {
	      free (yyss);
	      free (yyvs);
#ifdef YYLSP_NEEDED
	      free (yyls);
#endif
	    }
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
#ifndef YYSTACK_USE_ALLOCA
      yyfree_stacks = 1;
#endif
      yyss = (short *) YYSTACK_ALLOC (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss, (char *)yyss1,
		   size * (unsigned int) sizeof (*yyssp));
      yyvs = (YYSTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs, (char *)yyvs1,
		   size * (unsigned int) sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls, (char *)yyls1,
		   size * (unsigned int) sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 2:
#line 200 "ftpcmd.y"
{
			fromname = (char *) 0;
			restart_point = (off_t) 0;
		;
    break;}
case 4:
#line 208 "ftpcmd.y"
{
			user((char *) yyvsp[-1].str);
			free((char *) yyvsp[-1].str);
		;
    break;}
case 5:
#line 213 "ftpcmd.y"
{
			pass((char *) yyvsp[-1].str);
			free((char *) yyvsp[-1].str);
		;
    break;}
case 6:
#line 218 "ftpcmd.y"
{
			usedefault = 0;
			if (pdata >= 0) {
				(void) close(pdata);
				pdata = -1;
			}
			reply(200, "PORT command successful.");
		;
    break;}
case 7:
#line 227 "ftpcmd.y"
{
			if (yyvsp[-1].num)
				passive();
		;
    break;}
case 8:
#line 232 "ftpcmd.y"
{
		    if (maxbuf)
			setlevel (yyvsp[-1].num);
		    else
			reply(503, "Must first set PBSZ");
		;
    break;}
case 9:
#line 239 "ftpcmd.y"
{
			reply(534, "CCC not supported");
		;
    break;}
case 10:
#line 243 "ftpcmd.y"
{
			/* Others may want to do something more fancy here */
			if (!auth_type)
			    reply(503, "Must first perform authentication");
			else if (strlen(yyvsp[-1].str) > 10 ||
				 strlen(yyvsp[-1].str) == 10 && strcmp(yyvsp[-1].str,"4294967296") >= 0)
			    reply(501, "Bad value for PBSZ: %s", yyvsp[-1].str);
			else if (actualbuf >= (maxbuf =(unsigned int) atol(yyvsp[-1].str)))
			    reply(200, "PBSZ=%u", actualbuf);
			else {
			    if (ucbuf) (void) free(ucbuf);
			    actualbuf = (unsigned int) atol(yyvsp[-1].str);
			    /* I attempt what is asked for first, and if that
			       fails, I try dividing by 4 */
			    while ((ucbuf = (unsigned char *)malloc(actualbuf)) == NULL)
				if (actualbuf)
				    lreply(200, "Trying %u", actualbuf >>= 2);
				else {
				    perror_reply(421,
					"Local resource failure: malloc");
				    dologout(1);
				}
			    reply(200, "PBSZ=%u", maxbuf = actualbuf);
			}
		;
    break;}
case 11:
#line 269 "ftpcmd.y"
{
			switch (cmd_type) {

			case TYPE_A:
				if (cmd_form == FORM_N) {
					reply(200, "Type set to A.");
					type = cmd_type;
					form = cmd_form;
				} else
					reply(504, "Form must be N.");
				break;

			case TYPE_E:
				reply(504, "Type E not implemented.");
				break;

			case TYPE_I:
				reply(200, "Type set to I.");
				type = cmd_type;
				break;

			case TYPE_L:
#if NBBY == 8
				if (cmd_bytesz == 8) {
					reply(200,
					    "Type set to L (byte size 8).");
					type = cmd_type;
				} else
					reply(504, "Byte size must be 8.");
#else /* NBBY == 8 */
				UNIMPLEMENTED for NBBY != 8
#endif /* NBBY == 8 */
			}
		;
    break;}
case 12:
#line 304 "ftpcmd.y"
{
			switch (yyvsp[-1].num) {

			case STRU_F:
				reply(200, "STRU F ok.");
				break;

			default:
				reply(504, "Unimplemented STRU type.");
			}
		;
    break;}
case 13:
#line 316 "ftpcmd.y"
{
			switch (yyvsp[-1].num) {

			case MODE_S:
				reply(200, "MODE S ok.");
				break;

			default:
				reply(502, "Unimplemented MODE type.");
			}
		;
    break;}
case 14:
#line 328 "ftpcmd.y"
{
			reply(202, "ALLO command ignored.");
		;
    break;}
case 15:
#line 332 "ftpcmd.y"
{
			reply(202, "ALLO command ignored.");
		;
    break;}
case 16:
#line 336 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				retrieve((char *) 0, (char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 17:
#line 343 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				store_file((char *) yyvsp[-1].str, "w", 0);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 18:
#line 350 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				store_file((char *) yyvsp[-1].str, "a", 0);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 19:
#line 357 "ftpcmd.y"
{
			if (yyvsp[-1].num)
				send_file_list(".");
		;
    break;}
case 20:
#line 362 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL) 
				send_file_list((char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 21:
#line 369 "ftpcmd.y"
{
			if (yyvsp[-1].num)
				retrieve("/bin/ls -lgA", "");
		;
    break;}
case 22:
#line 374 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				retrieve("/bin/ls -lgA %s", (char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 23:
#line 381 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				statfilecmd((char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 24:
#line 388 "ftpcmd.y"
{
			statcmd();
		;
    break;}
case 25:
#line 392 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				delete_file((char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 26:
#line 399 "ftpcmd.y"
{
			if (fromname) {
				renamecmd(fromname, (char *) yyvsp[-1].str);
				free(fromname);
				fromname = (char *) 0;
			} else {
				reply(503, "Bad sequence of commands.");
			}
			free((char *) yyvsp[-1].str);
		;
    break;}
case 27:
#line 410 "ftpcmd.y"
{
			reply(225, "ABOR command successful.");
		;
    break;}
case 28:
#line 414 "ftpcmd.y"
{
			if (yyvsp[-1].num)
				cwd(pw->pw_dir);
		;
    break;}
case 29:
#line 419 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				cwd((char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 30:
#line 426 "ftpcmd.y"
{
			help(cmdtab, (char *) 0);
		;
    break;}
case 31:
#line 430 "ftpcmd.y"
{
			register char *cp = (char *)yyvsp[-1].str;

			if (strncasecmp(cp, "SITE", 4) == 0) {
				cp = (char *)yyvsp[-1].str + 4;
				if (*cp == ' ')
					cp++;
				if (*cp)
					help(sitetab, cp);
				else
					help(sitetab, (char *) 0);
			} else
				help(cmdtab, (char *) yyvsp[-1].str);
		;
    break;}
case 32:
#line 445 "ftpcmd.y"
{
			reply(200, "NOOP command successful.");
		;
    break;}
case 33:
#line 449 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				makedir((char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 34:
#line 456 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				removedir((char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 35:
#line 463 "ftpcmd.y"
{
			if (yyvsp[-1].num)
				pwd();
		;
    break;}
case 36:
#line 468 "ftpcmd.y"
{
			if (yyvsp[-1].num)
				cwd("..");
		;
    break;}
case 37:
#line 473 "ftpcmd.y"
{
			help(sitetab, (char *) 0);
		;
    break;}
case 38:
#line 477 "ftpcmd.y"
{
			help(sitetab, (char *) yyvsp[-1].str);
		;
    break;}
case 39:
#line 481 "ftpcmd.y"
{
			int oldmask;

			if (yyvsp[-1].num) {
				oldmask = umask(0);
				(void) umask(oldmask);
				reply(200, "Current UMASK is %03o", oldmask);
			}
		;
    break;}
case 40:
#line 491 "ftpcmd.y"
{
			int oldmask;

			if (yyvsp[-3].num) {
				if ((yyvsp[-1].num == -1) || (yyvsp[-1].num > 0777)) {
					reply(501, "Bad UMASK value");
				} else {
					oldmask = umask(yyvsp[-1].num);
					reply(200,
					    "UMASK set to %03o (was %03o)",
					    yyvsp[-1].num, oldmask);
				}
			}
		;
    break;}
case 41:
#line 506 "ftpcmd.y"
{
			if (yyvsp[-5].num && (yyvsp[-1].str != NULL)) {
				if (yyvsp[-3].num > 0777)
					reply(501,
				"CHMOD: Mode value must be between 0 and 0777");
				else if (chmod((char *) yyvsp[-1].str, yyvsp[-3].num) < 0)
					perror_reply(550, (char *) yyvsp[-1].str);
				else
					reply(200, "CHMOD command successful.");
			}
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 42:
#line 520 "ftpcmd.y"
{
			reply(200,
			    "Current IDLE time limit is %d seconds; max %d",
				timeout, maxtimeout);
		;
    break;}
case 43:
#line 526 "ftpcmd.y"
{
			if (yyvsp[-1].num < 30 || yyvsp[-1].num > maxtimeout) {
				reply(501,
			"Maximum IDLE time must be between 30 and %d seconds",
				    maxtimeout);
			} else {
				timeout = yyvsp[-1].num;
				(void) alarm((unsigned) timeout);
				reply(200,
				    "Maximum IDLE time set to %d seconds",
				    timeout);
			}
		;
    break;}
case 44:
#line 540 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				store_file((char *) yyvsp[-1].str, "w", 1);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 45:
#line 547 "ftpcmd.y"
{
#ifdef unix
#ifdef __svr4__
#undef BSD
#endif
#ifdef BSD
			reply(215, "UNIX Type: L%d Version: BSD-%d",
				NBBY, BSD);
#else /* BSD */
			reply(215, "UNIX Type: L%d", NBBY);
#endif /* BSD */
#else /* unix */
			reply(215, "UNKNOWN Type: L%d", NBBY);
#endif /* unix */
		;
    break;}
case 46:
#line 571 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL)
				sizecmd((char *) yyvsp[-1].str);
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 47:
#line 588 "ftpcmd.y"
{
			if (yyvsp[-3].num && yyvsp[-1].str != NULL) {
				struct stat stbuf;
				if (stat((char *) yyvsp[-1].str, &stbuf) < 0)
					perror_reply(550, "%s", (char *) yyvsp[-1].str);
				else if ((stbuf.st_mode&S_IFMT) != S_IFREG) {
					reply(550, "%s: not a plain file.",
						(char *) yyvsp[-1].str);
				} else {
					register struct tm *t;
					struct tm *gmtime();
					t = gmtime(&stbuf.st_mtime);
					reply(213,
					    "%04d%02d%02d%02d%02d%02d",
					    1900 + t->tm_year, t->tm_mon+1, t->tm_mday,
					    t->tm_hour, t->tm_min, t->tm_sec);
				}
			}
			if (yyvsp[-1].str != NULL)
				free((char *) yyvsp[-1].str);
		;
    break;}
case 48:
#line 610 "ftpcmd.y"
{
			auth((char *) yyvsp[-1].str);
		;
    break;}
case 49:
#line 614 "ftpcmd.y"
{
			auth_data((char *) yyvsp[-1].str);
			free((char *) yyvsp[-1].str);
		;
    break;}
case 50:
#line 619 "ftpcmd.y"
{
			reply(221, "Goodbye.");
			dologout(0);
		;
    break;}
case 51:
#line 624 "ftpcmd.y"
{
			yyerrok;
		;
    break;}
case 52:
#line 629 "ftpcmd.y"
{
			char *renamefrom();

			restart_point = (off_t) 0;
			if (yyvsp[-3].num && yyvsp[-1].str) {
				fromname = renamefrom((char *) yyvsp[-1].str);
				if (fromname == (char *) 0 && yyvsp[-1].str) {
					free((char *) yyvsp[-1].str);
				}
			}
		;
    break;}
case 53:
#line 641 "ftpcmd.y"
{
			fromname = (char *) 0;
			restart_point = yyvsp[-1].num;
			reply(350, "Restarting at %ld. %s", restart_point,
			    "Send STORE or RETRIEVE to initiate transfer.");
		;
    break;}
case 55:
#line 653 "ftpcmd.y"
{
			*(char **)&(yyval.str) = (char *)calloc(1, sizeof(char));
		;
    break;}
case 58:
#line 664 "ftpcmd.y"
{
			register char *a, *p;

			a = (char *)&data_dest.sin_addr;
			a[0] = yyvsp[-10].num; a[1] = yyvsp[-8].num; a[2] = yyvsp[-6].num; a[3] = yyvsp[-4].num;
			p = (char *)&data_dest.sin_port;
			p[0] = yyvsp[-2].num; p[1] = yyvsp[0].num;
			data_dest.sin_family = AF_INET;
		;
    break;}
case 59:
#line 676 "ftpcmd.y"
{
		yyval.num = FORM_N;
	;
    break;}
case 60:
#line 680 "ftpcmd.y"
{
		yyval.num = FORM_T;
	;
    break;}
case 61:
#line 684 "ftpcmd.y"
{
		yyval.num = FORM_C;
	;
    break;}
case 62:
#line 690 "ftpcmd.y"
{
		yyval.num = PROT_C;
	;
    break;}
case 63:
#line 694 "ftpcmd.y"
{
		yyval.num = PROT_S;
	;
    break;}
case 64:
#line 698 "ftpcmd.y"
{
		yyval.num = PROT_P;
	;
    break;}
case 65:
#line 702 "ftpcmd.y"
{
		yyval.num = PROT_E;
	;
    break;}
case 66:
#line 708 "ftpcmd.y"
{
		cmd_type = TYPE_A;
		cmd_form = FORM_N;
	;
    break;}
case 67:
#line 713 "ftpcmd.y"
{
		cmd_type = TYPE_A;
		cmd_form = yyvsp[0].num;
	;
    break;}
case 68:
#line 718 "ftpcmd.y"
{
		cmd_type = TYPE_E;
		cmd_form = FORM_N;
	;
    break;}
case 69:
#line 723 "ftpcmd.y"
{
		cmd_type = TYPE_E;
		cmd_form = yyvsp[0].num;
	;
    break;}
case 70:
#line 728 "ftpcmd.y"
{
		cmd_type = TYPE_I;
	;
    break;}
case 71:
#line 732 "ftpcmd.y"
{
		cmd_type = TYPE_L;
		cmd_bytesz = NBBY;
	;
    break;}
case 72:
#line 737 "ftpcmd.y"
{
		cmd_type = TYPE_L;
		cmd_bytesz = yyvsp[0].num;
	;
    break;}
case 73:
#line 743 "ftpcmd.y"
{
		cmd_type = TYPE_L;
		cmd_bytesz = yyvsp[0].num;
	;
    break;}
case 74:
#line 750 "ftpcmd.y"
{
		yyval.num = STRU_F;
	;
    break;}
case 75:
#line 754 "ftpcmd.y"
{
		yyval.num = STRU_R;
	;
    break;}
case 76:
#line 758 "ftpcmd.y"
{
		yyval.num = STRU_P;
	;
    break;}
case 77:
#line 764 "ftpcmd.y"
{
		yyval.num = MODE_S;
	;
    break;}
case 78:
#line 768 "ftpcmd.y"
{
		yyval.num = MODE_B;
	;
    break;}
case 79:
#line 772 "ftpcmd.y"
{
		yyval.num = MODE_C;
	;
    break;}
case 80:
#line 778 "ftpcmd.y"
{
		/*
		 * Problem: this production is used for all pathname
		 * processing, but only gives a 550 error reply.
		 * This is a valid reply in some cases but not in others.
		 */
		if (logged_in && yyvsp[0].str && strncmp((char *) yyvsp[0].str, "~", 1) == 0) {
			char **globlist;

			globlist = ftpglob(yyvsp[0].str);
			if (globerr) {
			    reply(550, globerr);
			    yyval.str = NULL;
			    if (globlist) {
				blkfree(globlist);
				free((char *) globlist);
			    }
			}
			else if (globlist && *globlist) {
			    yyval.str = *globlist;
			    blkfree(&globlist[1]);
			    free((char *) globlist);
			}
			else {
			    if (globlist) {
				blkfree(globlist);
				free((char *) globlist);
			    }
			    errno = ENOENT;
			    perror_reply(550, yyvsp[0].str);
			    yyval.str = NULL;
			}
			free((char *) yyvsp[0].str);
		} else
			yyval.str = yyvsp[0].str;
	;
    break;}
case 82:
#line 820 "ftpcmd.y"
{
		register int ret, dec, multby, digit;

		/*
		 * Convert a number that was read as decimal number
		 * to what it would be if it had been read as octal.
		 */
		dec = yyvsp[0].num;
		multby = 1;
		ret = 0;
		while (dec) {
			digit = dec%10;
			if (digit > 7) {
				ret = -1;
				break;
			}
			ret += digit * multby;
			multby *= 8;
			dec /= 10;
		}
		yyval.num = ret;
	;
    break;}
case 83:
#line 845 "ftpcmd.y"
{
		if (logged_in)
			yyval.num = 1;
		else {
			reply(530, "Please login with USER and PASS.");
			yyval.num = 0;
		}
	;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 543 "/usr/lib/bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;

 yyacceptlab:
  /* YYACCEPT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 0;

 yyabortlab:
  /* YYABORT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 1;
}
#line 855 "ftpcmd.y"


struct tab cmdtab[] = {		/* In order defined in RFC 765 */
	{ "USER", USER, STR1, 1,	"<sp> username" },
	{ "PASS", PASS, ZSTR1, 1,	"<sp> password" },
	{ "ACCT", ACCT, STR1, 0,	"(specify account)" },
	{ "SMNT", SMNT, ARGS, 0,	"(structure mount)" },
	{ "REIN", REIN, ARGS, 0,	"(reinitialize server state)" },
	{ "QUIT", QUIT, ARGS, 1,	"(terminate service)", },
	{ "PORT", PORT, ARGS, 1,	"<sp> b0, b1, b2, b3, b4" },
	{ "PASV", PASV, ARGS, 1,	"(set server in passive mode)" },
	{ "TYPE", TYPE, ARGS, 1,	"<sp> [ A | E | I | L ]" },
	{ "STRU", STRU, ARGS, 1,	"(specify file structure)" },
	{ "MODE", MODE, ARGS, 1,	"(specify transfer mode)" },
	{ "RETR", RETR, STR1, 1,	"<sp> file-name" },
	{ "STOR", STOR, STR1, 1,	"<sp> file-name" },
	{ "APPE", APPE, STR1, 1,	"<sp> file-name" },
	{ "MLFL", MLFL, OSTR, 0,	"(mail file)" },
	{ "MAIL", MAIL, OSTR, 0,	"(mail to user)" },
	{ "MSND", MSND, OSTR, 0,	"(mail send to terminal)" },
	{ "MSOM", MSOM, OSTR, 0,	"(mail send to terminal or mailbox)" },
	{ "MSAM", MSAM, OSTR, 0,	"(mail send to terminal and mailbox)" },
	{ "MRSQ", MRSQ, OSTR, 0,	"(mail recipient scheme question)" },
	{ "MRCP", MRCP, STR1, 0,	"(mail recipient)" },
	{ "ALLO", ALLO, ARGS, 1,	"allocate storage (vacuously)" },
	{ "REST", REST, ARGS, 1,	"(restart command)" },
	{ "RNFR", RNFR, STR1, 1,	"<sp> file-name" },
	{ "RNTO", RNTO, STR1, 1,	"<sp> file-name" },
	{ "ABOR", ABOR, ARGS, 1,	"(abort operation)" },
	{ "DELE", DELE, STR1, 1,	"<sp> file-name" },
	{ "CWD",  CWD,  OSTR, 1,	"[ <sp> directory-name ]" },
	{ "XCWD", CWD,	OSTR, 1,	"[ <sp> directory-name ]" },
	{ "LIST", LIST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "NLST", NLST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "SITE", SITE, SITECMD, 1,	"site-cmd [ <sp> arguments ]" },
	{ "SYST", SYST, ARGS, 1,	"(get type of operating system)" },
	{ "STAT", STAT, OSTR, 1,	"[ <sp> path-name ]" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ "NOOP", NOOP, ARGS, 1,	"" },
	{ "MKD",  MKD,  STR1, 1,	"<sp> path-name" },
	{ "XMKD", MKD,  STR1, 1,	"<sp> path-name" },
	{ "RMD",  RMD,  STR1, 1,	"<sp> path-name" },
	{ "XRMD", RMD,  STR1, 1,	"<sp> path-name" },
	{ "PWD",  PWD,  ARGS, 1,	"(return current directory)" },
	{ "XPWD", PWD,  ARGS, 1,	"(return current directory)" },
	{ "CDUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "XCUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "STOU", STOU, STR1, 1,	"<sp> file-name" },
	{ "AUTH", AUTH, STR1, 1,	"<sp> auth-type" },
	{ "ADAT", ADAT, STR1, 1,	"<sp> auth-data" },
	{ "PROT", PROT, ARGS, 1,	"<sp> protection-level" },
	{ "PBSZ", PBSZ, STR1, 1,	"<sp> buffer-size" },
	{ "CCC",  CCC,  ARGS, 1,	"(clear command channel)" },
	{ "SIZE", SIZE, OSTR, 1,	"<sp> path-name" },
	{ "MDTM", MDTM, OSTR, 1,	"<sp> path-name" },
	{ NULL,   0,    0,    0,	0 }
};

struct tab sitetab[] = {
	{ "UMASK", UMASK, ARGS, 1,	"[ <sp> umask ]" },
	{ "IDLE", IDLE, ARGS, 1,	"[ <sp> maximum-idle-time ]" },
	{ "CHMOD", CHMOD, NSTR, 1,	"<sp> mode <sp> file-name" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ NULL,   0,    0,    0,	0 }
};

struct tab *
lookup(p, cmd)
	register struct tab *p;
	char *cmd;
{

	for (; p->name != NULL; p++)
		if (strcmp(cmd, p->name) == 0)
			return (p);
	return (0);
}

#include <arpa/telnet.h>

/*
 * getline - a hacked up version of fgets to ignore TELNET escape codes.
 */
char *
getline(s, n, iop)
	char *s;
	register FILE *iop;
{
	register c;
	register char *cs;

	cs = s;
/* tmpline may contain saved command from urgent mode interruption */
	for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
		*cs++ = tmpline[c];
		if (tmpline[c] == '\n') {
			*cs++ = '\0';
			if (debug)
				syslog(LOG_DEBUG, "command: %s", s);
			tmpline[0] = '\0';
			return(s);
		}
		if (c == 0)
			tmpline[0] = '\0';
	}
	while ((c = getc(iop)) != EOF) {
		c &= 0377;
		if (c == IAC) {
		    if ((c = getc(iop)) != EOF) {
			c &= 0377;
			switch (c) {
			case WILL:
			case WONT:
				c = getc(iop);
				printf("%c%c%c", IAC, DONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case DO:
			case DONT:
				c = getc(iop);
				printf("%c%c%c", IAC, WONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case IAC:
				break;
			default:
				continue;	/* ignore command */
			}
		    }
		}
		*cs++ = c;
		if (--n <= 0 || c == '\n')
			break;
	}
	if (c == EOF && cs == s)
		return (NULL);
	*cs++ = '\0';
	if (auth_type) {
	    char out[sizeof(cbuf)], *cp;
	    int len, mic;

	    if ((cs = strpbrk(s, " \r\n")))
	    	*cs++ = '\0';
	    upper(s);
#ifdef NOCONFIDENTIAL
	    if (!strcmp(s, "CONF")) {
		reply(537, "CONF protected commands not supported.");
		*s = '\0';
		return(s);
	    }
#endif
	    if ((mic = strcmp(s, "ENC")) && strcmp(s, "MIC")
#ifndef NOCONFIDENTIAL
		&& strcmp(s, "CONF")
#endif
					) {
		reply(533, "All commands must be protected.");
		syslog(LOG_ERR, "Unprotected command received");
		*s = '\0';
		return(s);
	    } else if (debug)
		syslog(LOG_INFO, "command %s received (mic=%d)", s, mic);
/* Some paranoid sites may want to require that commands be encrypted. */
#ifdef PARANOID
	    if (mic) {
		reply(533, "All commands must be ENC protected.  Retry command under ENC.");
		*s = '\0';
		return(s);
	    }
#endif /* PARANOID */
#ifdef NOENCRYPTION
	    if (!mic) {
		reply(533, "ENC protection not supported.  Retry command under MIC.");
		*s = '\0';
		return(s);
	    }
#endif /* NOENCRYPTION */
	    if ((cp = strpbrk(cs, " \r\n")))
		*cp = '\0';
	    if (kerror = radix_encode(cs, out, &len, 1)) {
		reply(501, "Can't base 64 decode argument to %s command (%s)",
		      mic ? "MIC" : "ENC", radix_error(kerror));
		*s = '\0';
		return(s);
	    }
	    if (debug) syslog(LOG_DEBUG, "getline got %d from %s <%s>\n", 
			      len, cs, mic?"MIC":"ENC");
#ifdef SRP
	if (strcmp(auth_type, "SRP") == 0)
        {
          int outlen;
          if ((outlen = srp_decode (!mic, (unsigned char *) out,
            (unsigned char *) out, len)) < 0)
          {
	    reply (535, "%s", mic ? "MIC command modified" :
              "ENC command garbled");
	    syslog (LOG_ERR,"%s failed", mic ? "MIC srp_decode" :
              "ENC srp_decode");
	    *s = '\0';
	    return s;
          }
          else
          {
	    (void) memcpy (s, out, outlen);
	    (void) strcpy (s+outlen, "\r\n");
          }
	}
#endif
#ifdef KERBEROS
	    if (strcmp(auth_type, "KERBEROS_V4") == 0) {
		if ((kerror = mic ?
		    krb_rd_safe((unsigned char *)out, len, &kdata.session,
			    &his_addr, &ctrl_addr, &msg_data)
		  : krb_rd_priv((unsigned char *)out, len, schedule,
			    &kdata.session, &his_addr, &ctrl_addr, &msg_data))
			!= KSUCCESS) {
		    reply(535, "%s! (%s)",
			   mic ? "MIC command modified" : "ENC command garbled",
			   krb_get_err_text(kerror));
		    syslog(LOG_ERR,"%s failed: %s",
			   mic ? "MIC krb_rd_safe" : "ENC krb_rd_priv",
			   krb_get_err_text(kerror));
		    *s = '\0';
		    return(s);
		}
		(void) memcpy(s, msg_data.app_data, msg_data.app_length);
		(void) strcpy(s+msg_data.app_length, "\r\n");
	    }
#endif /* KERBEROS */
#ifdef GSSAPI
/* we know this is a MIC or ENC already, and out/len already has the bits */
	    if (strcmp(auth_type, "GSSAPI") == 0) {
		gss_buffer_desc xmit_buf, msg_buf;
		OM_uint32 maj_stat, min_stat;
		int conf_state;

		xmit_buf.value = out;
		xmit_buf.length = len;
		/* decrypt the message */
		conf_state = !mic;
		maj_stat = gss_unseal(&min_stat, gcontext, &xmit_buf,
				      &msg_buf, &conf_state, NULL);
		if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			if (debug) syslog(LOG_DEBUG, "%s-unseal continued", 
					  mic?"MIC":"ENC");
			reply(535, "%s-unseal continued, oops",
			      mic?"MIC":"ENC");
			*s = 0; return s;
		}
		if (maj_stat != GSS_S_COMPLETE) {
			reply_gss_error(535, maj_stat, min_stat, 
					mic? "failed unsealing MIC message":
					"failed unsealing ENC message");
			*s = 0;
			return s;
		}

		memcpy(s, msg_buf.value, msg_buf.length);
		strcpy(s+msg_buf.length-(s[msg_buf.length-1]?0:1), "\r\n");
		gss_release_buffer(&min_stat, &msg_buf);
	    }
#endif /* GSSAPI */
	    /* Other auth types go here ... */
	}
#if defined KERBEROS || defined GSSAPI || defined SRP	/* or other auth types */
	else {	/* !auth_type */
	    if ( (!(strncmp(s, "ENC", 3))) || (!(strncmp(s, "MIC", 3)))
#ifndef NOCONFIDENTIAL
                || (!(strncmp(s, "CONF", 4)))
#endif
                                        ) {
                reply(503, "Must perform authentication before sending protected commands");
                *s = '\0';
                return(s);
	    }
	}
#endif /* KERBEROS */

	if (debug)
		syslog(LOG_DEBUG, "command: <%s>(%d)", s, strlen(s));
	return (s);
}

static RETSIGTYPE
toolong(sig)
	int sig;
{
	time_t now;

	reply(421,
	  "Timeout (%d seconds): closing control connection.", timeout);
	(void) time(&now);
	if (logging) {
		syslog(LOG_INFO,
			"User %s timed out after %d seconds at %s",
			(pw ? pw -> pw_name : "unknown"), timeout, ctime(&now));
	}
	dologout(1);
}

yylex()
{
	static int cpos, state;
	register char *cp, *cp2;
	register struct tab *p;
	int n;
	char c, *copy();

	for (;;) {
		switch (state) {

		case CMD:
			(void) signal(SIGALRM, toolong);
			(void) alarm((unsigned) timeout);
			if (getline(cbuf, sizeof(cbuf)-1, stdin) == NULL) {
				reply(221, "You could at least say goodbye.");
				dologout(0);
			}
			(void) alarm(0);

			/* If getline() finds an error, the string is null */
			if (*cbuf == '\0')
				continue;

#ifdef SETPROCTITLE
			if (strncasecmp(cbuf, "PASS", 4) != NULL)
				setproctitle("%s: %s", proctitle, cbuf);
#endif /* SETPROCTITLE */
			if ((cp = strchr(cbuf, '\r'))) {
				*cp++ = '\n';
				*cp = '\0';
			}
			if ((cp = strpbrk(cbuf, " \n")))
				cpos = cp - cbuf;
			if (cpos == 0)
				cpos = 4;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cbuf);
			p = lookup(cmdtab, cbuf);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.str = p->name;
				return (p->token);
			}
			break;

		case SITECMD:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			cp = &cbuf[cpos];
			if ((cp2 = strpbrk(cp, " \n")))
				cpos = cp2 - cbuf;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cp);
			p = lookup(sitetab, cp);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					state = CMD;
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.str = p->name;
				return (p->token);
			}
			state = CMD;
			break;

		case OSTR:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR1:
		case ZSTR1:
		dostr1:
			if (cbuf[cpos] == ' ') {
				cpos++;
				state = state == OSTR ? STR2 : ++state;
				return (SP);
			}
			break;

		case ZSTR2:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR2:
			cp = &cbuf[cpos];
			n = strlen(cp);
			cpos += n - 1;
			/*
			 * Make sure the string is nonempty and \n terminated.
			 */
			if (n > 1 && cbuf[cpos] == '\n') {
				cbuf[cpos] = '\0';
				yylval.str = copy(cp);
				cbuf[cpos] = '\n';
				state = ARGS;
				return (STRING);
			}
			break;

		case NSTR:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.num = atoi(cp);
				cbuf[cpos] = c;
				state = STR1;
				return (NUMBER);
			}
			state = STR1;
			goto dostr1;

		case ARGS:
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.num = atoi(cp);
				cbuf[cpos] = c;
				return (NUMBER);
			}
			switch (cbuf[cpos++]) {

			case '\n':
				state = CMD;
				return (CRLF);

			case ' ':
				return (SP);

			case ',':
				return (COMMA);

			case 'A':
			case 'a':
				return (A);

			case 'B':
			case 'b':
				return (B);

			case 'C':
			case 'c':
				return (C);

			case 'E':
			case 'e':
				return (E);

			case 'F':
			case 'f':
				return (F);

			case 'I':
			case 'i':
				return (I);

			case 'L':
			case 'l':
				return (L);

			case 'N':
			case 'n':
				return (N);

			case 'P':
			case 'p':
				return (P);

			case 'R':
			case 'r':
				return (R);

			case 'S':
			case 's':
				return (S);

			case 'T':
			case 't':
				return (T);

			}
			break;

		default:
			fatal("Unknown state in scanner.");
		}
		yyerror((char *) 0);
		state = CMD;
		longjmp(errcatch,0);
	}
}

upper(s)
	register char *s;
{
	while (*s != '\0') {
		if (islower(*s))
			*s = toupper(*s);
		s++;
	}
}

char *
copy(s)
	char *s;
{
	char *p;

	p = malloc((unsigned) strlen(s) + 1);
	if (p == NULL)
		fatal("Ran out of memory.");
	(void) strcpy(p, s);
	return (p);
}

help(ctab, s)
	struct tab *ctab;
	char *s;
{
	register struct tab *c;
	register int width, NCMDS;
	char str[80];
	char *type;

	if (ctab == sitetab)
		type = "SITE ";
	else
		type = "";
	width = 0, NCMDS = 0;
	for (c = ctab; c->name != NULL; c++) {
		int len = strlen(c->name);

		if (len > width)
			width = len;
		NCMDS++;
	}
	width = (width + 8) &~ 7;
	if (s == 0) {
		register int i, j, w;
		int columns, lines;

		lreply(214, "The following %scommands are recognized %s.",
		    type, "(* =>'s unimplemented)");
		columns = 76 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			strcpy(str, "   ");
			for (j = 0; j < columns; j++) {
				c = ctab + j * lines + i;
				sprintf(&str[strlen(str)], "%s%c", c->name,
					c->implemented ? ' ' : '*');
				if (c + lines >= &ctab[NCMDS])
					break;
				w = strlen(c->name) + 1;
				while (w < width) {
					strcat(str, " ");
					w++;
				}
			}
			reply(0, "%s", str);
		}
		reply(214, "Direct comments to ftp-bugs@%s.", hostname);
		return;
	}
	upper(s);
	c = lookup(ctab, s);
	if (c == (struct tab *)0) {
		reply(502, "Unknown command %s.", s);
		return;
	}
	if (c->implemented)
		reply(214, "Syntax: %s%s %s", type, c->name, c->help);
	else
		reply(214, "%s%-*s\t%s; unimplemented.", type, width,
		    c->name, c->help);
}

sizecmd(filename)
char *filename;
{
	switch (type) {
	case TYPE_L:
	case TYPE_I: {
		struct stat stbuf;
		if (stat(filename, &stbuf) < 0 ||
		    (stbuf.st_mode&S_IFMT) != S_IFREG)
			reply(550, "%s: not a plain file.", filename);
		else
			reply(213, "%lu", stbuf.st_size);
		break;}
	case TYPE_A: {
		FILE *fin;
		register int c;
		register long count;
		struct stat stbuf;
		fin = fopen(filename, "r");
		if (fin == NULL) {
			perror_reply(550, filename);
			return;
		}
		if (fstat(fileno(fin), &stbuf) < 0 ||
		    (stbuf.st_mode&S_IFMT) != S_IFREG) {
			reply(550, "%s: not a plain file.", filename);
			(void) fclose(fin);
			return;
		}

		count = 0;
		while((c=getc(fin)) != EOF) {
			if (c == '\n')	/* will get expanded to \r\n */
				count++;
			count++;
		}
		(void) fclose(fin);

		reply(213, "%ld", count);
		break;}
	default:
		reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
	}
}
