/* $XConsortium: Wrap.h,v 1.3 94/02/06 20:09:49 rws Exp $ */
/*
 * header file for compatibility with something useful
 */

/* $XFree86: xc/lib/Xdmcp/Wrap.h,v 1.2 1998/10/10 15:25:18 dawes Exp $ */

/*
 * Incorporated into the SRP Telnet distribution 10/19/2000 by
 * Tom Wu <tjw@cs.stanford.edu>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef FWDX_XDM

typedef unsigned char auth_cblock[8];	/* block size */

typedef struct auth_ks_struct { auth_cblock _; } auth_wrapper_schedule[16];

void _XdmcpWrapperToOddParity (unsigned char *in, unsigned char *out);

/* Wraphelp.c
 * des routines for non-usa - eay 10/9/1991 eay@psych.psy.uq.oz.au
 * These routines were written for speed not size so they are bigger than
 * needed.  I have removed some of the loop unrolling, this will reduce
 * code size at the expense of some speed.
 * 25/9/1991 eay - much faster _XdmcpAuthSetup (4 times faster).
 * 19/9/1991 eay - cleaned up the IP and FP code.
 * 10/9/1991 eay - first release.
 * The des routines this file has been made from can be found in
 * ftp.psy.uq.oz.au /pub/DES
 */

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

static ulong skb[8][64]={
/* for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
0x00000000,0x00000010,0x20000000,0x20000010,
0x00010000,0x00010010,0x20010000,0x20010010,
0x00000800,0x00000810,0x20000800,0x20000810,
0x00010800,0x00010810,0x20010800,0x20010810,
0x00000020,0x00000030,0x20000020,0x20000030,
0x00010020,0x00010030,0x20010020,0x20010030,
0x00000820,0x00000830,0x20000820,0x20000830,
0x00010820,0x00010830,0x20010820,0x20010830,
0x00080000,0x00080010,0x20080000,0x20080010,
0x00090000,0x00090010,0x20090000,0x20090010,
0x00080800,0x00080810,0x20080800,0x20080810,
0x00090800,0x00090810,0x20090800,0x20090810,
0x00080020,0x00080030,0x20080020,0x20080030,
0x00090020,0x00090030,0x20090020,0x20090030,
0x00080820,0x00080830,0x20080820,0x20080830,
0x00090820,0x00090830,0x20090820,0x20090830,
/* for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 */
0x00000000,0x02000000,0x00002000,0x02002000,
0x00200000,0x02200000,0x00202000,0x02202000,
0x00000004,0x02000004,0x00002004,0x02002004,
0x00200004,0x02200004,0x00202004,0x02202004,
0x00000400,0x02000400,0x00002400,0x02002400,
0x00200400,0x02200400,0x00202400,0x02202400,
0x00000404,0x02000404,0x00002404,0x02002404,
0x00200404,0x02200404,0x00202404,0x02202404,
0x10000000,0x12000000,0x10002000,0x12002000,
0x10200000,0x12200000,0x10202000,0x12202000,
0x10000004,0x12000004,0x10002004,0x12002004,
0x10200004,0x12200004,0x10202004,0x12202004,
0x10000400,0x12000400,0x10002400,0x12002400,
0x10200400,0x12200400,0x10202400,0x12202400,
0x10000404,0x12000404,0x10002404,0x12002404,
0x10200404,0x12200404,0x10202404,0x12202404,
/* for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 */
0x00000000,0x00000001,0x00040000,0x00040001,
0x01000000,0x01000001,0x01040000,0x01040001,
0x00000002,0x00000003,0x00040002,0x00040003,
0x01000002,0x01000003,0x01040002,0x01040003,
0x00000200,0x00000201,0x00040200,0x00040201,
0x01000200,0x01000201,0x01040200,0x01040201,
0x00000202,0x00000203,0x00040202,0x00040203,
0x01000202,0x01000203,0x01040202,0x01040203,
0x08000000,0x08000001,0x08040000,0x08040001,
0x09000000,0x09000001,0x09040000,0x09040001,
0x08000002,0x08000003,0x08040002,0x08040003,
0x09000002,0x09000003,0x09040002,0x09040003,
0x08000200,0x08000201,0x08040200,0x08040201,
0x09000200,0x09000201,0x09040200,0x09040201,
0x08000202,0x08000203,0x08040202,0x08040203,
0x09000202,0x09000203,0x09040202,0x09040203,
/* for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 */
0x00000000,0x00100000,0x00000100,0x00100100,
0x00000008,0x00100008,0x00000108,0x00100108,
0x00001000,0x00101000,0x00001100,0x00101100,
0x00001008,0x00101008,0x00001108,0x00101108,
0x04000000,0x04100000,0x04000100,0x04100100,
0x04000008,0x04100008,0x04000108,0x04100108,
0x04001000,0x04101000,0x04001100,0x04101100,
0x04001008,0x04101008,0x04001108,0x04101108,
0x00020000,0x00120000,0x00020100,0x00120100,
0x00020008,0x00120008,0x00020108,0x00120108,
0x00021000,0x00121000,0x00021100,0x00121100,
0x00021008,0x00121008,0x00021108,0x00121108,
0x04020000,0x04120000,0x04020100,0x04120100,
0x04020008,0x04120008,0x04020108,0x04120108,
0x04021000,0x04121000,0x04021100,0x04121100,
0x04021008,0x04121008,0x04021108,0x04121108,
/* for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
0x00000000,0x10000000,0x00010000,0x10010000,
0x00000004,0x10000004,0x00010004,0x10010004,
0x20000000,0x30000000,0x20010000,0x30010000,
0x20000004,0x30000004,0x20010004,0x30010004,
0x00100000,0x10100000,0x00110000,0x10110000,
0x00100004,0x10100004,0x00110004,0x10110004,
0x20100000,0x30100000,0x20110000,0x30110000,
0x20100004,0x30100004,0x20110004,0x30110004,
0x00001000,0x10001000,0x00011000,0x10011000,
0x00001004,0x10001004,0x00011004,0x10011004,
0x20001000,0x30001000,0x20011000,0x30011000,
0x20001004,0x30001004,0x20011004,0x30011004,
0x00101000,0x10101000,0x00111000,0x10111000,
0x00101004,0x10101004,0x00111004,0x10111004,
0x20101000,0x30101000,0x20111000,0x30111000,
0x20101004,0x30101004,0x20111004,0x30111004,
/* for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 */
0x00000000,0x08000000,0x00000008,0x08000008,
0x00000400,0x08000400,0x00000408,0x08000408,
0x00020000,0x08020000,0x00020008,0x08020008,
0x00020400,0x08020400,0x00020408,0x08020408,
0x00000001,0x08000001,0x00000009,0x08000009,
0x00000401,0x08000401,0x00000409,0x08000409,
0x00020001,0x08020001,0x00020009,0x08020009,
0x00020401,0x08020401,0x00020409,0x08020409,
0x02000000,0x0A000000,0x02000008,0x0A000008,
0x02000400,0x0A000400,0x02000408,0x0A000408,
0x02020000,0x0A020000,0x02020008,0x0A020008,
0x02020400,0x0A020400,0x02020408,0x0A020408,
0x02000001,0x0A000001,0x02000009,0x0A000009,
0x02000401,0x0A000401,0x02000409,0x0A000409,
0x02020001,0x0A020001,0x02020009,0x0A020009,
0x02020401,0x0A020401,0x02020409,0x0A020409,
/* for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 */
0x00000000,0x00000100,0x00080000,0x00080100,
0x01000000,0x01000100,0x01080000,0x01080100,
0x00000010,0x00000110,0x00080010,0x00080110,
0x01000010,0x01000110,0x01080010,0x01080110,
0x00200000,0x00200100,0x00280000,0x00280100,
0x01200000,0x01200100,0x01280000,0x01280100,
0x00200010,0x00200110,0x00280010,0x00280110,
0x01200010,0x01200110,0x01280010,0x01280110,
0x00000200,0x00000300,0x00080200,0x00080300,
0x01000200,0x01000300,0x01080200,0x01080300,
0x00000210,0x00000310,0x00080210,0x00080310,
0x01000210,0x01000310,0x01080210,0x01080310,
0x00200200,0x00200300,0x00280200,0x00280300,
0x01200200,0x01200300,0x01280200,0x01280300,
0x00200210,0x00200310,0x00280210,0x00280310,
0x01200210,0x01200310,0x01280210,0x01280310,
/* for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 */
0x00000000,0x04000000,0x00040000,0x04040000,
0x00000002,0x04000002,0x00040002,0x04040002,
0x00002000,0x04002000,0x00042000,0x04042000,
0x00002002,0x04002002,0x00042002,0x04042002,
0x00000020,0x04000020,0x00040020,0x04040020,
0x00000022,0x04000022,0x00040022,0x04040022,
0x00002020,0x04002020,0x00042020,0x04042020,
0x00002022,0x04002022,0x00042022,0x04042022,
0x00000800,0x04000800,0x00040800,0x04040800,
0x00000802,0x04000802,0x00040802,0x04040802,
0x00002800,0x04002800,0x00042800,0x04042800,
0x00002802,0x04002802,0x00042802,0x04042802,
0x00000820,0x04000820,0x00040820,0x04040820,
0x00000822,0x04000822,0x00040822,0x04040822,
0x00002820,0x04002820,0x00042820,0x04042820,
0x00002822,0x04002822,0x00042822,0x04042822,
};


static unsigned long SPtrans[8][64]={
/* nibble 0 */
0x00410100, 0x00010000, 0x40400000, 0x40410100,
0x00400000, 0x40010100, 0x40010000, 0x40400000,
0x40010100, 0x00410100, 0x00410000, 0x40000100,
0x40400100, 0x00400000, 0x00000000, 0x40010000,
0x00010000, 0x40000000, 0x00400100, 0x00010100,
0x40410100, 0x00410000, 0x40000100, 0x00400100,
0x40000000, 0x00000100, 0x00010100, 0x40410000,
0x00000100, 0x40400100, 0x40410000, 0x00000000,
0x00000000, 0x40410100, 0x00400100, 0x40010000,
0x00410100, 0x00010000, 0x40000100, 0x00400100,
0x40410000, 0x00000100, 0x00010100, 0x40400000,
0x40010100, 0x40000000, 0x40400000, 0x00410000,
0x40410100, 0x00010100, 0x00410000, 0x40400100,
0x00400000, 0x40000100, 0x40010000, 0x00000000,
0x00010000, 0x00400000, 0x40400100, 0x00410100,
0x40000000, 0x40410000, 0x00000100, 0x40010100,

/* nibble 1 */
0x08021002, 0x00000000, 0x00021000, 0x08020000,
0x08000002, 0x00001002, 0x08001000, 0x00021000,
0x00001000, 0x08020002, 0x00000002, 0x08001000,
0x00020002, 0x08021000, 0x08020000, 0x00000002,
0x00020000, 0x08001002, 0x08020002, 0x00001000,
0x00021002, 0x08000000, 0x00000000, 0x00020002,
0x08001002, 0x00021002, 0x08021000, 0x08000002,
0x08000000, 0x00020000, 0x00001002, 0x08021002,
0x00020002, 0x08021000, 0x08001000, 0x00021002,
0x08021002, 0x00020002, 0x08000002, 0x00000000,
0x08000000, 0x00001002, 0x00020000, 0x08020002,
0x00001000, 0x08000000, 0x00021002, 0x08001002,
0x08021000, 0x00001000, 0x00000000, 0x08000002,
0x00000002, 0x08021002, 0x00021000, 0x08020000,
0x08020002, 0x00020000, 0x00001002, 0x08001000,
0x08001002, 0x00000002, 0x08020000, 0x00021000,

/* nibble 2 */
0x20800000, 0x00808020, 0x00000020, 0x20800020,
0x20008000, 0x00800000, 0x20800020, 0x00008020,
0x00800020, 0x00008000, 0x00808000, 0x20000000,
0x20808020, 0x20000020, 0x20000000, 0x20808000,
0x00000000, 0x20008000, 0x00808020, 0x00000020,
0x20000020, 0x20808020, 0x00008000, 0x20800000,
0x20808000, 0x00800020, 0x20008020, 0x00808000,
0x00008020, 0x00000000, 0x00800000, 0x20008020,
0x00808020, 0x00000020, 0x20000000, 0x00008000,
0x20000020, 0x20008000, 0x00808000, 0x20800020,
0x00000000, 0x00808020, 0x00008020, 0x20808000,
0x20008000, 0x00800000, 0x20808020, 0x20000000,
0x20008020, 0x20800000, 0x00800000, 0x20808020,
0x00008000, 0x00800020, 0x20800020, 0x00008020,
0x00800020, 0x00000000, 0x20808000, 0x20000020,
0x20800000, 0x20008020, 0x00000020, 0x00808000,

/* nibble 3 */
0x00080201, 0x02000200, 0x00000001, 0x02080201,
0x00000000, 0x02080000, 0x02000201, 0x00080001,
0x02080200, 0x02000001, 0x02000000, 0x00000201,
0x02000001, 0x00080201, 0x00080000, 0x02000000,
0x02080001, 0x00080200, 0x00000200, 0x00000001,
0x00080200, 0x02000201, 0x02080000, 0x00000200,
0x00000201, 0x00000000, 0x00080001, 0x02080200,
0x02000200, 0x02080001, 0x02080201, 0x00080000,
0x02080001, 0x00000201, 0x00080000, 0x02000001,
0x00080200, 0x02000200, 0x00000001, 0x02080000,
0x02000201, 0x00000000, 0x00000200, 0x00080001,
0x00000000, 0x02080001, 0x02080200, 0x00000200,
0x02000000, 0x02080201, 0x00080201, 0x00080000,
0x02080201, 0x00000001, 0x02000200, 0x00080201,
0x00080001, 0x00080200, 0x02080000, 0x02000201,
0x00000201, 0x02000000, 0x02000001, 0x02080200,

/* nibble 4 */
0x01000000, 0x00002000, 0x00000080, 0x01002084,
0x01002004, 0x01000080, 0x00002084, 0x01002000,
0x00002000, 0x00000004, 0x01000004, 0x00002080,
0x01000084, 0x01002004, 0x01002080, 0x00000000,
0x00002080, 0x01000000, 0x00002004, 0x00000084,
0x01000080, 0x00002084, 0x00000000, 0x01000004,
0x00000004, 0x01000084, 0x01002084, 0x00002004,
0x01002000, 0x00000080, 0x00000084, 0x01002080,
0x01002080, 0x01000084, 0x00002004, 0x01002000,
0x00002000, 0x00000004, 0x01000004, 0x01000080,
0x01000000, 0x00002080, 0x01002084, 0x00000000,
0x00002084, 0x01000000, 0x00000080, 0x00002004,
0x01000084, 0x00000080, 0x00000000, 0x01002084,
0x01002004, 0x01002080, 0x00000084, 0x00002000,
0x00002080, 0x01002004, 0x01000080, 0x00000084,
0x00000004, 0x00002084, 0x01002000, 0x01000004,

/* nibble 5 */
0x10000008, 0x00040008, 0x00000000, 0x10040400,
0x00040008, 0x00000400, 0x10000408, 0x00040000,
0x00000408, 0x10040408, 0x00040400, 0x10000000,
0x10000400, 0x10000008, 0x10040000, 0x00040408,
0x00040000, 0x10000408, 0x10040008, 0x00000000,
0x00000400, 0x00000008, 0x10040400, 0x10040008,
0x10040408, 0x10040000, 0x10000000, 0x00000408,
0x00000008, 0x00040400, 0x00040408, 0x10000400,
0x00000408, 0x10000000, 0x10000400, 0x00040408,
0x10040400, 0x00040008, 0x00000000, 0x10000400,
0x10000000, 0x00000400, 0x10040008, 0x00040000,
0x00040008, 0x10040408, 0x00040400, 0x00000008,
0x10040408, 0x00040400, 0x00040000, 0x10000408,
0x10000008, 0x10040000, 0x00040408, 0x00000000,
0x00000400, 0x10000008, 0x10000408, 0x10040400,
0x10040000, 0x00000408, 0x00000008, 0x10040008,

/* nibble 6 */
0x00000800, 0x00000040, 0x00200040, 0x80200000,
0x80200840, 0x80000800, 0x00000840, 0x00000000,
0x00200000, 0x80200040, 0x80000040, 0x00200800,
0x80000000, 0x00200840, 0x00200800, 0x80000040,
0x80200040, 0x00000800, 0x80000800, 0x80200840,
0x00000000, 0x00200040, 0x80200000, 0x00000840,
0x80200800, 0x80000840, 0x00200840, 0x80000000,
0x80000840, 0x80200800, 0x00000040, 0x00200000,
0x80000840, 0x00200800, 0x80200800, 0x80000040,
0x00000800, 0x00000040, 0x00200000, 0x80200800,
0x80200040, 0x80000840, 0x00000840, 0x00000000,
0x00000040, 0x80200000, 0x80000000, 0x00200040,
0x00000000, 0x80200040, 0x00200040, 0x00000840,
0x80000040, 0x00000800, 0x80200840, 0x00200000,
0x00200840, 0x80000000, 0x80000800, 0x80200840,
0x80200000, 0x00200840, 0x00200800, 0x80000800,

/* nibble 7 */
0x04100010, 0x04104000, 0x00004010, 0x00000000,
0x04004000, 0x00100010, 0x04100000, 0x04104010,
0x00000010, 0x04000000, 0x00104000, 0x00004010,
0x00104010, 0x04004010, 0x04000010, 0x04100000,
0x00004000, 0x00104010, 0x00100010, 0x04004000,
0x04104010, 0x04000010, 0x00000000, 0x00104000,
0x04000000, 0x00100000, 0x04004010, 0x04100010,
0x00100000, 0x00004000, 0x04104000, 0x00000010,
0x00100000, 0x00004000, 0x04000010, 0x04104010,
0x00004010, 0x04000000, 0x00000000, 0x00104000,
0x04100010, 0x04004010, 0x04004000, 0x00100010,
0x04104000, 0x00000010, 0x00100010, 0x04004000,
0x04104010, 0x00100000, 0x04100000, 0x04000010,
0x00104000, 0x00004010, 0x04004010, 0x04100000,
0x00000010, 0x04104000, 0x00104010, 0x00000000,
0x04000000, 0x04100010, 0x00004000, 0x00104010};

#define des_cblock auth_cblock
#define des_key_schedule auth_wrapper_schedule


#define ITERATIONS 16
#define HALF_ITERATIONS 8

#define c2l(c,l)	(l =((ulong)(*((c)++)))    , \
			 l|=((ulong)(*((c)++)))<< 8, \
			 l|=((ulong)(*((c)++)))<<16, \
			 l|=((ulong)(*((c)++)))<<24)

#define l2c(l,c)	(*((c)++)=(uchar)(((l)    )&0xff), \
			 *((c)++)=(uchar)(((l)>> 8)&0xff), \
			 *((c)++)=(uchar)(((l)>>16)&0xff), \
			 *((c)++)=(uchar)(((l)>>24)&0xff))

#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
	(b)^=(t),\
	(a)^=((t)<<(n)))

#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),\
	(a)=(a)^(t)^(t>>(16-(n))))\

static char shifts2[16]={0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};

int _XdmcpAuthSetup(key,schedule)
des_cblock key;
des_key_schedule schedule;
	{
	register ulong c,d,t,s;
	register uchar *in;
	register ulong *k;
	register int i;

	k=(ulong *)schedule;
	in=(uchar *)key;

	c2l(in,c);
	c2l(in,d);

	/* do PC1 in 60 simple operations */ 
	PERM_OP(d,c,t,4,0x0f0f0f0f);
	HPERM_OP(c,t,-2, 0xcccc0000);
	HPERM_OP(c,t,-1, 0xaaaa0000);
	HPERM_OP(c,t, 8, 0x00ff0000);
	HPERM_OP(c,t,-1, 0xaaaa0000);
	HPERM_OP(d,t,-8, 0xff000000);
	HPERM_OP(d,t, 8, 0x00ff0000);
	HPERM_OP(d,t, 2, 0x33330000);
	d=((d&0x00aa00aa)<<7)|((d&0x55005500)>>7)|(d&0xaa55aa55);
	d=(d>>8)|((c&0xf0000000)>>4);
	c&=0x0fffffff;

	for (i=0; i<ITERATIONS; i++)
		{
		if (shifts2[i])
			{ c=((c>>2)|(c<<26)); d=((d>>2)|(d<<26)); }
		else
			{ c=((c>>1)|(c<<27)); d=((d>>1)|(d<<27)); }
		c&=0x0fffffff;
		d&=0x0fffffff;
		/* could be a few less shifts but I am to lazy at this
		 * point in time to investigate */
		s=	skb[0][ (c    )&0x3f                ]|
			skb[1][((c>> 6)&0x03)|((c>> 7)&0x3c)]|
			skb[2][((c>>13)&0x0f)|((c>>14)&0x30)]|
			skb[3][((c>>20)&0x01)|((c>>21)&0x06) |
			                      ((c>>22)&0x38)];
		t=	skb[4][ (d    )&0x3f                ]|
			skb[5][((d>> 7)&0x03)|((d>> 8)&0x3c)]|
			skb[6][ (d>>15)&0x3f                ]|
			skb[7][((d>>21)&0x0f)|((d>>22)&0x30)];

		/* table contained 0213 4657 */
		*(k++)=((t<<16)|(s&0x0000ffff));
		s=     ((s>>16)|(t&0xffff0000));
		
		s=(s<<4)|(s>>28);
		*(k++)=s;
		}
	return(0);
	}

#define D_ENCRYPT(L,R,S)        \
	t=(R<<1)|(R>>31); \
	u=(t^s[S  ]); \
	t=(t^s[S+1]); \
	t=(t>>4)|(t<<28); \
	L^=     SPtrans[1][(t    )&0x3f]| \
		SPtrans[3][(t>> 8)&0x3f]| \
		SPtrans[5][(t>>16)&0x3f]| \
		SPtrans[7][(t>>24)&0x3f]| \
		SPtrans[0][(u    )&0x3f]| \
		SPtrans[2][(u>> 8)&0x3f]| \
		SPtrans[4][(u>>16)&0x3f]| \
		SPtrans[6][(u>>24)&0x3f];

int _XdmcpAuthDoIt(input,output,ks,encrypt)
des_cblock *input;
des_cblock *output;
des_key_schedule ks;
int encrypt;
	{
	register unsigned long l,r,t,u;
	register unsigned long *s;
	uchar *in,*out;
	int i;

	in=(uchar *)input;
	out=(uchar *)output;
	c2l(in,l);
	c2l(in,r);

	/* do IP */
        PERM_OP(r,l,t, 4,0x0f0f0f0f);
        PERM_OP(l,r,t,16,0x0000ffff);
        PERM_OP(r,l,t, 2,0x33333333);
        PERM_OP(l,r,t, 8,0x00ff00ff);
        PERM_OP(r,l,t, 1,0x55555555);
        /* r and l are reversed - remember that :-) */
        t=l;
        l=r;
	r=t;

	s=(ulong *)ks;

	if (encrypt)
		{
		for (i=0; i<(ITERATIONS*2); i+=4)
			{
			D_ENCRYPT(l,r,  i); /*  1 */
			D_ENCRYPT(r,l,  i+2); /*  2 */
			}
		}
	else
		{
		for (i=(ITERATIONS*2)-2; i >= 0; i-=4)
			{
			D_ENCRYPT(l,r,  i); /*  1 */
			D_ENCRYPT(r,l,  i-2); /*  2 */
			}
		}

	/* swap l and r
	 * we will not do the swap so just remember they are
	 * reversed for the rest of the subroutine
         * luckily by FP fixes this problem :-) */

        PERM_OP(r,l,t, 1,0x55555555);
        PERM_OP(l,r,t, 8,0x00ff00ff);
        PERM_OP(r,l,t, 2,0x33333333);
        PERM_OP(l,r,t,16,0x0000ffff);
        PERM_OP(r,l,t, 4,0x0f0f0f0f);

	l2c(l,out);
	l2c(r,out);
	return(0);
	}

/*
 * $TOG: Wrap.c /main/10 1998/02/06 14:41:53 kaleb $
 *
 * 
Copyright 1989, 1998  The Open Group

All Rights Reserved.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.
 * *
 * Author:  Keith Packard, MIT X Consortium
 */

/* $XFree86: xc/lib/Xdmcp/Wrap.c,v 1.2 1998/10/10 15:25:18 dawes Exp $ */

/*#include <X11/Xos.h>
#include <X11/X.h>
#include <X11/Xmd.h>
#include <X11/Xdmcp.h>

#ifdef HASXDMAUTH
*/
/*
 * The following function exists only to demonstrate the
 * desired functional interface for this routine.  You will
 * need to add the appropriate algorithm if you wish to
 * use XDM-AUTHENTICATION-1/XDM-AUTHORIZATION-1.
 *
 * Examine the XDMCP specification for the correct algorithm
 */

void
XdmcpWrap (
    unsigned char	*input,
    unsigned char	*wrapper,
    unsigned char	*output,
    int			bytes)
{
    int			i, j;
    int			len;
    unsigned char	tmp[8];
    unsigned char	expand_wrapper[8];
    auth_wrapper_schedule	schedule;

    _XdmcpWrapperToOddParity (wrapper, expand_wrapper);
    _XdmcpAuthSetup (expand_wrapper, schedule);
    for (j = 0; j < bytes; j += 8)
    {
	len = 8;
	if (bytes - j < len)
	    len = bytes - j;
	/* block chaining */
	for (i = 0; i < len; i++)
	{
	    if (j == 0)
		tmp[i] = input[i];
	    else
		tmp[i] = input[j + i] ^ output[j - 8 + i];
	}
	for (; i < 8; i++)
	{
	    if (j == 0)
		tmp[i] = 0;
	    else
		tmp[i] = 0 ^ output[j - 8 + i];
	}
	_XdmcpAuthDoIt (tmp, (output + j), schedule, 1);
    }
}

/*
 * Given a 56 bit wrapper in XDMCP format, create a 56
 * bit wrapper in 7-bits + odd parity format
 */

static int
OddParity (unsigned char c)
{
    c = c ^ (c >> 4);
    c = c ^ (c >> 2);
    c = c ^ (c >> 1);
    return ~c & 0x1;
}

/*
 * Spread the 56 bit wrapper among 8 bytes, using the upper 7 bits
 * of each byte, and storing an odd parity bit in the low bit
 */

void
_XdmcpWrapperToOddParity (
    unsigned char   *in,
    unsigned char   *out)
{
    int		    ashift, bshift;
    int		    i;
    unsigned char   c;

    ashift = 7;
    bshift = 1;
    for (i = 0; i < 7; i++)
    {
	c = ((in[i] << ashift) | (in[i+1] >> bshift)) & 0x7f;
	out[i] = (c << 1) | OddParity (c);
	ashift--;
	bshift++;
    }
    c = in[i];
    out[i] = (c << 1) | OddParity(c);
}

/*
 * $TOG: Unwrap.c /main/10 1998/02/06 14:41:06 kaleb $
 *
 * 
Copyright 1989, 1998  The Open Group

All Rights Reserved.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.
 * *
 * Author:  Keith Packard, MIT X Consortium
 */

/* $XFree86: xc/lib/Xdmcp/Unwrap.c,v 1.2 1998/10/10 15:25:16 dawes Exp $ */

/*#include <X11/Xos.h>
#include <X11/X.h>
#include <X11/Xmd.h>
#include <X11/Xdmcp.h>

#ifdef HASXDMAUTH
*/
/*
 * The following function exists only to demonstrate the
 * desired functional interface for this routine.  You will
 * need to add the appropriate algorithm if you wish to
 * use XDM-AUTHENTICATION-1/XDM-AUTHORIZATION-1.
 *
 * The interface for this routine is quite simple.  All three
 * arguments are arrays of 8 unsigned characters, the first two
 * are 64 bits of useful data, the last is 56 bits of useful
 * data packed into 8 bytes, using the low 7 bits of each
 * byte, filling the high bit with odd parity.
 *
 * Examine the XDMCP specification for the correct algorithm
 */

void
XdmcpUnwrap (
    unsigned char	*input,
    unsigned char	*wrapper,
    unsigned char	*output,
    int			bytes)
{
    int			i, j, k;
    unsigned char	tmp[8];
    unsigned char	blocks[2][8];
    unsigned char	expand_wrapper[8];
    auth_wrapper_schedule	schedule;

    _XdmcpWrapperToOddParity (wrapper, expand_wrapper);
    _XdmcpAuthSetup (expand_wrapper, schedule);

    k = 0;
    for (j = 0; j < bytes; j += 8)
    {
	if (bytes - j < 8)
	    return; /* bad input length */
	for (i = 0; i < 8; i++)
	    blocks[k][i] = input[j + i];
	_XdmcpAuthDoIt ((unsigned char *) (input + j), (unsigned char *) tmp, schedule, 0);
	/* block chaining */
	k = (k == 0) ? 1 : 0;
	for (i = 0; i < 8; i++)
	{
	    if (j == 0)
		output[j + i] = tmp[i];
	    else
		output[j + i] = tmp[i] ^ blocks[k][i];
	}
    }
}

#endif /* FWDX_XDM */
