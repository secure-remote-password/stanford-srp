/*
 * Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 *
 * This library and applications are FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the conditions within the COPYRIGHT file are adhered to.
 *
 */

package security.math;

import java.io.PrintStream;

/**
 * This class is public, but the constructor is protected.
 * It is intended that this class be used as a base for the BigInteger
 * wrapper class, and not used directly.
 *
 *	It is an implementation class, and should really be called
 *	BigIntegerImpl :-(
 *
 * <p>Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 */
public class BigNum implements Cloneable
{
	private static final String LIBRARY_NAME = "bignum";

	private static boolean native_link_ok = false;
	private static boolean native_lib_loaded = false;
	private static String native_link_err = "Class not loaded";

	private static BigNum staticZero;
	private static BigNum staticOne;

/*
	static 
	{
		// load the DLL or shared library that contains the native code
		try
		{
			System.loadLibrary( LIBRARY_NAME );
			native_lib_loaded = true;
			try
			{
				//
				//	Should really do a bit more testing than this ...
				//
				if (bignum_test() == 0)
				{
					// create a static BigNum that will be set to one.
					native_link_ok = true;
					native_link_err = null;

					staticOne = new BigNum();
					staticOne.setToOne();
				}
				else
				{
					native_link_err = "Self test failed";
				}
			}
			catch ( UnsatisfiedLinkError ule )
			{
				native_link_err = "Errors linking to " + LIBRARY_NAME + " native library";
			}
		}
		catch ( UnsatisfiedLinkError ule )
		{
			native_link_err = "The " + LIBRARY_NAME + " native library was not found";
		}
		catch ( Exception e )
		{
			native_link_err = "The " + LIBRARY_NAME + " native library could not be linked";
		}
	}
*/

	public final static boolean
	hasFileLibraryLoaded()
	{
		return native_lib_loaded;
	}

	public final static boolean
	isLibraryCorrect()
	{
		return native_link_ok;
	}

	public final static String
	getLinkErrorString()
	{
		return native_link_err;
	}
	


	//
	//	Constants
	//

	// If LONG
	// static final int BITS = 62; // Not 63, since we dont have unsigned
	// static final long RADIX = (1L << BITS);
	// static final long MASK = RADIX-1;
	// static final int LBITS = BITS/2;
	// static final long LRADIX = (1L << LBITS);
	// static final long LMASK = LRADIX-1;

	// If not LONG
	static final int BITS = 30;
	static final int RADIX = (1 << BITS);
	static final int MASK = RADIX-1;
	static final int LBITS = BITS/2;
	static final int LRADIX = (1 << LBITS);
	static final int LMASK = LRADIX-1;

	//
	//	Data members for Java implementation
	//

	// If LONG
	// private long n[];
	// If not LONG
	private int n[];

	private int len;
	private boolean negative;

	//
	//	Data members for native implementation
	//
	private int pointer_; // N.B. may need to be long if running on a 64bit machine


	public int byteLength()
	{
		if (native_link_ok)
		{
			return bignum_bytelen();
		}
		else
		{
			int r = ((len - 1) * BITS)/8;

			// If LONG
			// long i = n[0];
			// If not LONG
			int i = n[0];

			while (i != 0)
			{
				i >>>= 8;
				++r;
			}
			return r;
		}
	}

	public void check_state()
	{
		bitLength(this);
	}

	public static
	int bitLength(BigNum n)
	{
		if (native_link_ok)
		{
			return bignum_bitlen(n);
		}
		else
		{
			int len = n.len;

			if (len == 0)
				return 0;

			int r = (len - 1) * BITS;

			// If LONG
			// long i = n.n[len-1];
			// If not LONG
			int i = n.n[len-1];

			// Could probably speed this up with a binary search
			while (i != 0)
			{
				i >>>= 1;
				++r;
			}

// For debugging only
// if (r == 0) throw new MathError("Invalid state");

			return r;
		}
	}

	public static
	boolean bit(BigNum n, int i)
	{
		if (native_link_ok)
		{
			// return bignum_bit(n, i);
			throw new MathError("bignum_bit failed");
		}
		else
		{
			int bit = i % BITS;
			i /= BITS;

			if (i >= n.len || ((n.n[i] & (1L << bit)) == 0))
				return false;
			return true;
		}
	}

	protected BigNum()
	{
		if (native_link_ok)
		{
			bignum_new();
		}
		else
		{
			// If LONG
			// n = new long[8];	// 512 bits (nearly)
			// If not LONG
			n = new int[16];	// 512 bits (nearly)

			len = 0;
			negative = false;
		}
	}
	
	public Object
	clone()
	{
		BigNum r = new BigNum();
		copy(r, this);
		return r;
	}
	
	public void
	copy(Object src)
	{
		copy(this, (BigNum)src);
	}
	
	protected static void
	copy(BigNum dst, BigNum src)
	{
		if (dst == src)
			return;
			// throw new IllegalArgumentException();

		if (native_link_ok)
		{
			if ((bignum_copy(dst, src)) == 0)
				throw new MathError("copy failed");
		}
		else
		{
			// If LONG
			// dst.n = new long[src.n.length];
			// If not LONG
			dst.n = new int[src.n.length];

			dst.negative = src.negative;
			dst.len = src.len;
			if (src.len > 0)
				System.arraycopy(src.n, 0, dst.n, 0, src.len);
		}
	}

	public static void
	grow(BigNum a, int i)
	{
		if (native_link_ok)
		{
			if (bignum_grow(a, i) == 0)
				throw new MathError( "grow failed" );
		}
		else
		{
			// If LONG
			// long an[] = a.n;
			// If not LONG
			int an[] = a.n;

			if (i <= an.length)
				return;

			i += 16; // Add 8 or 16 for efficiency

			// If LONG
			// long n[] = new long[i];
			// If not LONG
			int n[] = new int[i];

			System.arraycopy(an, 0, n, 0, an.length);
			a.n = n;
		}
	}


	public int
	intoBinary(byte buffer[])
	{
		if (native_link_ok)
		{
			int r;
			if (buffer.length < (byteLength()))
				throw new MathError("into-binary buffer too small");
			if ((r = bignum_into_bytes(buffer)) == 0)
				throw new MathError("into-binary failed");
			return r;
		}
		else
		{
			int len = (bitLength(this)+7)/8;
			if (buffer.length < (len))
				throw new MathError("into-binary buffer too small");

			int pos = 0;
			int bitpos = 0;

			// Index in reverse to get LSB first
			for (int i = len-1; i >= 0; --i)
			{
				int b = (int)((n[pos] >>> bitpos) & 0xFFL);
				bitpos += 8;
				if (bitpos >= BITS)
				{
					bitpos -= BITS;
					pos++;
					if (bitpos > 0)
						b |= (n[pos] << (8-bitpos)) & 0xFFL;
				}
				buffer[i] = (byte)b;
			}
			return len;
		}
	}

	protected void 
	fromBinary(byte buffer[])
	{
		if (native_link_ok)
		{
			// Why is this throwing exceptions?
			if ((bignum_from_bytes(buffer)) == 0)
				throw new MathError("from-binary failed");
		}
		else
		{
			negative = false;	// Can't init negatives yet
			len = ((buffer.length)*8 + BITS-1) / BITS;
			grow(this, len);

			int pos = 0;
			n[pos] = 0;
			int bitpos = 0;
			// Index in reverse to get LSB first
			for (int i = buffer.length-1; i >= 0; --i)
			{
				// If LONG
				// long b = buffer[i] & 0xFF;
				// If not LONG
				int b = buffer[i] & 0xFF;

				n[pos] |= (b << bitpos) & MASK;
				bitpos += 8;
				if (bitpos >= BITS)
				{
					pos++;
					n[pos] = 0;
					bitpos -= BITS;
					if (bitpos > 0)
						n[pos] = b >>> (8-bitpos);
				}
			}
			while (len > 0 && n[len-1] == 0)
				len--;
		}
	}

	public static void
	assign(BigNum r, int val)
	{
		if (native_link_ok)
		{
			if (bignum_set_word(r, val) == 0)
				throw new MathError("set to integer failed");
		}
		else
		{
			if (val != 0)
			{
				r.len = 1;

				// If LONG
				// r.n[0] = val & 0x7FFFFFFFL;
				// If not LONG
				r.n[0] = val & 0x7FFFFFFF;

				r.negative = (val < 0);
			}
			else
			{
				r.len = 0;
				r.n[0] = 0;
				r.negative = false;
			}
		}
	}

	public static void
	zero(BigNum a)
	{
		if (native_link_ok)
		{
			if (a.setToZero() == 0)
				throw new MathError( "set to zero failed" );
		}
		else
		{
			a.n[0] = 0;
			a.negative = false;
			a.len = 0;
		}
	}

	public static void
	one(BigNum a)
	{
		if (native_link_ok)
		{
			if (a.setToOne() == 0)
				throw new MathError( "set to one failed" );
		}
		else
		{
			a.n[0] = 1;
			a.negative = false;
			a.len = 1;
		}
	}

	public static boolean
	isOne(BigNum a)
	{
		if (native_link_ok)
		{
			return (bignum_iszero(a) == 0);
		}
		else
		{
			return (a.len == 1 && a.n[0] == 1);
		}
	}

	public static boolean
	even(BigNum a)
	{
		if (native_link_ok)
		{
			// return (bignum_iseven(a) == 0);
			throw new MathError( "no native lib" );
		}
		else
		{
			return !(a.len > 0 && (a.n[0] & 1) == 1);
		}
	}

	public static boolean
	odd(BigNum a)
	{
		if (native_link_ok)
		{
			// return (bignum_isodd(a) == 0);
			throw new MathError( "no native lib" );
		}
		else
		{
			return (a.len > 0 && (a.n[0] & 1) == 1);
		}
	}

	public static boolean
	isZero(BigNum a)
	{
		if (native_link_ok)
		{
			return (bignum_iszero(a) == 0);
		}
		else
		{
			if (a.len == 0) return true;
a.check_state();
			// if (a.len > 1) return false;
			// return (a.n[0] == 0);
			return false;
		}
	}

	public static void
	inc(BigNum a)
	{
		add(a, 1);
	}

	public static void
	dec(BigNum a)
	{
		sub(a, 1);
	}

	public static void
	add( BigNum r, int a )
	{
		if (a == 0)
			return;

		if (native_link_ok)
		{
			throw new MathError("not yet implemented");
		}
		else
		{
			if (a < 0)
			{
				if (r.negative)
				{
					r.negative = false;
					add_unsigned(r, -a);
					r.negative = true;
				}
				else
				{
					sub_unsigned(r, -a);
				}
			}
			else
			{
				if (r.negative)
				{
					r.negative = false;
					sub_unsigned(r, a);
					r.negative = true ^ r.negative;
				}
				else
				{
					add_unsigned(r, a);
				}
			}
		}
	}

	public static void
	sub(BigNum r, int a)
	{
		if (a == 0)
			return;

		if (native_link_ok)
		{
			throw new MathError("not yet implemented");
		}
		else
		{
//			//
//			// Test for zeroes
//			//
//			if (a == 0)
//				return;
//			if (isZero(r))
//			{
//				assign(r, a);
//				r.negative = (a < 0);
//				return;
//			}


			if (a < 0)
			{
				if (r.negative)
				{
					r.negative = false;
					sub_unsigned(r, -a);
					r.negative = true ^ r.negative;
				}
				else
				{
					add_unsigned(r, -a);
				}
			}
			else
			{
				if (r.negative)
				{
					r.negative = false;
					add_unsigned(r, a);
					r.negative = true;
				}
				else
				{
					sub_unsigned(r, a);
				}
			}
		}
	}


	public static void
	add(BigNum r ,BigNum a, BigNum b)
	{
		if (native_link_ok)
		{
			if (bignum_add(r, a, b) == 0)
				throw new MathError("addition failed");
		}
		else
		{
			//
			// Test for zeroes
			//
			if (a.len == 0)
			{
				copy(r, b);
				return;
			}
			if (b.len == 0)
			{
				copy(r, a);
				return;
			}

			if (a.negative)
			{
				if (b.negative)
				{
					add_unsigned(r, a, b);
					r.negative = true;
				}
				else
				{
					sub_unsigned(r, b, a);
				}
			}
			else
			{
				if (b.negative)
				{
					sub_unsigned(r, a, b);
				}
				else
				{
					add_unsigned(r, a, b);
				}
			}
		}
	}

	public static void
	add_unsigned(BigNum r, int a)
	{
		if (native_link_ok)
		{
			throw new MathError("not yet implemented");
		}
		else
		{
			if (a == 0)
				return;

			if (a < 0)
				throw new MathError("unexpected negative");

			if (r.len == 0)
			{
				r.n[0] = a;
				r.len = 1;
				r.negative = false;
				return;
			}

			// Not tested till now, since len may have been zero
			if (r.negative)
				throw new MathError("unexpected negative");


			grow(r, r.len+1);
			boolean carry = false;

			// If LONG
			// long rn[] = r.n;
			// long sum = rn[0] + a;
			// If not LONG
			int rn[] = r.n;
			int sum = rn[0] + a;

			rn[0] = sum & MASK;
			carry = (sum >= RADIX);

			int i = 1;
			int rlen = r.len;
			for (;carry && i < rlen; ++i)
			{
				sum = rn[i] + 1;
				if (sum < RADIX)
				{
					rn[i] = sum;
					carry = false;
				}
				else
				{
					rn[i] = sum & MASK;
				}
			}
			if (carry)
			{
				rn[i] = 1;
				r.len++;
			}
		}
	}

	public static void
	add_unsigned(BigNum r ,BigNum a, BigNum b)
	{
		if (native_link_ok)
		{
			if (bignum_add(r, a, b) == 0)
				throw new MathError("addition failed");
		}
		else
		{
			// Ensure a is the longest
			if (a.len < b.len)
			{
				BigNum t = a;
				a = b;
				b = t;
			}

			// Needed in case the result is same object as r
			int alen = a.len;
			int blen = b.len;

			r.len = alen;
			grow(r, r.len);
			r.negative = false;

			// If LONG
			// long an[] = a.n;
			// long bn[] = b.n;
			// long rn[] = r.n;
			// If not LONG
			int an[] = a.n;
			int bn[] = b.n;
			int rn[] = r.n;

			boolean carry = false;
			int i;
			for (i=0; i < blen; ++i)
			{
				// If LONG
				// long sum = an[i] + bn[i] + (carry ? 1 : 0);
				// If not LONG
				int sum = an[i] + bn[i] + (carry ? 1 : 0);

				rn[i] = sum & MASK;
				carry = (sum >= RADIX);
			}
			for (;carry && i < alen; ++i)
			{
				// If LONG
				// long sum = an[i] + 1;
				// If not LONG
				int sum = an[i] + 1;

				if (sum < RADIX)
				{
					rn[i] = sum;
					carry = false;
				}
				else
				{
					rn[i] = sum & MASK;
				}
			}
			if (a.len > i)
				System.arraycopy(an, i, rn, i, alen-i);
			if (carry)
			{
				r.len++;
				grow(r, r.len);
				r.n[i] = 1;	// Note - rn not valid after grow
			}
// r.check_state();
		}
	}


	public static void
	sub(BigNum r, BigNum a, BigNum b)
	{
		if (native_link_ok)
		{
			if (bignum_sub(r, a, b) == 0)
				throw new MathError("addition failed");
		}
		else
		{
			//
			// Test for zeroes
			//
			if (a.len == 0)
			{
				copy(r, b);
				if (b.len > 0)
					r.negative = true ^ b.negative;
				return;
			}
			if (b.len == 0)
			{
				copy(r, a);
				return;
			}

			if (a.negative)
			{
				if (b.negative)
				{
					sub_unsigned(r, b, a);
				}
				else
				{
					add_unsigned(r, b, a);
					r.negative = true;
				}
			}
			else
			{
				if (b.negative)
				{
					add_unsigned(r, a, b);
				}
				else
				{
					sub_unsigned(r, a, b);
				}
			}
		}
	}


	public static void
	sub_unsigned(BigNum r, int a)
	{
		if (native_link_ok)
		{
			throw new MathError("not yet implemented");
		}
		else
		{
			if (a == 0)
				return;

			if (a < 0)
				throw new MathError("unexpected negative");

			if (r.len == 0)
			{
				r.n[0] = a;
				r.len = 1;
				r.negative = true;
				return;
			}

			// Not tested till now, since len may have been zero
			if (r.negative)
				throw new MathError("unexpected negative");

			// If LONG
			// long rn[] = r.n;
			// If not LONG
			int rn[] = r.n;

			int rlen = r.len;

			if (rlen == 1)
			{
				if (a == rn[0])
				{
					rn[0] = 0;
					r.len = 0;
					r.negative = false;
					return;
				}
				if (a < rn[0])
				{
					rn[0] -= a;
					return;
				}
				r.negative = true;
			}

			// If LONG
			// long diff = r.n[0] - a;
			// If not LONG
			int diff = rn[0] - a;

			rn[0] = diff & MASK;
			boolean borrow = (diff < 0);

			for (int i = 0; borrow && i < rlen; ++i)
			{
				diff = rn[i] - 1;
				if (diff >= 0)
				{
					rn[i] = diff;
					borrow = false;
				}
				else
				{
					rn[i] = diff & MASK;
				}
			}

			while (rlen > 0 && rn[rlen-1] == 0)
				rlen--;
			r.len = rlen;
		}
	}

	public static void
	sub_unsigned(BigNum r, BigNum a, BigNum b)
	{
		if (native_link_ok)
		{
			if (bignum_sub(r, a, b) == 0)
				throw new MathError("addition failed");
		}
		else
		{
			switch (ucmp(a, b))
			{
			case 0:
				zero(r);
				return;
			case -1:
				BigNum t = a;
				a = b;
				b = t;
				r.negative = true;
				break;
			case 1:
				r.negative = false;
			}

			// Now a is the largest

			grow(r, a.len);

			// If LONG
			// long an[] = a.n;
			// long bn[] = b.n;
			// long rn[] = r.n;
			// If not LONG
			int an[] = a.n;
			int bn[] = b.n;
			int rn[] = r.n;
			int alen = a.len;
			int blen = b.len;

			boolean borrow = false;
			int i;
			for (i=0; i < blen; ++i)
			{
				// If LONG
				// long diff = an[i] - bn[i] - (borrow ? 1 : 0);
				// If not LONG
				int diff = an[i] - bn[i] - (borrow ? 1 : 0);

				rn[i] = diff & MASK;
				borrow = (diff < 0);
			}
			for (;borrow && i < alen; ++i)
			{
				// If LONG
				// long diff = an[i] - 1;
				// If not LONG
				int diff = an[i] - 1;

				if (diff >= 0)
				{
					rn[i] = diff;
					borrow = false;
				}
				else
				{
					rn[i] = diff & MASK;
				}
			}
			if (a.len > i)
				System.arraycopy(an, i, rn, i, a.len-i);

			int rlen = a.len;
			while (rlen > 0 && rn[rlen-1] == 0)
				rlen--;
			r.len = rlen;
		}
	}

	//
	// returns 0 if a==b
	// returns -1 if a<b
	// returns 1 if a>b
	//
	public static int
	cmp( BigNum a, BigNum b)
	{
		if (native_link_ok)
		{
			return bignum_cmp( a, b );
		}
		else
		{
			// Not strictly necessary
			// but we're never sure of the sign flag on a zero
			if (a.len == 0 && b.len == 0) return 0;

			if (a.negative)
			{
				if (b.negative)
				{
					return ucmp(b, a);
				}
				else
				{
					return -1;
				}
			}
			else
			{
				if (b.negative)
				{
					return 1;
				}
				else
				{
					return ucmp(a, b);
				}
			}
		}
	}

	public static int
	ucmp(BigNum a, BigNum b)
	{
		if (native_link_ok)
		{
			return bignum_ucmp(a, b);
		}
		else
		{
			int alen = a.len;
			int blen = b.len;

			if (alen < blen) return -1;
			if (alen > blen) return 1;

			// If LONG
			// long an[] = a.n;
			// long bn[] = b.n;
			// If not LONG
			int an[] = a.n;
			int bn[] = b.n;


			for (int i = alen-1; i >= 0; --i)
			{
				if (an[i] < bn[i]) return -1;
				if (an[i] > bn[i]) return 1;
			}
			return 0;
		}
	}

	public static void
	shiftLeft(BigNum r, BigNum a, int n)
	{
		shiftLeft(r, a, (short)n);
	}

	public static void
	shiftLeft(BigNum r, BigNum a, short n)
	{
		if (native_link_ok)
		{
			if ( bignum_lshift( r, a, n ) == 0 )
				throw new MathError( "shift left failed" );
		}
		else
		{
			if (a.len == 0)
			{
				zero(r);
				return;
			}
			int rem = n % BITS;
			int blocks = n / BITS;
			int len = a.len;

			r.len = len + blocks;
			grow(r, r.len);

			// If LONG
			// long rn[] = r.n;
			// If not LONG
			int rn[] = r.n;

			System.arraycopy(a.n, 0, rn, blocks, len);

			if (blocks > 0)
				for (int i = blocks-1; i >= 0 ; --i) { rn[i] = 0; }

			if (rem != 0)
			{
				// If LONG
				// long carry = 0;
				// If not LONG
				int carry = 0;

				int rlen = r.len;
				for (int i = blocks; i < rlen; ++i)
				{
					// If LONG
					// long l = rn[i];
					// If not LONG
					int l = rn[i];

					rn[i] = ((l << rem) | carry) & MASK;
					carry = l >>> (BITS-rem);
				}
				if (carry != 0)
				{
					rlen += 1;
					grow(r, rlen);
					r.n[rlen-1] = carry;
					r.len = rlen;
				}
			}
		}
	}

	public static void
	shiftLeftOnce(BigNum r, BigNum a)
	{
		if (native_link_ok)
		{
			if ( bignum_lshift1( r, a ) == 0 )
				throw new MathError( "shift left once failed" );
		}
		else
		{
			shiftLeft(r, a, (short)1);
		}
	}
	
	public static void
	shiftRight(BigNum r, BigNum a, int n)
	{
		shiftRight(r, a, (short)n);
	}

	public static void
	shiftRight(BigNum r, BigNum a, short n)
	{
		if (native_link_ok)
		{
			if ( bignum_rshift( r, a, n ) == 0 )
				throw new MathError( "shift right failed" );
		}
		else
		{
			int rem = n % BITS;
			int blocks = n / BITS;

			if (blocks >= a.len)
			{
				zero(r);
				return;
			}

			r.len = a.len - blocks;
			grow(r, r.len);

			System.arraycopy(a.n, blocks, r.n, 0, r.len);

			if (rem != 0)
			{
				// If LONG
				// long carry = 0;
				// long rn[] = r.n;
				// If not LONG
				int carry = 0;
				int rn[] = r.n;

				int rlen = r.len;
				for (int i = rlen-1; i > 0; --i)
				{
					// If LONG
					// long l = r.n[i];
					// If not LONG
					int l = rn[i];

					rn[i] = (l >>> rem) | carry;
					carry = (l << (BITS-rem)) & MASK;
				}
				// If LONG
				// long l = rn[0];
				// If not LONG
				int l = rn[0];

				rn[0] = (l >>> rem) | carry;
				if (rlen > 0 && rn[rlen-1] == 0)
					r.len--;
			}
		}
	}

	public static void
	shiftRightOnce(BigNum r, BigNum a)
	{
		if (native_link_ok)
		{
			if ( bignum_rshift1( r, a ) == 0 )
				throw new MathError( "shift right once failed" );
		}
		else
		{
			shiftRight(r, a, (short)1);
		}
	}


	/**
	 * r must not be the same object as a or b
	 */
	public static void
	mul(BigNum r ,BigNum a, BigNum b)
	{
		if ( r == a || r == b )
			throw new MathError( "Result must not be either Parameter ( a or b )" );

		if (native_link_ok)
		{
			if ( bignum_mul( r, a, b ) == 0 )
				throw new MathError( "multiply failed" );
		}
		else
		{
			//
			//	Test for zeroes
			//
			if (a.len == 0 || b.len == 0)
			{
				zero(r);
				return;
			}

			r.negative = a.negative ^ b.negative;
			r.len = a.len + b.len;
			grow(r, r.len);

			// If LONG
			// long an[] = a.n;
			// long bn[] = b.n;
			// long rn[] = r.n;
			// If not LONG
			int an[] = a.n;
			int bn[] = b.n;
			int rn[] = r.n;

			int alen = a.len;
			int blen = b.len;
			int rlen = r.len;

			for (int i = rlen-1; i >= 0; --i) { rn[i] = 0; }

	// If LONG
	//		for (int i = 0; i < a.len; ++i)
	//		{
	//			long carry = 0;
	//			long al = a.n[i] & LMASK;
	//			long ah = (a.n[i] >>> LBITS) & LMASK;
	//			int ri = i;

	//			for (int j = 0; j < b.len; ++j)
	//			{
	//				long bl = b.n[j] & LMASK;
	//				long bh = (b.n[j] >>> LBITS) & LMASK;

	//				long m1 = ah * bl;
	//				long l = al * bl;
	//				long m2 = al * bh;
	//				long h = ah * bh;

	//				m1 += m2;
	//				if ((m1 & MASK) < m2)
	//					h += LRADIX;
	//				h += (m1 >>> LBITS) & LMASK;

	//				m2 = (m1 & LMASK) << LBITS;
	//				l += m2;
	//				if ((l & MASK) < m2)
	//					h++;

	//				m1 = r.n[ri];
	//				l += m1;
	//				if ((l & MASK) < m1)
	//					h++;
	//				l += carry;
	//				if ((l & MASK) < carry)
	//					h++;
	//				carry = h & MASK;
	//				r.n[ri++] = l & MASK;
	//			}
	//			r.n[ri] = carry;
	//		}
	// If not LONG
			for (int i = 0; i < a.len; ++i)
			{
				long carry = 0;
				long m1 = an[i];
				int ri = i;

				for (int j = 0; j < b.len; ++j)
				{
					long m2 = rn[ri];
					m2 += bn[j] * m1 + carry;
					carry = m2 >>> BITS;
					rn[ri++] = (int)m2 & MASK;
				}
				rn[ri] = (int)carry;
			}


			if (rn[rlen-1] == 0)
				r.len--;
		}
	}

	//
	//	r cannot be m
	//
	public static void
	mod(BigNum r, BigNum m, BigNum d)
	{
		if (native_link_ok)
		{
			if ( bignum_mod( r, m, d ) == 0 )
				throw new MathError( "modulo failed" );
		}
		else
		{
			copy(r, m);
			if (ucmp(m, d) < 0)
				return;

			int i = bitLength(m) - bitLength(d);

			BigNum ds = new BigNum();
			shiftLeft(ds, d, i);

			for (; i>= 0; --i)
			{
				if (cmp(r, ds) >= 0)
					sub(r, r, ds);
				shiftRight(ds, ds, (short)1);
			}
		}
	}

	public static void
	div(BigNum dv ,BigNum m, BigNum d)
	{
		if (native_link_ok)
		{
			if ( bignum_div( dv, null, m, d ) == 0 )
				throw new MathError( "divide failed" );
		}
		else
		{
			div(dv, null, m, d);
		}
	}

	public static void
	div(BigNum dv ,BigNum rem, BigNum m, BigNum d)
	{
		if (native_link_ok)
		{
			if ( bignum_div( dv, rem, m, d ) == 0 )
				throw new MathError( "divide failed" );
		}
		else
		{
			if (d.len == 0)
				throw new MathError("divide by zero");

			if (cmp(m, d) < 0)
			{
				if (rem != null)
					copy(rem, m);
				if (dv != null)
					zero(dv);
				return;
			}

			if (dv == null)
				dv = new BigNum();
			if (rem == null)
				rem = new BigNum();

			BigNum ds = new BigNum();
			copy(rem, m);
			zero(dv);

			int i = bitLength(m) - bitLength(d);
			shiftLeft(ds, d, i);

			for (; i >= 0; --i)
			{
				if (dv.len == 0)
				{
					if (cmp(rem, ds) >= 0)
					{
						one(dv);
						sub(rem, rem, ds);
					}
				}
				else
				{
					shiftLeftOnce(dv, dv);
					if (cmp(rem, ds) >= 0)
					{
						dv.n[0] |= 1;
						sub(rem, rem, ds);
					}
				}
				shiftRightOnce(ds, ds);
			}
			dv.negative = m.negative ^ d.negative;
		}
	}

	public static void
	modExp( BigNum r, BigNum a, BigNum power, BigNum modulo)
	{
		if (native_link_ok)
		{
			if ( bignum_mod_exp( r, a, power, modulo ) == 0 )
				throw new MathError("modulo exp failed");
		}
		else
		{
			BigNum d = new BigNum();
			BigNum v = new BigNum();

			mod(v, a, modulo);
			int bits = bitLength(power);

			if ((power.n[0] & 1) != 0)
				mod(r, a, modulo);
			else
				one(r);

			int nb = recip(d, modulo);
			for (int i = 1; i < bits; i++)
			{
				modMulRecip(v, v, v, modulo, d, (short)nb);
				if (bit(power, i))
					modMulRecip(r, r, v, modulo, d, (short)nb);
			}
		}
	}

	public static void
	modMul( BigNum r, BigNum a, BigNum b, BigNum modulo)
	{
		if (native_link_ok)
		{
			if ( bignum_mod_mul( r, a, b, modulo ) == 0 )
				throw new MathError("modulo multiply failed");
		}
		else
		{
			BigNum t = new BigNum();
			mul(t, a, b);
			mod(r, t, modulo);
		}
	}

	public static int
	recip( BigNum r, BigNum m )
	{
		if (native_link_ok)
		{
			int returnValue;
			if ( ( returnValue = bignum_reciprical( r, m ) ) == -1 )
				throw new MathError("reciprical failed");
			return returnValue;
		}
		else
		{
			BigNum t = new BigNum();
			one(t);

			int mbits = bitLength(m);

			shiftLeft(t, t, 2*mbits);
			div(r, null, t, m);
			return mbits+1;
		}
	}

	public static void
	euclid(BigNum r, BigNum x, BigNum y )
	{
		if (native_link_ok)
		{
			// if (euclid(r, a, b) == 0 )
				throw new MathError("euclid failed");
		}
		else
		{
			BigNum a = new BigNum();
			BigNum b = new BigNum();

			copy(a, x);
			copy(b, y);

			int shifts = 0;

			while (b.len != 0)
			{
				if ((a.n[0] & 1) != 0)	// a odd
					if ((b.n[0] & 1) != 0)	// b odd
					{
						sub(a, a, b);
						shiftRightOnce(a, a);
						if (cmp(a, b) < 0)
						{
							BigNum t = a;
							a = b;
							b = t;
						}
					}
					else
					{
						shiftRightOnce(b, b);
						if (cmp(a, b) < 0)
						{
							BigNum t = a;
							a = b;
							b = t;
						}
					}
				else
					if ((b.n[0] & 1) != 0)	// b odd
					{
						shiftRightOnce(a, a);
						if (cmp(a, b) < 0)
						{
							BigNum t = a;
							a = b;
							b = t;
						}
					}
					else
					{
						shiftRightOnce(a, a);
						shiftRightOnce(b, b);
						shifts++;
					}
			}
			if (shifts > 0)
				shiftLeft(r, a, shifts);
			else
				copy(r, a);
		}
	}

	public static void
	gcd( BigNum r, BigNum a, BigNum b )
	{
		if (native_link_ok)
		{
			if (bignum_gcd( r, a, b ) == 0)
				throw new MathError("gcd failed");
		}
		else
		{
			if (cmp(a, b) > 0)
				euclid(r, a, b);
			else
				euclid(r, b, a);
		}
	}

	public static void
	modMulRecip(BigNum r, BigNum x, BigNum y, BigNum m, BigNum i, short nb )
	{
		if (native_link_ok)
		{
			if ( bignum_modmul_recip( r, x, y, m, i, nb ) == 0 )
				throw new MathError("modulo reciprical failed");
		}
		else
		{
			BigNum a = new BigNum();
			BigNum b = new BigNum();
			BigNum c = new BigNum();
			BigNum d = new BigNum();

			mul(a, x, y);
			shiftRight(d, a, nb-1);
			mul(b, d, i);
			shiftRight(c, b, nb-1);
			mul(b, m, c);
			sub(r, a, b);

			int j = 0;
			while (cmp(r, m) >= 0)
			{
				if (j++ > 2)
					throw new MathError("modulo reciprical failed");
				sub(r, r, m);
			}
		}
	}

//
//	Doesn't seem to work at present
//	(either implementation)
//
	public static void
	extended_euclid(BigNum u1, BigNum u2, BigNum u3, BigNum a, BigNum b)
	{
		if (native_link_ok)
		{
			// if ( extended_euclid( u1, u2, u3, a, b ) == 0 )
				throw new MathError("inverse modulo n failed");
		}
		else
		{
/*
			BigNum t;
//			BigNum in1 = u1;
//			BigNum in2 = u2;
//			BigNum in3 = u3;
			BigNum t1 = new BigNum();
			BigNum t2 = new BigNum();
			BigNum t3 = new BigNum();
			
			if (cmp(a, b) < 0)
			{
				t = a; a = b; b = t;
			}

			int k;
			for (k = 0; ((1 & a.n[0] & b.n[0]) == 0); ++k)
			{
				shiftRightOnce(a, a);
				shiftRightOnce(b, b);
			}

			one(u1);
			zero(u2);
			copy(u3, a);
			copy(t1, b);
			copy(t2, a); dec(t2);
			copy(t3, b);


			do {
				do {
					if (even(u3))
					{
						if (odd(u1) || odd(u2))
						{
							add(u1, u1, b);
							add(u2, u2, a);
						}
						shiftRightOnce(u1, u1);
						shiftRightOnce(u2, u2);
						shiftRightOnce(u3, u3);
					}
					if (even(t3) || (cmp(u3, t3) < 0))
					{
						t = u1; u1 = t1; t1 = t;
						t = u2; u2 = t2; t2 = t;
						t = u3; u3 = t3; t3 = t;
					}
				} while (even(u3));

				while (cmp(u1, t1) < 0 || cmp(u2, t2) < 0)
				{
					add(u1, u1, b);
					add(u2, u2, a);
				}
				sub(u1, u1, t1);
				sub(u2, u2, t2);
				sub(u3, u3, t3);
			} while (t3.len > 0 && !t3.negative);

			while (cmp(u1, b) >= 0 && cmp(u2, a) >= 0)
			{
				sub(u1, u1, b);
				sub(u2, u2, a);
			}

			shiftLeft(a, a, k);
			shiftLeft(b, b, k);
			shiftLeft(u3, u3, k);

//			copy(in1, u1);
//			copy(in2, u2);
//			copy(in3, u3);

/*
			if (isZero(b))
			{
				copy(u3, a);
				one(u1);
				zero(u2);
				return;
			}

			BigNum A = new BigNum();
			mod(A, a, b);

			extended_euclid(u1, u2, u3, b, A);

			BigNum t = new BigNum();
			copy(t, u1);
			copy(u1, u2);
			div(A, null, a, b);

			BigNum B = new BigNum();
			mul(B, u2, A);
			mul(A, t, B);
			copy(t, A);
			copy(u2, t);
*/
		}
	}

//
//	And this is in a state - only one of the three implementations
//	seems to go ...
//
	public static void
	inverseModN(BigNum r, BigNum a, BigNum n)
	{
		if (native_link_ok)
		{
			if (bignum_inverse_modn(r, a, n) == 0)
				throw new MathError("inverse modulo n failed");
		}
		else
		{
			if (a.negative || n.negative)
				throw new MathError("invalid negative argument");

/*
System.out.println("a = "+ a.toString());
System.out.println("n = "+ n.toString());
			BigNum x = new BigNum();
			BigNum y = new BigNum();
			BigNum u = new BigNum();
			BigNum v = new BigNum();
			BigNum gcd = new BigNum();

			copy(x, a);
			copy(y, n);

System.out.println("a = "+ a.toString());
System.out.println("n = "+ n.toString());
			extended_euclid(u, v, gcd, y, x);
copy(r, gcd); System.out.println("gcd = "+ r.toString());
copy(r, u); System.out.println("u = "+ r.toString());
copy(r, v); System.out.println("v = "+ r.toString());
copy(r, y); System.out.println("a = "+ r.toString());
copy(r, x); System.out.println("n = "+ r.toString());

//			if (v.negative)
//				add(v, v, n);

			// GCD should be 1 if successful
//			if (!(gcd.len == 1 && gcd.n[0] == 1))
//				throw new MathError("inverse modulo n failed");

			sub(r, n, v);
return;/*
//			mod(r, v, n);

// Now test
BigNum t = new BigNum();
modMul(t, a, r, n); 
if (t.len != 1 || t.n[0] == 1)
{
	System.out.println("a = "+ a.toString());
	System.out.println("n = "+ n.toString());
	System.out.println("r = "+ r.toString());
	throw new MathError("inverse modulo n failed");
}
else
	System.out.println("Inverse worked");

*/
			BigNum x1 = new BigNum();
			BigNum x2 = new BigNum();
			BigNum x3 = a;
			BigNum y1 = new BigNum();
			BigNum y2 = new BigNum();
			BigNum y3 = n;

			one(x1); one(y2);
			zero(x2); zero(y1);

			while (y3.len != 0)
			{
				BigNum t1 = new BigNum();
				BigNum t2 = new BigNum();
				BigNum t3 = new BigNum();
				BigNum q = new BigNum();
				BigNum p = new BigNum();

				div(q, t3, x3, y3);
				mul(t1, q, y2);
				sub(t2, x2, t1);
				mul(p, q, y1);
				sub(t1, x1, p);

				x1 = y1; x2 = y2; x3 = y3;
				y1 = t1; y2 = t2; y3 = t3;
			}

			if (x1.negative)
				add(x1, x1, n);

// copy(r, x1); System.out.println("x1 = "+ r.toString());
// copy(r, x3); System.out.println("x3 = "+ r.toString());

//			if (!x3.negative && x3.len == 1 && x3.n[0] == 1)
//				mod(r, x1, n);
//			else
//				throw new MathError("inverse modulo n failed");

			copy(r, x1);

/*

// Now test
BigNum t = new BigNum();
modMul(t, a, r, n); 
if (t.len != 1 || t.n[0] != 1)
	throw new MathError("inverse modulo n failed");
else
System.out.println("Inverse worked");




// Alternative again ...
			BigNum d = new BigNum();
			BigNum x = new BigNum();
			BigNum y = new BigNum();

			extended_euclid(d, x, y, n, a);

			if (b.len == 0)
			{
				copy(rd, a);
				one(rx);
				zero(ry);
				return;
			}

			BigNum A = new BigNum();
			mod(A, a, b);

			extended_euclid(rd, rx, ry, b, A);

			BigNum t = new BigNum();
			copy(t, rx);
			copy(rx, ry);
			div(a, null, a, b);

			BigNum B = new BigNum();
			mul(B, ry, A);
			mul(A, t, B);
			copy(t, A);
			copy(ry, t);


			if (y.negative)
				add(y, y, n);

			if (!d.negative && d.len == 1 && d.n[0] == 1)
				throw new MathError("inverse modulo n failed");

			mod(r, y, n);
*/
		}
	}



	public String
	toString()
	{
		throw new MathError("BigNums can not natively be strings.");
	}
	
	protected void finalize()
	{
		if (native_link_ok)
		{
			bignum_free();
		}
	}
	

	//
	//	Test code
	//
	public static void
	main(String argv[])
	{
		try {
			self_test(System.out, argv);
		}
		catch(Throwable t)
		{
			t.printStackTrace();
		}
	}

	public static void
	self_test(PrintStream out, String argv[])
	throws Exception
	{
	}

	public static void
	display(PrintStream out, BigNum x)
	{
		out.println("Length: "+x.len);
		out.println("Sign flag: "+ x.negative);
	}


	private native static int bignum_test();

	private native int bignum_new();
	private native void bignum_free();

	private native static int bignum_copy(BigNum a, BigNum b);
	private native static int bignum_iszero(BigNum a);
	private native static int bignum_grow(BigNum a, int i);
	private native static int bignum_bytelen();
	private native static int bignum_bitlen(BigNum a);

	private native int bignum_into_bytes(byte[] buffer);
	private native int bignum_from_bytes(byte[] buffer);

	private native int setToOne();
	private native int setToZero();

	private native static int bignum_add_word(BigNum a, int w);
	private native static int bignum_set_word(BigNum a, int w);
	private native static int bignum_add(BigNum r, BigNum a, BigNum b);
	private native static int bignum_sub(BigNum r, BigNum a, BigNum b);
	private native static int bignum_cmp(BigNum a, BigNum b);
	private native static int bignum_ucmp(BigNum a, BigNum b);




	public native int hashCode(); // just returns the MSB word but this allows use in hashtables etc.

	private native static int bignum_mul( BigNum r, BigNum a, BigNum b );
	private native static int bignum_mod( BigNum rem, BigNum m, BigNum d );
	private native static int bignum_div( BigNum dv, BigNum rem, BigNum m, BigNum d );
	private native static int bignum_lshift( BigNum r, BigNum a, short n );
	private native static int bignum_lshift1( BigNum r, BigNum a );
	private native static int bignum_rshift( BigNum r, BigNum a, short n );
	private native static int bignum_rshift1( BigNum r, BigNum a );
	private native static int bignum_mod_exp( BigNum r, BigNum a, BigNum p, BigNum m );
	private native static int bignum_modmul_recip( BigNum r, BigNum x, BigNum y, BigNum m, BigNum i, short nb );
	private native static int bignum_mod_mul( BigNum r, BigNum a, BigNum b, BigNum m );
	private native static int bignum_reciprical( BigNum r, BigNum m );
	private native static int bignum_gcd( BigNum r, BigNum a, BigNum b );
	private native static int bignum_inverse_modn( BigNum r, BigNum a, BigNum n );
}
