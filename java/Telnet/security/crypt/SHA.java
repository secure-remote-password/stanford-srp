/*
 * Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 *
 * This library and applications are FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the conditions within the COPYRIGHT file are adhered to.
 *
 */

package security.crypt;

import java.io.PrintStream;

/**
 * This class implements the SHA message digest.
 *
 * <p>Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 */
public final class SHA extends MessageDigest
{
	private static final String LIBRARY_NAME = "sha";
	private static final String DIGEST_NAME = "SHA";

	private static boolean native_link_ok = false;
	private static boolean native_lib_loaded = false;
	private static String native_link_err = "Class not loaded";

/*
	static 
	{
		// load the DLL or shared library that contains the native code
		// implementation of the SHA message digest algorithm.
		try
		{
			System.loadLibrary( LIBRARY_NAME );
			native_lib_loaded = true;
			try
			{
				//
				//	Should really do a bit more testing than this ...
				//
				if (sha_test() == 0)
				{
					native_link_ok = true;
					native_link_err = null;
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
	
	/**
	 * Length of the final hash (in bytes).
	 */
	public static final int HASH_LENGTH = 20;
	public static final int DATA_LENGTH = 64;


	//
	// Only required for java implementation
	//
	protected int data[];
	protected int digest[];
	protected byte tmp[];
	protected int w[];



	/**
	 * Return length of the hash (in bytes).
	 * @see #HASH_LENGTH
	 * @return   The length of the hash.
	 */
	public final int hash_length()
	{
		return HASH_LENGTH;
	}

	/**
	 * Return length of the data (in bytes) hashed in every transform.
	 * @return   The length of the data block.
	 */
	public final int data_length()
	{
		return DATA_LENGTH;
	}

	/**
	 * Return name of this hash function.
	 * @return   The name of the hash function.
	 */
	public String name()
	{
		return "SHA";
	}


	/**
	 * The public constructor.
	 * @throws UnsatisfiedLinkError if the library is not of the correct version
	 */
	public SHA()
	{
		if (native_link_ok) native_init(); else java_init();
		reset();
	}

	private void java_init()
	{
		digest = new int[HASH_LENGTH/4];
		data = new int[DATA_LENGTH/4];
		tmp = new byte[DATA_LENGTH];
		w = new int[80];
	}

	/**
	 * Initialise (reset) the message digest.
	 */
	public void md_reset()
	{
		if (native_link_ok) native_reset(); else java_reset();
	}

	private void java_reset()
	{
		digest[0] = 0x67452301;
		digest[1] = 0xefcdab89;
		digest[2] = 0x98badcfe;
		digest[3] = 0x10325476;
		digest[4] = 0xC3D2E1F0;
	}

	/**
	 * Add data to the message digest
	 * @param data    The data to be added.
	 * @param offset  The start of the data in the array.
	 * @param length  The amount of data to add.
	 */
	protected void md_transform()
	{
		if (native_link_ok) native_transform();
					else java_transform();
	}

	protected void java_transform()
	{
		byte2int(data, 0, buf(), 0, DATA_LENGTH/4);
		transform(data);
	}

	/**
	 * Returns the digest of the data added and resets the digest.
	 * @return    the digest of all the data added to the message digest as a byte array.
	 */
	protected byte[] md_digest()
	{
		return (native_link_ok) ? native_digest() : java_digest();
	}

	private byte[] java_digest()
	{
		int pos = buf_off();
		if (pos != 0) System.arraycopy(buf(), 0, tmp, 0, pos);

		tmp[pos++] = (byte)0x80;

		if (pos >= (DATA_LENGTH-8))
		{
			while (pos < DATA_LENGTH) tmp[pos++] = 0;
			byte2int(data, 0, tmp, 0, DATA_LENGTH/4);
			transform(data);
			pos = 0;
		}
		while (pos < (DATA_LENGTH-8)) tmp[pos++] = 0;

		byte2int(data, 0, tmp, 0, (DATA_LENGTH/4)-2);

		// Big endian
		data[14] = (int)(bitcount()>>>32);
		data[15] = (int)bitcount();

		transform(data);


		byte buf[] = new byte[HASH_LENGTH];

		// Big endian
		int off = 0;
		for (int i=0; i<HASH_LENGTH/4; ++i) {
			int d = digest[i];
			buf[off++] = (byte)(d>>>24);
			buf[off++] = (byte)(d>>>16);
			buf[off++] = (byte)(d>>>8);
			buf[off++] = (byte)d;
		}
		return buf;
	}


    /**
	 * Returns the digest of the data added and resets the digest.
	 * @return the digest of all the data added to the message digest as an object.
	 */
	public MessageHash digestAsHash()
	{
		return new HashSHA( this );
	}

	/**
	 * Returns the hash of a single string.
	 * @param msg the string to hash.
	 * @return the hash of the string.
	 */
	public static byte[]
	hash( String msg )
	{
		return hash( msg, new SHA() );
	}

	/**
	 * Returns the hash of a single byte array.
	 * @param msg the byte array to hash.
	 * @return the hash of the string.
	 */
	public static byte[]
	hash( byte msg[] )
	{
		return hash( msg, new SHA() );
	}

	/**
	 * Returns the MessageHash of a single string.
	 * @param msg the string to hash.
	 * @return the MessageHash of the string.
	 */
	public static HashSHA
	hashAsMessageHash( String msg )
	{
		return new HashSHA( hash( msg, new SHA() ) );
	}

	/**
	 * Returns the MessageHash of a single byte array.
	 * @param msg the byte array to hash.
	 * @return the MessageHash of the byte array.
	 */
	public static HashSHA
	hashAsMessageHash( byte msg[] )
	{
		return new HashSHA( hash( msg, new SHA() ) );
	}

	/**
	 * Returns the hash of a single byte array.
	 * @param msg the byte array to hash.
	 * @return the hash of the string.
	 */
	public static HashSHA
	CreateHash( byte hash[] )
	{
		return new HashSHA( hash );
	}




	//
	// SHA transform routines
	//
	static protected int f1(int a, int b, int c) { return (c^(a&(b^c))) + 0x5A827999; }
	static protected int f2(int a, int b, int c) { return (a^b^c) + 0x6ED9EBA1; }
	static protected int f3(int a, int b, int c) { return ((a&b)|(c&(a|b))) + 0x8F1BBCDC; }
	static protected int f4(int a, int b, int c) { return (a^b^c) + 0xCA62C1D6; }

	protected void transform (int X[])
	{
		int A = digest[0];
		int B = digest[1];
		int C = digest[2];
		int D = digest[3];
		int E = digest[4];

		int W[] = w;
		for (int i=0; i<16; i++)
		{
			W[i] = X[i];
		}
		for (int i=16; i<80; i++)
		{
			int j = W[i-16] ^ W[i-14] ^ W[i-8] ^ W[i-3];
			W[i] = j;
			W[i] = (j << 1) | (j >>> -1);
		}


		E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[0]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[1]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[2]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[3]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[4]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[5]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[6]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[7]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[8]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[9]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[10]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[11]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[12]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[13]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[14]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[15]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[16]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[17]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[18]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[19]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[20]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[21]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[22]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[23]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[24]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[25]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[26]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[27]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[28]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[29]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[30]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[31]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[32]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[33]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[34]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[35]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[36]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[37]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[38]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[39]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[40]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[41]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[42]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[43]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[44]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[45]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[46]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[47]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[48]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[49]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[50]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[51]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[52]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[53]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[54]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[55]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[56]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[57]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[58]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[59]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[60]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[61]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[62]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[63]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[64]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[65]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[66]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[67]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[68]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[69]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[70]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[71]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[72]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[73]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[74]; C =((C << 30)|(C >>> -30));
		E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[75]; B =((B << 30)|(B >>> -30));
		D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[76]; A =((A << 30)|(A >>> -30));
		C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[77]; E =((E << 30)|(E >>> -30));
		B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[78]; D =((D << 30)|(D >>> -30));
		A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[79]; C =((C << 30)|(C >>> -30));

		digest[0] += A;
		digest[1] += B;
		digest[2] += C;
		digest[3] += D;
		digest[4] += E;

	}









	//
	// The native functions that implement SHA
	//

	/**
	 * This is the amount of data required by the native code.
	 */
	private static final int INT_BUFFER_LENGTH = 88;

	/**
	 * The contextBuffer required by the native code.
	 */
    private byte contextBuf[]; /* SHA internal data buffer */

	private void native_init()
	{
		contextBuf = new byte[INT_BUFFER_LENGTH];
	}

	private void native_reset()
	{
		sha_init();
	}

	private void native_transform()
	{
		sha_transform(buf(), 0, data_length());
	}

	private byte[] native_digest()
	{
		byte buf[] = new byte[HASH_LENGTH];
		sha_finish(buf);
		return buf;
	}

	/**
	 * Resets the Context buffer to initial values.
	 */
	private synchronized native void sha_init();

	/**
	 * Adds to the hash.
	 * @param data    The data to be added.
	 * @param offset  The start of the data within the array.
	 * @param length  The amount of data to add.
	 */
	private synchronized native void sha_transform(byte data[], int offset, int length);

	/**
	 * Fills the buffer with the digested output and resets the digest.
	 * @param output   The buffer where the digest is to be stored.
	 */
	private synchronized native void sha_finish( byte output[] );
	private synchronized native static int sha_test();






	public static final void byte2int(int dst[], int dst_off, byte src[], int src_off, int len)
	{
		while (len-- > 0)
		{
			// Big endian
			dst[dst_off++] = (((int)src[src_off++]) << 24) | ((((int)src[src_off++]) & 0xFF) << 16)
					| ((((int)src[src_off++]) & 0xFF) << 8) | (((int)src[src_off++]) & 0xFF);
		}
	}




    public static final void
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
	self_test( PrintStream out, String argv[] )
	throws Exception
	{
	 	test(out, "Anyone got any SHA-1 test data?", "f96cea198ad1dd5617ac084a3d92c6107708c0ef" );
	}

	private static void
	test( PrintStream out, String msg, String hashStr )
	{
		hashStr = hashStr.toUpperCase();
		SHA sha = new SHA();
		sha.add( msg );
		String x = toString( sha.digest() );
		out.println( "Message " + msg );
		out.println( "calc hash:" + x );
		out.println( "real hash:" + hashStr );
		if ( hashStr.equals( x ) )
			out.println( "Good" );
		else
			out.println( "************* SHA FAILED **************" );
	}

	private static byte[]
	fromString( String inHex )
	{
		int len=inHex.length();
		int pos =0;
		byte buffer[] = new byte [( ( len + 1 ) / 2 )];
		if ( ( len % 2 ) == 1 )
		{
			buffer[0]=(byte)asciiToHex(inHex.charAt(0));
			pos=1;
			len--;
		}

		for(int ptr = pos; len > 0; len -= 2 )
			buffer[pos++] = (byte)( 
					( asciiToHex( inHex.charAt( ptr++ ) ) << 4 ) |
					( asciiToHex( inHex.charAt( ptr++ ) ) )
					);
		return buffer;
	}

	private static final String
	toString( byte buffer[] )
	{
		StringBuffer returnBuffer = new StringBuffer();
		for ( int pos = 0, len = buffer.length; pos < len; pos++ )
			returnBuffer.append( hexToAscii( ( buffer[pos] >>> 4 ) & 0x0F ) )
						.append( hexToAscii( buffer[pos] & 0x0F ) );
		return returnBuffer.toString();
	}

	private static final int
	asciiToHex(char c)
	{
		if ( ( c >= 'a' ) && ( c <= 'f' ) )
			return ( c - 'a' + 10 );
		if ( ( c >= 'A' ) && ( c <= 'F' ) )
			return ( c - 'A' + 10 );
		if ( ( c >= '0' ) && ( c <= '9' ) )
			return ( c - '0' );
		throw new Error("ascii to hex failed");
	}

	private static char
	hexToAscii(int h)
	{
		if ( ( h >= 10 ) && ( h <= 15 ) )
			return (char)( 'A' + ( h - 10 ) );
		if ( ( h >= 0 ) && ( h <= 9 ) )
			return (char)( '0' + h );
		throw new Error("hex to ascii failed");
	}
}
