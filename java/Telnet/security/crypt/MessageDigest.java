/*
 * Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 *
 * This library and applications are FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the conditions within the COPYRIGHT file are adhered to.
 *
 */
 
package security.crypt;

/**
 * This is the abstract base class for all message digests.
 * <p>Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 *
 * @see java.crypt.MD5
 * @see java.crypt.SHA
 */
public abstract class MessageDigest
{
	private byte buf[];
	private int buf_off = 0;
	private long bitcount = 0;

	/**
	 * Both protected and abstract, so this class must be derived
	 * from in order to be useful.
	 */
	protected MessageDigest()
	{
		buf = new byte[data_length()];
	}

	/**
	 * Return the number of bits added to the digest so far
	 */
	public final long bitcount() { return bitcount; }

	public final byte[] buf() { return buf; }
	public final int buf_off() { return buf_off; }

	/**
	 * Return the hash length in bytes
	 */
	public int length() { return hash_length(); }



	/**
	 * Return the hash length in bytes
	 */
	public abstract int hash_length();

	/**
	/**
	 * Return the length (in bytes) of the block that
	 * this hash function operates on.
	 */
	public abstract int data_length();

	/**
	 * Return the message digest name
	 * @return   The name of the message digest.
	 */
    public abstract String name();


	/**
	 * Initialise (reset) the message digest.
	 */
	public final void reset()
	{
		bitcount = 0;
		buf_off = 0;
		md_reset();
	}
		
	/**
	 * Reset the message digest
	 */
	protected abstract void md_reset();
		
	/**
	 * Perform a transformation
	 */
	protected abstract void md_transform();
		
	/**
	 * Perform the final transformation
	 */
	protected abstract byte[] md_digest();
		
	/**
	 * Obtain the digest<p>
	 * <p>N.B. this resets the digest.
	 * @return    the digest of all the data added to the message digest.
	 */
	public final byte[] digest()
	{
		byte r[] = md_digest();
		reset();
		return r;
	}
	
	/**
	 * Obtain the digest as a Hash object<p>
	 * <p>N.B. this resets the digest.
	 * @return    the Hash of all the data added to the message digest.
	 */
	public abstract MessageHash digestAsHash();

	/**
	 * Add the low bytes of a string to the digest (ie. treat the string as ASCII).
	 * @param message    The string to add.
	 * @param offset     The start of the data string.
	 * @param length     The length of the data string.
	 */
	public final void add( String message, int offset, int length )
	{
		if ( message == null )
			throw new CryptoError( "Cannot hash a null string" );

		if  ( length < 0 )
			throw new CryptoError( "Negative length" );

		if ( offset < 0 )
			throw new CryptoError( "Negative offset" );

		if  ( ( length + offset ) > message.length() )
			throw new CryptoError( "Offset past end of data" );
		
		if ( length == 0 )
			return; // nothing to do so do nothing.
		
		byte data[] = new byte[length];
		
		message.getBytes( offset, offset + length, data, 0 );
		
		addToDigest( data, 0, length );
	}

	/**
	 * Add the low bytes of a string to the digest (ie. treat the string
	 * as ASCII ).
	 * @param message    The string to add.
	 */
	public final void add( String message )
	{
		if ( message == null )
			throw new CryptoError( "Cannot hash a null string" );

		int length = message.length();
		
		if ( length == 0 )
			return; // nothing to do so do nothing.
		
		byte data[] = new byte[ length ];
		
		message.getBytes( 0, length, data, 0 );
		
		addToDigest( data, 0, length );
	}

	/**
	 * Add a byte array to the digest
	 * @param data    The data to be added.
	 */
	public final void add( byte data[] )
	{
		addToDigest(data, 0, data.length);
	}

	/**
	 * Add a section of a byte array to the digest
	 * @param data    The data to add.
	 * @param offset     The start of the data to add.
	 * @param length     The length of the data to add.
	 */
	public final void add(byte data[], int offset, int length)
	{
		if ( data == null )
			throw new CryptoError( "Cannot hash a null array" );

		if ( length < 0 )
			throw new CryptoError( "Negative length" );

		if ( offset < 0 )
			throw new CryptoError( "Negative offset" );

		if ( ( length + offset ) > data.length )
			throw new CryptoError( "Offset past end of data" );

		if ( length == 0 ) 
			return; // do nothing.

		addToDigest( data, offset, length );
	}

	/**
	 * Add data to the message digest
	 * This method is protected to ensure that all parameters
     * are valid at this point - essential if the parameters
	 * are passed to native functions.
	 * @param data    The data to be added.
	 * @param off     The start of the data in the array.
	 * @param len     The amount of data to add.
	 */
	protected final void addToDigest(byte data[], int off, int len)
	{
		int datalen = data_length();

		bitcount += ((long)len << 3);

		while (len >= (datalen - buf_off))
		{
			System.arraycopy(data, off, buf, buf_off, datalen - buf_off);

			md_transform();

			len -= (datalen - buf_off);
			off += (datalen - buf_off);
			buf_off = 0;
		}

		if (len > 0) 
		{
			System.arraycopy(data, off, buf, buf_off, len);
			buf_off += len;
		}
	}
	
	/**
	 * A convenience function for hashing a string.<p>
	 * eg:
	 * <pre> byte key[] = MessageDigest.hash( passPhrase, new MD5() ); </pre>
	 * @param message  The string to hash.
	 * @param md       An instance of a message digest.
	 * @see MD5#hash(java.lang.String)
	 * @see SHA#hash(java.lang.String)
	 */
	public static final byte[] hash( String message, MessageDigest md )
	{
		md.add( message );
		return md.digest();
	}

	/**
	 * A convenience function for hashing a byte array.<p>
	 * eg:
	 * <pre> byte key[] = MessageDigest.hash( bytearray, new MD5() ); </pre>
	 * @param message  The byte array to hash.
	 * @param md       An instance of a message digest.
	 * @see MD5#hash(byte[])
	 * @see SHA#hash(byte[])
	 */
	public static final byte[] hash( byte message[], MessageDigest md )
	{
		md.add( message );
		return md.digest();
	}
}
