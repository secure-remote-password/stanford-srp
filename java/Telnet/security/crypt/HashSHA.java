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
 * This class represents the output of a SHA message digestor. 
 *
 * <p>Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 */
public final class HashSHA extends MessageHash
{
	/**
	 * Creates this from an SHA message digestor
	 * @param md An SHA MessageDigest.
	 */
	public HashSHA( SHA md )
	{
		super( md.digest() );
	}

	/**
	 * Creates this from a byte array that must be the the correct length
	 * @param hash A byte array which represents an SHA hash.
	 */
	public HashSHA( byte hash[] )
	{
		super( checkHash( hash ) );
	}

	/**
	 * Returns a big endian Hex string prefixed with "SHA:",
	 *	showing the value of the hash.
	 * @return a string reprosenting the hash.
	 */
	public String
	toString()
	{
		return "SHA:" + super.toString();
	}

	/**
	 * this checks the byte array is the correct size for the an SHA hash.
	 * @param hash A byte array which represents an SHA hash.
	 */
	//
	// Hang on! This shouldn't throw an exception!
	// The caller of this function (eg. HashSHA) should
	// throw the exception.
	//
	private static final byte[]
	checkHash( byte hash[] )
	{
		if ( hash.length != SHA.HASH_LENGTH )
			throw new RuntimeException( "Hash length incorrect " + hash.length );
		return hash;
	}
}
