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
 * this class reprosents the output from a message digestor in a form
 * where the type and be asertained.
 *
 * <p>Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 */
public class MessageHash
{
	private byte hash[];
	
	/**
	 * You can not create an instance of this object
	 * @see java.crypt.HashSHA
	 * @see java.crypt.HashMD5
	 */
	protected MessageHash( byte hash0[] )
	{
		hash = new byte[hash0.length];
		System.arraycopy( hash0, 0, hash, 0, hash0.length );
	}
	
	/**
	 * @return the hash as a new byte array.
	 */
	public final byte[]
	toByteArray()
	{
		byte buf[] = new byte[hash.length];
		System.arraycopy( hash, 0, buf, 0, hash.length );
		return buf;
	}
	
	/**
	 * @return the hash length.
	 */
	public final int
	length()
	{
		return hash.length;
	}
	
	public int
	hashCode()
	{
		switch( hash.length )
		{
		case 0:
			return 0;
		case 1:
			return hash[0];
		case 2:
			return hash[0] ^ ( hash[1] << 8 );
		case 3:
			return hash[0] ^ ( hash[1] << 8 ) ^ ( hash[2] << 16 );
		default:
			return hash[0] ^ ( hash[1] << 8 ) ^ ( hash[2] << 16 ) ^ ( hash[3] << 24 );
		}
	}

	public boolean
	equals( Object obj )
	{
		if ( obj instanceof MessageHash )
			return equalTo( ( (MessageHash)obj ).hash );
		return false;
	}

	protected final boolean
	equalTo( byte buffer[] )
	{
		byte hash[] = this.hash;
		int len;
		if ( buffer.length == ( len = hash.length ) )
		{
			while ( --len >= 0 )
				if ( buffer[len] != hash[len] )
					return false;
			return true;
		}
		return false;
	}
	
	/**
	 * Returns a big endian Hex string showing the value of the hash.
	 * @return a string reprosenting the hash.
	 */
	public String
	toString()
	{
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < hash.length; i++ )
			sb.append( Integer.toString( (  hash[i] >>> 4 ) & 0x0F,16 ) ).append( Integer.toString( hash[i] & 0x0F,16 ) );
		return sb.toString();
	}
}
