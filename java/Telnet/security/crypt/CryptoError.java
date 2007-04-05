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
 * This class is for any unexpected error in the native crypto library.
 * <p>Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 */
public class CryptoError extends Error
{
	// Should never happen
	private CryptoError()
	{
		super("I thought this error was impossible to create!");
	}
	
	/**
	 * Only classes in this package can create a crypto error.
	 * @param reason   the reason the error was thrown.
	 */
	CryptoError(String reason)
	{
		super(reason);
	}	
}
