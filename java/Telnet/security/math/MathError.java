/*
 * Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 *
 * This library and applications are FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the conditions within the COPYRIGHT file are adhered to.
 *
 */

package security.math;

/**
 * Maths Internal error class
 *
 * <p>Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 * All rights reserved.
 */
public class MathError extends Error
{
	/**
	 * Creates an error, given a reason string.
	 * @param reason  A string describing the reason for the error.
	 */
	MathError(String reason)
	{
		super( "Maths error : " + reason );
	}
}

