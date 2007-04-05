/*
 * Util.java
 * Author: Tom Wu
 *
 * Miscellaneous utilities for crypto routines.
 */

package security.crypt;

public class Util {
  public static final int HASH_LEN = 20;
  public static final char[] TABLE =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./"
      .toCharArray();
  public static final RandomBytes RNG = new RandomBytes();

  // These functions assume that the byte array has MSB at 0, LSB at end.
  // Reverse the byte array (not the String) if this is not the case.
  // All base64 strings are in natural order, least significant digit last.

  public static String tob64(byte[] buffer) {
    boolean notleading = false;
    int len = buffer.length, pos = len % 3, c;
    byte b0 = 0, b1 = 0, b2 = 0;
    StringBuffer sb = new StringBuffer();

    switch(pos) {
    case 1:
      b2 = buffer[0];
      break;
    case 2:
      b1 = buffer[0];
      b2 = buffer[1];
      break;
    }
    do {
      c = (b0 & 0xfc) >>> 2;
      if(notleading || c != 0) {
	sb.append(TABLE[c]);
	notleading = true;
      }
      c = ((b0 & 3) << 4) | ((b1 & 0xf0) >>> 4);
      if(notleading || c != 0) {
	sb.append(TABLE[c]);
	notleading = true;
      }
      c = ((b1 & 0xf) << 2) | ((b2 & 0xc0) >>> 6);
      if(notleading || c != 0) {
	sb.append(TABLE[c]);
	notleading = true;
      }
      c = b2 & 0x3f;
      if(notleading || c != 0) {
	sb.append(TABLE[c]);
	notleading = true;
      }
      if(pos >= len)
	break;
      else
	try {
	  b0 = buffer[pos++];
	  b1 = buffer[pos++];
	  b2 = buffer[pos++];
	} catch(ArrayIndexOutOfBoundsException e) { break; }
    } while(true);

    if(notleading)
      return sb.toString();
    else
      return "0";
  }

  public static byte[] fromb64(String str) throws NumberFormatException {
    int len = str.length();
    if(len == 0)
      throw new NumberFormatException("Empty Base64 string");

    byte[] a = new byte[len + 1];
    char c;
    int i, j;

    for(i = 0; i < len; ++i) {
      c = str.charAt(i);
      try {
	for(j = 0; c != TABLE[j]; ++j)
	  ;
      } catch(Exception e) {
	throw new NumberFormatException("Illegal Base64 character");
      }
      a[i] = (byte) j;
    }

    i = len - 1;
    j = len;
    try {
      while(true) {
	a[j] = a[i];
	if(--i < 0)
	  break;
	a[j] |= (a[i] & 3) << 6;
	--j;
	a[j] = (byte) ((a[i] & 0x3c) >>> 2);
	if(--i < 0)
	  break;
	a[j] |= (a[i] & 0xf) << 4;
	--j;
	a[j] = (byte) ((a[i] & 0x30) >>> 4);
	if(--i < 0)
	  break;
	a[j] |= (a[i] << 2);

	// Nasty, evil bug in Microsloth's Java interpreter under
	// Netscape:  The following three lines of code are supposed
	// to be equivalent, but under the Windows NT VM (Netscape3.0)
	// using either of the two commented statements would cause
	// the zero to be placed in a[j] *before* decrementing j.
	// Weeeeird.
	a[j-1] = 0; --j;
	// a[--j] = 0;
	// --j; a[j] = 0;

	if(--i < 0)
	  break;
      }
    } catch(Exception e) {}

    try {
      while(a[j] == 0)
	++j;
    } catch(Exception e) {
      return new byte[1];
    }
    
    byte[] result = new byte[len - j + 1];
    System.arraycopy(a, j, result, 0, len - j + 1);
    //for(i = 0; i < len - j + 1; ++i)
    //      result[i] = a[i + j];
    return result;
  }

  private static final int asciiToHex(char c)  {
    if ( ( c >= 'a' ) && ( c <= 'f' ) )
      return ( c - 'a' + 10 );
    if ( ( c >= 'A' ) && ( c <= 'F' ) )
      return ( c - 'A' + 10 );
    if ( ( c >= '0' ) && ( c <= '9' ) )
      return ( c - '0' );
    return 0;
  }

  private static final char hexToAscii(int h) {
    if ( ( h >= 10 ) && ( h <= 15 ) )
      return (char)( 'A' + ( h - 10 ) );
    if ( ( h >= 0 ) && ( h <= 9 ) )
      return (char)( '0' + h );
    return '0';
  }

  public static String tohex(byte[] buffer) {
    StringBuffer result = new StringBuffer();

    for(int i = 0; i < buffer.length; ++i)
      result.append(hexToAscii((buffer[i] >>> 4) & 0xF))
	    .append(hexToAscii(buffer[i] & 0x0F));
    return result.toString();
  }

  public static byte[] fromhex(String str) {
    int len = str.length(), pos = (len + 1) / 2;
    byte[] buffer = new byte[pos];

    for(--len, --pos; len > 0; len -= 2, --pos)
      buffer[pos] = (byte) (asciiToHex(str.charAt(len - 1)) << 4 |
			    asciiToHex(str.charAt(len)));
    if(len > 0)
      buffer[0] = (byte) asciiToHex(str.charAt(0));
    return buffer;
  }

  public static byte[] userHash(String user, String pass) {
    return SHA.hash(user + ":" + pass);
  }

  // Perform an interleaved even-odd hash on the byte string
  public static byte[] sessionKeyHash(byte[] number) {
    int i, offset;

    for(offset = 0; offset < number.length && number[offset] == 0; ++offset)
      ;

    byte[] key = new byte[2 * HASH_LEN];
    byte[] hout;

    int klen = (number.length - offset) / 2;
    byte[] hbuf = new byte[klen];

    for(i = 0; i < klen; ++i)
      hbuf[i] = number[number.length - 2 * i - 1];
    hout = SHA.hash(hbuf);
    for(i = 0; i < HASH_LEN; ++i)
      key[2 * i] = hout[i];

    for(i = 0; i < klen; ++i)
      hbuf[i] = number[number.length - 2 * i - 2];
    hout = SHA.hash(hbuf);
    for(i = 0; i < HASH_LEN; ++i)
      key[2 * i + 1] = hout[i];

    return key;
  }

  public static boolean matches(byte[] b1, byte[] b2) {
    int i = b1.length;
    if(i == b2.length) {
      while(--i >= 0)
	if(b1[i] != b2[i])
	  return false;
      return true;
    }
    else
      return false;
  }

  public static byte[] xor(byte[] b1, byte[] b2, int length) {
    byte[] result = new byte[length];
    for(int i = 0; i < length; ++i)
      result[i] = (byte) (b1[i] ^ b2[i]);
    return result;
  }
}
