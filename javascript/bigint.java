public class bigint extends java.applet.Applet {
    public java.util.Random newRandom() {
	return new java.util.Random();
    }

    public java.security.SecureRandom newSecureRandom() {
	return new java.security.SecureRandom();
    }

    public java.math.BigInteger newBigInteger(String value, int radix) {
	return new java.math.BigInteger(value, radix);
    }

    public java.math.BigInteger newBigIntegerRandom(int bitlen, java.util.Random rng) {
	return new java.math.BigInteger(bitlen, rng);
    }

    /* Opera toString() workaround */
    public char[] toCharArray(java.math.BigInteger x, int radix) {
	return x.toString(radix).toCharArray();
    }
}
