package security.srp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * The Client-side interface to the SRP protocol.  This accepts and
 * generates the protocol messages, computes the final session key,
 * and performs authentication verification.  The task of transporting
 * the messages themselves across the network is left to the
 * implementor.
 */
public class SRPClient {
  private BigInteger n;
  private BigInteger g;
  private byte[] s;
  private BigInteger x;
  private BigInteger v;
  private BigInteger a;
  private BigInteger A;
  private String user;
  private byte[] key;
  private MessageDigest hash, ckhash;

  private static int A_LEN = 64;		// 64 bits for 'a'

  /**
   * Creates a new SRP Client object from the initial round of the
   * exchange.
   * @param username The user's username on the server host.
   * @param modulus The user's safe-prime modulus, received from
   *                the server.
   * @param generator The user's primitive generator, received from
   *                  the server.
   * @param salt The user's password salt, received from the server.
   */
  public SRPClient(String username, byte[] modulus, byte[] generator,
		   byte[] salt) {
    user = username;
    n = new BigInteger(1, modulus);
    g = new BigInteger(1, generator);
    s = salt;
    key = null;
    hash = Util.newDigest();
    hash.update(Util.xor(Util.newDigest().digest(modulus),
		      Util.newDigest().digest(generator), 20));
    hash.update(Util.newDigest().digest(username.getBytes()));
    hash.update(salt);
    ckhash = Util.newDigest();
  }

  /**
   * @returns The user's safe-prime modulus
   */
  public byte[] modulus() { return Util.trim(n.toByteArray()); }

  /**
   * @returns The user's primitive generator
   */
  public byte[] generator() { return Util.trim(g.toByteArray()); }

  /**
   * @returns The user's password salt
   */
  public byte[] salt() { return s; }

  /**
   * @returns The exponential residue (parameter A) to be sent to the
   *          server.
   */
  public byte[] exponential() {
    if(A == null) {
      BigInteger one = BigInteger.valueOf(1);
      do {
	a = new BigInteger(A_LEN, Util.RNG);
      } while(a.compareTo(one) <= 0);
      A = g.modPow(a, n);
      byte[] out = Util.trim(A.toByteArray());
      hash.update(out);
      ckhash.update(out);
      return out;
    }
    else
      return Util.trim(A.toByteArray());
  }

  /**
   * Deprecated.  Use exponential() instead.
   */
  public byte[] generateExponential() { return exponential(); }

  /**
   * Incorporates the user's password into the session key computation.
   * @param pass The user's password or passphrase.
   */
  public void inputPassword(String pass) {
    MessageDigest ctxt = Util.newDigest();
    ctxt.update(s);
    ctxt.update(Util.userHash(user, pass));
    x = new BigInteger(1, ctxt.digest());
    v = g.modPow(x, n);
  }

  /**
   * @returns The secret shared session key between client and server
   * @param srvexp The server's exponential (parameter B).
   */
  public byte[] sessionKey(byte[] srvexp) {
    hash.update(srvexp);
    byte[] uhash = Util.newDigest().digest(srvexp);
    byte[] fourbytes = {uhash[0], uhash[1], uhash[2], uhash[3]};
    BigInteger sum = x.multiply(new BigInteger(1, fourbytes));
    BigInteger base = new BigInteger(1, srvexp);
    if(base.compareTo(v) < 0)
      base = base.add(n);
    base = base.subtract(v);
    BigInteger S = base.modPow(sum.add(a), n);
    key = Util.sessionKeyHash(Util.trim(S.toByteArray()));
    hash.update(key);
    return key;
  }

  /**
   * @returns The secret shared session key between client and server
   */
  public byte[] sessionKey() { return key; }

  /**
   * Deprecated.  Use sessionKey() instead.
   */
  public byte[] getSessionKey(byte[] srvexp) {
    return sessionKey(srvexp);
  }

  /**
   * @returns The response to the server's challenge.
   */
  public byte[] response() {
    byte[] resp = hash.digest();
    ckhash.update(resp);
    ckhash.update(key);
    return resp;
  }

  /**
   * @param resp The server's response to the client's challenge
   * @returns True if and only if the server's response was correct.
   */
  public boolean verify(byte[] resp) {
    return Util.matches(resp, ckhash.digest());
  }

  public static void main(String[] args) {
    SRPClient cli = null;
    BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
    String u = null;

    try {
      System.out.print("Enter username: ");
      System.out.flush();
      u = stdin.readLine();
      String str;
      System.out.print("Enter n (from server): ");
      System.out.flush();
      str = stdin.readLine();
      byte[] n = Util.fromb64(str);
      System.out.print("Enter g (from server): ");
      System.out.flush();
      str = stdin.readLine();
      byte[] g = Util.fromb64(str);
      System.out.print("Enter salt (from server): ");
      System.out.flush();
      str = stdin.readLine();
      byte[] salt = Util.fromb64(str);
      
      cli = new SRPClient(u, n, g, salt);

      byte[] ex = cli.generateExponential();
      System.out.println("A (to server): " + Util.tob64(ex));

      PasswordEntryBox peb = new PasswordEntryBox("Enter Password", "Please enter SRP password");
      String password = peb.getAnswer();

      if(password == null)
	System.exit(1);

      System.out.print("Enter B (from server): ");
      System.out.flush();

      str = stdin.readLine();

      cli.inputPassword(password);
      byte[] key = cli.getSessionKey(Util.fromb64(str));
      System.out.println("Session key: " + Util.tohex(key));

      System.out.println("Response (to server): " + Util.tohex(cli.response()));
    }
    catch(IOException e) {
      e.printStackTrace();
    }
    finally {
      System.exit(0);
    }
  }
}
