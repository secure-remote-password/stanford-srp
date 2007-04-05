package security.srp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * The Server-side interface to the SRP protocol.  This accepts and
 * generates the protocol messages, computes the final session key,
 * and performs authentication verification.  The task of transporting
 * the messages themselves across the network is left to the
 * implementor.
 */
public class SRPServer {
  private BigInteger n;
  private BigInteger g;
  private BigInteger v;
  private byte[] s;
  private BigInteger b;
  private BigInteger B;
  private byte[] key;
  private MessageDigest hash, ckhash;

  private static int B_LEN = 64;	// 64 bits for 'b'

  /**
   * Creates a new SRP Server object from the username (possibly
   * received from the client) and the PasswordFile containing the
   * password database.
   * @param username The user's username.
   * @param pw The password database.
   */
  public SRPServer(String username, PasswordFile pw)
       throws NoSuchUserException {
    String[] result = pw.lookup(username);
    if(result == null)
      throw new NoSuchUserException();
    v = new BigInteger(1, Util.fromb64(result[0]));
    s = Util.fromb64(result[1]);
    byte[] nb = Util.fromb64(result[3]);
    byte[] gb = Util.fromb64(result[4]);
    g = new BigInteger(1, gb);
    n = new BigInteger(1, nb);
    hash = Util.newDigest();

    ckhash = Util.newDigest();
    ckhash.update(Util.xor(Util.newDigest().digest(nb),
			   Util.newDigest().digest(gb), 20));
    ckhash.update(Util.newDigest().digest(username.getBytes()));
    ckhash.update(s);
    key = null;
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
   * @returns The exponential residue (parameter B) to be sent to the
   *          client.
   */
  public byte[] exponential() {
    if(B == null) {
      BigInteger one = BigInteger.valueOf(1);
      do {
	b = new BigInteger(B_LEN, Util.RNG);
      } while(b.compareTo(one) <= 0);
      B = v.add(g.modPow(b, n));
      if(B.compareTo(n) >= 0)
	B = B.subtract(n);
    }
    return Util.trim(B.toByteArray());
  }

  /**
   * Deprecated.  Use exponential() instead.
   */
  public byte[] generateExponential() { return exponential(); }

  /**
   * @param cliexp The client's exponential (parameter A).
   * @returns The secret shared session key between client and server
   */
  public byte[] sessionKey(byte[] cliexp) {
    byte[] B_arr = Util.trim(B.toByteArray());
    ckhash.update(cliexp);
    ckhash.update(B_arr);
    hash.update(cliexp);
    byte[] uhash = Util.newDigest().digest(B_arr);
    byte[] fourbytes = {uhash[0], uhash[1], uhash[2], uhash[3]};

    BigInteger S = new BigInteger(1, cliexp).
      multiply(v.modPow(new BigInteger(1, fourbytes), n)).mod(n);
    key = Util.sessionKeyHash(Util.trim(S.modPow(b, n).toByteArray()));
    ckhash.update(key);
    return key;
  }

  /**
   * @returns The secret shared session key between client and server
   */
  public byte[] sessionKey() { return key; }

  /**
   * Deprecated.  Use sessionKey() instead.
   */
  public byte[] getSessionKey(byte[] cliexp) { return sessionKey(cliexp); }

  /**
   * @returns The response to the client's challenge.
   */
  public byte[] response() {
    return hash.digest();
  }

  /**
   * @param resp The client's response to the server's challenge
   * @returns True if and only if the client's response was correct.
   */
  public boolean verify(byte[] resp) {
    if(Util.matches(resp, ckhash.digest())) {
      hash.update(resp);
      hash.update(key);
      return true;
    }
    else
      return false;
  }

  public static void main(String[] args) {
    SRPServer serv = null;
    BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
    String u = null;

    try {
      PasswordFile pf;
      if(args.length < 1)
	pf = new PasswordFile();
      else
	pf = new PasswordFile(args[0]);
      System.out.print("Enter username: ");
      System.out.flush();
      u = stdin.readLine();
      serv = new SRPServer(u, pf);
    }
    catch(FileNotFoundException e) {
      System.err.println("Password file not found");
      System.exit(1);
    }
    catch(NoSuchUserException e) {
      System.err.println("User " + u + " unknown");
      System.exit(1);
    }
    catch(Exception e) {
      e.printStackTrace();
      System.exit(1);
    }

    System.out.println("n (to client): " + Util.tob64(serv.modulus()));
    System.out.println("g (to client): " + Util.tob64(serv.generator()));
    System.out.println("salt (to client): " + Util.tob64(serv.salt()));

    byte[] ex = serv.generateExponential();

    System.out.print("Enter B (from client): ");
    System.out.flush();
    try {
      String astr = stdin.readLine();

      // Must get A first before revealing B
      System.out.println("B (to client): " + Util.tob64(ex));

      byte[] key = serv.getSessionKey(Util.fromb64(astr));
      System.out.println("Session key: " + Util.tohex(key));

      System.out.print("Enter response (from client): ");
      System.out.flush();
      String resp = stdin.readLine();

      if(serv.verify(Util.fromhex(resp)))
	System.out.println("Authentication successful.");
      else
	System.out.println("Authentication failed.");
    }
    catch(IOException e) {
      e.printStackTrace();
    }
  }
}
