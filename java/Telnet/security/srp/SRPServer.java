package security.srp;

import java.io.DataInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import security.math.BigInteger;
import security.crypt.Util;
import security.crypt.SHA;

public class SRPServer {
  private BigInteger n;
  private BigInteger g;
  private BigInteger v;
  private byte[] s;
  private BigInteger b;
  private BigInteger B;
  private byte[] key;
  private SHA hash, ckhash;

  private static int B_LEN = 8;		// 64 bits for 'b'

  public SRPServer(String username, PasswordFile pw)
       throws NoSuchUserException {
    String[] result = pw.lookup(username);
    if(result == null)
      throw new NoSuchUserException();
    v = new BigInteger(Util.fromb64(result[0]));
    s = Util.fromb64(result[1]);
    byte[] nb = Util.fromb64(result[3]);
    byte[] gb = Util.fromb64(result[4]);
    g = new BigInteger(gb);
    n = new BigInteger(nb);
    hash = new SHA();

    ckhash = new SHA();
    ckhash.add(Util.xor(SHA.hash(nb), SHA.hash(gb), 20));
    ckhash.add(SHA.hash(username));
    ckhash.add(s);
    key = null;
  }

  public byte[] modulus() { return n.toByteArray(); }
  public byte[] generator() { return g.toByteArray(); }
  public byte[] salt() { return s; }
  public byte[] exponential() { return B.toByteArray(); }
  public byte[] sessionKey() { return key; }

  public byte[] generateExponential() {
    do {
      b = new BigInteger(Util.RNG.nextBytes(B_LEN));
    } while(b.cmp(BigInteger.one) <= 0);
    B = new BigInteger().add(v, g.modExp(b, n));
    if(B.cmp(n) >= 0)
      B.sub(B, n);
    return B.toByteArray();
  }

  public byte[] getSessionKey(byte[] cliexp) {
    ckhash.add(cliexp);
    ckhash.add(B.toByteArray());
    hash.add(cliexp);
    byte[] uhash = SHA.hash(B.toByteArray());
    byte[] fourbytes = {uhash[0], uhash[1], uhash[2], uhash[3]};
    BigInteger S = new BigInteger();
    BigInteger.modMul(S, new BigInteger(cliexp),
		      new BigInteger(v).modExp(new BigInteger(fourbytes), n),
		      n);
    key = Util.sessionKeyHash(S.modExp(b, n).toByteArray());
    ckhash.add(key);
    return key;
  }

  public byte[] response() {
    return hash.digest();
  }

  public boolean verify(byte[] resp) {
    if(Util.matches(resp, ckhash.digest())) {
      hash.add(resp);
      hash.add(key);
      return true;
    }
    else
      return false;
  }

  public static void main(String[] args) {
    SRPServer serv = null;
    DataInputStream stdin = new DataInputStream(System.in);
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

    System.out.print("Enter A (from client): ");
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
