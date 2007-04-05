package security.srp;

import java.io.DataInputStream;
import java.io.IOException;
import security.math.BigInteger;
import security.crypt.SHA;
import security.crypt.Util;

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
  private SHA hash, ckhash;

  private static int A_LEN = 8;		// 64 bits for 'a'

  public SRPClient(String username, byte[] modulus, byte[] generator,
		   byte[] salt) {
    user = username;
    n = new BigInteger(modulus);
    g = new BigInteger(generator);
    s = salt;
    key = null;
    hash = new SHA();
    hash.add(Util.xor(SHA.hash(modulus), SHA.hash(generator), 20));
    hash.add(SHA.hash(username));
    hash.add(salt);
    ckhash = new SHA();
  }

  public byte[] modulus() { return n.toByteArray(); }
  public byte[] generator() { return g.toByteArray(); }
  public byte[] salt() { return s; }
  public byte[] exponential() { return A.toByteArray(); }
  public byte[] sessionKey() {  return key; }

  public byte[] generateExponential() {
    do {
      a = new BigInteger(Util.RNG.nextBytes(A_LEN));
    } while(a.cmp(BigInteger.one) <= 0);
    A = new BigInteger(g).modExp(a, n);
    byte[] out = A.toByteArray();
    hash.add(out);
    ckhash.add(out);
    return out;
  }

  public void inputPassword(String pass) {
    SHA ctxt = new SHA();
    ctxt.add(s);
    ctxt.add(Util.userHash(user, pass));
    x = new BigInteger(ctxt.digest());
    v = new BigInteger(g).modExp(x, n);
  }

  public byte[] getSessionKey(byte[] srvexp) {
    hash.add(srvexp);
    byte[] uhash = SHA.hash(srvexp);
    byte[] fourbytes = {uhash[0], uhash[1], uhash[2], uhash[3]};
    BigInteger sum =
      new BigInteger().mul(new BigInteger(fourbytes), x);
    BigInteger base = new BigInteger(srvexp);
    if(base.cmp(v) < 0)
      base.add(base, n);
    base.sub(base, v);
    BigInteger S = base.modExp(new BigInteger().add(sum, a), n);
    key = Util.sessionKeyHash(S.toByteArray());
    hash.add(key);
    return key;
  }

  public byte[] response() {
    byte[] resp = hash.digest();
    ckhash.add(resp);
    ckhash.add(key);
    return resp;
  }

  public boolean verify(byte[] resp) {
    return Util.matches(resp, ckhash.digest());
  }

  public static void main(String[] args) {
    SRPClient cli = null;
    DataInputStream stdin = new DataInputStream(System.in);
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

      System.out.print("Enter B (from server): ");
      System.out.flush();

      str = stdin.readLine();

      String password =
	new PasswordEntryBox("Enter Password", "Please enter SRP password").
	getAnswer();
      if(password == null)
	System.exit(1);

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
