/*
 * Authenticator.java
 * Author: Tom Wu
 *
 * The base class for Telnet authenticator modules.  Provides some
 * common services and hooks for implementations.
 */

package socket;

import java.io.OutputStream;
import java.io.IOException;

public abstract class Authenticator {

  // Authentication specifier bitmasks
  private final static byte AUTH_WHO_CLIENT = (byte) 0;
  private final static byte AUTH_WHO_SERVER = (byte) 1;
  private final static byte AUTH_WHO_MASK = (byte) 1;

  private final static byte AUTH_HOW_ONE_WAY = (byte) 0;
  private final static byte AUTH_HOW_MUTUAL = (byte) 2;
  private final static byte AUTH_HOW_MASK = (byte) 2;

  public final static boolean enabled = true;

  /**
   * Sets debugging level for authentication code.
   */
  protected static int debug = 3;

  /**
   * The remote side of the telnet connection.
   */
  private static OutputStream telnet;

  /**
   * Buffer and index pointer for data recorded from a SEND command.
   */
  private static byte[] sendbuf;
  private static int sendidx;

  /**
   * List of currently-supported authenticator types.
   */
  private static Authenticator[] authenticators =
    { new SRPAuthenticator(AUTH_WHO_CLIENT | AUTH_HOW_ONE_WAY) };

  /**
   * Set the OutputStream used to send option replies.
   */
  public static void setOutputStream(OutputStream out) { telnet = out; }

  /**
   * Given a type (e.g. SRP) and a way (e.g. CLIENT|ONE_WAY), find the
   * matching authenticator from the list of supported ones.  Returns
   * null if the specified authenticator is not supported.
   */
  public static Authenticator getAuthenticator(int type, int way) {
    for(int i = 0; i < authenticators.length; ++i)
      if(authenticators[i].getType() == type &&
	 authenticators[i].way == way)
	return authenticators[i];
    if(debug > 0)
      System.out.println("getAuthenticator: unable to find authenticator for ("
			 + type + ", " + way + ")");
    return null;
  }

  protected static void sendname(String name) throws IOException {
    if(debug > 1) {
      System.out.println("SENT IAC SB AUTHENTICATION NAME \"" + name + "\"");
    }
    telnet.write(TelnetIO.IACSB);
    telnet.write(TelnetIO.TELOPT_AUTHENTICATION);
    telnet.write(TelnetIO.TELQUAL_NAME);
    byte[] nbuf = new byte[name.length()];
    name.getBytes(0, name.length(), nbuf, 0);
    telnet.write(nbuf);
    telnet.write(TelnetIO.IACSE);
  }

  public static void sendNext() throws IOException{
    while(sendidx + 1 < sendbuf.length) {
      Authenticator auth =
	getAuthenticator(sendbuf[sendidx], sendbuf[sendidx + 1]);
      sendidx += 2;
      if(auth != null && auth.send())
	return;
    }

    if(debug > 1)
      System.out.println("SENT IAC SB AUTHENTICATION IS NULL 0");
    telnet.write(TelnetIO.IACSB);
    telnet.write(TelnetIO.TELOPT_AUTHENTICATION);
    telnet.write(TelnetIO.TELQUAL_IS);
    telnet.write(0);
    telnet.write(0);
    telnet.write(TelnetIO.IACSE);
    telnet.flush();

    if(debug > 0)
      System.out.println("Unable to authenticate securely; falling back to standard login.");
  }

  public static void dispatch(byte[] buf, int count) throws IOException {
    if(debug > 1)
      System.out.print("RCVD IAC SB AUTHENTICATION");

    if(buf[0] == TelnetIO.TELQUAL_SEND) {
      if(debug > 1) {
	System.out.print(" SEND");
	for(int j = 1; j < count; ++j)
	  System.out.print(" " + buf[j]);
	System.out.println();
      }
      sendbuf = new byte[count - 1];
      System.arraycopy(buf, 1, sendbuf, 0, count - 1);
      sendidx = 0;
      sendNext();
      return;
    }
    if(count < 4)
      return;
    Authenticator auth = getAuthenticator(buf[1], buf[2]);
    if(auth == null)
      return;
    byte[] authbuf = new byte[count - 4];
    System.arraycopy(buf, 4, authbuf, 0, count - 4);

    switch(buf[0]) {
    case TelnetIO.TELQUAL_IS:
      if(debug > 1) {
	System.out.println(" IS " + buf[1] + " " + buf[2] +
			   auth.printsub(buf[3], authbuf));
      }
      auth.is(buf[3], authbuf);
      break;
    case TelnetIO.TELQUAL_REPLY:
      if(debug > 1) {
	System.out.println(" REPLY " + buf[1] + " " + buf[2] +
			   auth.printsub(buf[3], authbuf));
      }
      auth.reply(buf[3], authbuf);
      break;
    }
  }

  // Instance logic

  protected byte way;

  public Authenticator(int mode) { way = (byte) mode; }

  protected void data(int type, byte[] buf) throws IOException {
    if(debug > 1) {
      System.out.println("SENT IAC SB AUTHENTICATION IS " + getType() + " " +
			 way + ((buf == null) ? "" : printsub(type, buf)));
    }

    telnet.write(TelnetIO.IACSB);
    telnet.write(TelnetIO.TELOPT_AUTHENTICATION);
    telnet.write(TelnetIO.TELQUAL_IS);		// Assume we're the client
    telnet.write(getType());
    telnet.write(way);
    telnet.write(type);
    if(buf != null)
      for(int i = 0; i < buf.length; ++i) {
	telnet.write(buf[i]);
	if(buf[i] == TelnetIO.IAC)
	  telnet.write(TelnetIO.IAC);
      }
    telnet.write(TelnetIO.IACSE);
    telnet.flush();
  }

  public abstract byte getType();
  public abstract boolean send() throws IOException;
  public abstract void is(int type, byte[] buf) throws IOException;
  public abstract void reply(int type, byte[] buf) throws IOException;
  public abstract String printsub(int type, byte[] buf);
}
