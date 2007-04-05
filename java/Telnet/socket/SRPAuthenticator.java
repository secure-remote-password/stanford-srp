/*
 * SRPAuthenticator.java
 * Author: Tom Wu
 *
 * An authenticator that negotiates SRP-style authentication.
 */

package socket;

import java.io.IOException;
import security.srp.SRPClient;
import security.crypt.Util;

public class SRPAuthenticator extends Authenticator {
  private final static byte AUTHTYPE_SRP = (byte) 5;

  private final static byte SRP_AUTH = (byte) 0;
  private final static byte SRP_REJECT = (byte) 1;
  private final static byte SRP_ACCEPT = (byte) 2;
  private final static byte SRP_CHALLENGE = (byte) 3;
  private final static byte SRP_RESPONSE = (byte) 4;
  private final static byte SRP_EXP = (byte) 8;
  private final static byte SRP_PARAMS = (byte) 9;

  private static String username = null;
  private LoginBox box = null;
  private SRPClient client = null;
  private boolean waitresponse = false;

  private static int decodeLength(byte[] buf, int offset) {
    try {
      return ((buf[offset] & 0xff) << 8) | (buf[offset + 1] & 0xff);
    } catch(ArrayIndexOutOfBoundsException e) { return 0; }
  }

  public SRPAuthenticator(int way) { super(way); }

  public byte getType() { return AUTHTYPE_SRP; }

  public boolean send() throws IOException {
    System.out.println("SRP: Attempting authentication...");
    box = new LoginBox("SRP Login", "Enter SRP Username");
    username = box.getUsername();
    if(username == null)
      return false;
    sendname(username);
    data(SRP_AUTH, null);
    waitresponse = false;
    return true;
  }

  // Server side not implemented
  public void is(int type, byte[] buf) throws IOException {}

  public void reply(int type, byte[] buf) throws IOException {
    String message;
    switch(type) {
    case SRP_REJECT:
      if(buf.length > 0)
	message = "SRP: authentication refused (" + new String(buf, 0) + ")";
      else
	message = "SRP: authentication refused";
      if(box == null)
	System.out.println(message);
      else
	new ErrorDialog(box, "Login Failed", message).waitForUser();
      box.destroy();
      client = null;
      Authenticator.sendNext();
      break;
    case SRP_ACCEPT:
      if(!waitresponse) {
	if(box == null)
	  System.out.println("SRP: protocol error");
	else
	  box.showError("Protocol error");
	break;
      }
      if(client.verify(buf))
	System.out.println("SRP: authentication successful");
      else
	System.out.println("Warning: SRP server authentication failed!");
      waitresponse = false;
      box.destroy();
      break;
    case SRP_PARAMS:
      if(username == null) {
	System.out.println("SRP: no username available");
	break;
      }
      int marker = 0;
      int len = decodeLength(buf, marker);
      marker += 2;
      if(len <= 0 || marker + len > buf.length) {
	System.out.println("SRP: invalid length " + len);
	break;
      }
      byte[] modbuf = new byte[len];
      System.arraycopy(buf, marker, modbuf, 0, len);
      marker += len;

      len = decodeLength(buf, marker);
      marker += 2;
      if(len <= 0 || marker + len > buf.length) {
	System.out.println("SRP: invalid length " + len);
	break;
      }
      byte[] genbuf = new byte[len];
      System.arraycopy(buf, marker, genbuf, 0, len);
      marker += len;

      len = decodeLength(buf, marker);
      marker += 2;
      if(len <= 0 || marker + len > buf.length) {
	System.out.println("SRP: invalid length " + len);
	break;
      }
      byte[] saltbuf = new byte[len];
      System.arraycopy(buf, marker, saltbuf, 0, len);
      marker += len;

      client = new SRPClient(username, modbuf, genbuf, saltbuf);
      data(SRP_EXP, client.generateExponential());
      break;
    case SRP_CHALLENGE:
      if(client == null) {
	System.out.println("SRP: protocol error");
	break;
      }
      String password = box.getPassword();
      if(password == null) {
	box.destroy();
	client = null;
	Authenticator.sendNext();
	break;
      }
      box.showMessage("Generating session key...");
      client.inputPassword(password);
      client.getSessionKey(buf);
 
      data(SRP_RESPONSE, client.response());
      waitresponse = true;

      break;
    }
  }

  public String printsub(int type, byte[] buf) {
    String s;
    switch(type) {
    case SRP_REJECT:
      return " REJECT \"" + new String(buf, 0) + "\"";
    case SRP_ACCEPT:
      s = "ACCEPT";
      break;
    case SRP_AUTH:
      s = "AUTH";
      break;
    case SRP_CHALLENGE:
      s = "CHALLENGE";
      break;
    case SRP_RESPONSE:
      s = "RESPONSE";
      break;
    case SRP_PARAMS:
      s = "PARAMS";
      break;
    case SRP_EXP:
      s = "EXP";
      break;
    default:
      return null;
    }
    StringBuffer b = new StringBuffer(" " + s);
    for(int i = 0; i < buf.length; ++i) {
      b.append(' ');
      b.append(buf[i] & 0xff);
    }
    return b.toString();
  }
}
