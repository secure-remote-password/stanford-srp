/*
 * PasswordFile.java
 * Author: Tom Wu
 *
 * Manages the paired password/configuration files for the Desktop
 * authentication system.
 */

package security.srp;

import java.io.*;
import java.util.*;

public class PasswordFile extends Object {
  private Hashtable htp;
  private Hashtable htc;
  private File pf;
  private File cf;
  private String[] last_params;
  private long pmod;
  private long cmod;

  private static String DEFAULT_PASSWD = "/etc/tpasswd";

  public PasswordFile(File pwFile)
       throws FileNotFoundException, IOException {
    this(pwFile.getAbsolutePath());
  }

  public PasswordFile(String fileName)
       throws FileNotFoundException, IOException {
    pf = new File(fileName);
    cf = new File(fileName + ".conf");
    update();
  }

  public PasswordFile(String pwName, String confName)
       throws FileNotFoundException, IOException {
    pf = new File(pwName);
    cf = new File(confName);
    update();
  }

  public PasswordFile() throws FileNotFoundException, IOException {
    this(DEFAULT_PASSWD);
  }

  protected synchronized void update()
       throws FileNotFoundException, IOException {
    cmod = cf.lastModified();
    readConf(new FileInputStream(cf));
    pmod = pf.lastModified();
    readPasswd(new FileInputStream(pf));
  }

  protected void checkCurrent() {
    if(cf.lastModified() > cmod || pf.lastModified() > pmod) {
      System.out.println("Files touched; re-reading...");
      try { update(); } catch(IOException e) {}
    }
  }

  protected synchronized void readConf(InputStream in)
       throws FileNotFoundException, IOException {
    DataInputStream din = new DataInputStream(in);
    String line, N, g, idx, lastidx = null;
    String[] params = null;

    htc = new Hashtable();
    while((line = din.readLine()) != null) {
      StringTokenizer st = new StringTokenizer(line, ":");
      try {
	idx = st.nextToken();
	N = st.nextToken();
	g = st.nextToken();
      } catch(NoSuchElementException e) { continue; }
      lastidx = idx;
      params = new String[2];
      params[0] = N;
      params[1] = g;
      htc.put(idx, params);
    }
    if(params != null) {
      last_params = new String[3];
      last_params[0] = lastidx;
      last_params[1] = params[0];
      last_params[2] = params[1];
    }
    else
      last_params = null;
  }

  public String[] getCurrentParams() { return last_params; }

  protected synchronized void readPasswd(InputStream in)
       throws FileNotFoundException, IOException {
    DataInputStream din = new DataInputStream(in);
    String line, userid, password, salt, basis;
    String[] fields, params;

    htp = new Hashtable();
    while((line = din.readLine()) != null) {
      StringTokenizer st = new StringTokenizer(line, ":");
      try {
	userid = st.nextToken();
	password = st.nextToken();
	salt = st.nextToken();
	basis = st.nextToken();
      } catch(NoSuchElementException e) { continue; }
      params = (String[]) htc.get(basis);
      fields = new String[5];
      fields[0] = password;
      fields[1] = salt;
      fields[2] = basis;
      fields[3] = params[0];
      fields[4] = params[1];
      htp.put(userid, fields);
    }
  }

  public void changePasswd(String user, String epasswd, String salt,
			   String[] params) {
    checkCurrent();
    String[] newfields = new String[5];
    newfields[0] = epasswd;
    newfields[1] = salt;
    newfields[2] = params[0];
    newfields[3] = params[1];
    newfields[4] = params[2];
    htp.put(user, newfields);
    try { savePasswd(); } catch(IOException e) {}
  }

  public void printPasswd() {
    this.writePasswd(System.out);
  }

  public synchronized void savePasswd() throws IOException {
    FileOutputStream fos = new FileOutputStream(pf);
    if(pf != null) {
      try {
	this.writePasswd(new PrintStream(fos));
      }
      finally { fos.close(); }
    }
    pmod = pf.lastModified();
  }

  public synchronized void writePasswd(PrintStream ws) {
    Enumeration keys = htp.keys();
    while(keys.hasMoreElements()) {
      String k = (String) keys.nextElement();
      String[] info = (String[]) htp.get(k);
      ws.println(k + ":" + info[0] + ":" + info[1] + ":" + info[2]);
    }
  }

  public String[] lookup(String s) {
    checkCurrent();
    if(htp.containsKey(s))
      return (String[]) htp.get(s);
    else
      return null;
  }

  public boolean contains(String s) {
    checkCurrent();
    return htp.containsKey(s);
  }

  public static void main(String[] args) {
    if(args.length < 2 || args.length > 3) {
      System.err.println("Usage: passwd username passwd-file [conf-file]");
      System.exit(1);
    }

    PasswordFile pwf;

    try {
      if(args.length == 2)
        pwf = new PasswordFile(args[1]);
      else
        pwf = new PasswordFile(args[1], args[2]);
    }
    catch(Exception e) {
      System.exit(1);
    }

    // To be completed...
  }

  /*
  public void map(StringMapper sm) {
    Enumeration keys = ht.keys();
    String k, mapout;
    while(keys.hasMoreElements()) {
      k = (String) keys.nextElement();
      mapout = sm.map((String) ht.get(k));
      if(mapout == null)
	ht.remove(k);
      else
	ht.put(k, mapout);
    }
  }

  public void merge(PasswordFile p2) {
    Enumeration keys2 = p2.ht.keys();
    String k2;
    while(keys2.hasMoreElements()) {
      k2 = (String) keys2.nextElement();
      ht.put(k2, p2.ht.get(k2));
    }
  }

  public void eliminateDuplicates(PasswordFile p2) {
    Enumeration keys2 = p2.ht.keys();
    String k2;
    while(keys2.hasMoreElements()) {
      k2 = (String) keys2.nextElement();
      if(ht.containsKey(k2))
	ht.remove(k2);
    }
  }
  */
}
