package security.srp;

public class NoSuchUserException extends Exception {
  public NoSuchUserException() { super(); }

  public NoSuchUserException(String arg) { super(arg); }
}
