/*
 * LoginBox.java
 * Author: Tom Wu
 *
 * A class that puts up a generic login/password frame.
 */

package socket;

import java.awt.*;

public class LoginBox extends Frame {
  private TextField logname, passwd;
  private Button enter, cancel;
  private Label msg;
  private boolean uselected, pselected, valid;

  public LoginBox(String title, String welcome) {
    super(title);

    uselected = false;
    pselected = false;
    valid = false;

    Panel p;
    Label l;

    GridBagLayout gb = new GridBagLayout();

    setLayout(gb);

    GridBagConstraints c = new GridBagConstraints();

    c.fill = GridBagConstraints.BOTH;
    c.insets = new Insets(2, 2, 2, 2);

    c.gridwidth = GridBagConstraints.BOTH;
    l = new Label("Login:", Label.RIGHT);
    gb.setConstraints(l, c);
    add(l);

    c.gridwidth = GridBagConstraints.REMAINDER;
    logname = new TextField(12);
    logname.setFont(new Font("Courier", Font.PLAIN, 12));
    gb.setConstraints(logname, c);
    add(logname);

    c.gridwidth = GridBagConstraints.BOTH;
    l = new Label("Password:", Label.RIGHT);
    gb.setConstraints(l, c);
    add(l);

    c.gridwidth = GridBagConstraints.REMAINDER;
    passwd = new TextField(12);
    passwd.setFont(new Font("Courier", Font.PLAIN, 12));
    passwd.setEchoCharacter('*');
    gb.setConstraints(passwd, c);
    add(passwd);

    p = new Panel();
    p.setLayout(new FlowLayout());

    enter = new Button("Log In");
    p.add(enter);

    cancel = new Button("Cancel");
    p.add(cancel);

    c.gridwidth = GridBagConstraints.REMAINDER;
    c.fill = GridBagConstraints.NONE;
    gb.setConstraints(p, c);
    add(p);

    c.gridwidth = GridBagConstraints.REMAINDER;
    c.fill = GridBagConstraints.BOTH;
    msg = new Label(welcome, Label.CENTER);
    msg.setFont(new Font("Helvetica", Font.BOLD, 14));
    gb.setConstraints(msg, c);
    add(msg);

    validate();
    logname.requestFocus();

    resize(240, 200);
    show();
  }

  public void showMessage(String s) {
    msg.setForeground(Color.black);
    msg.setText(s);
  }

  public void showError(String s) {
    msg.setForeground(Color.red);
    msg.setText(s);
  }

  public boolean action(Event evt, Object arg) {
    if(evt.id == Event.ACTION_EVENT)
      if(evt.target == logname) {
	showMessage("");
	passwd.requestFocus();
	uselected = true;
	valid = true;
	wakeup();
      }
      else if(evt.target == cancel) {
	destroy();
      }
      else if(evt.target == passwd || evt.target == enter) {
	uselected = true;
	pselected = true;
	valid = true;
	enter.disable();
	showMessage("Authenticating...");
	wakeup();
      }
    return super.action(evt, arg);
  }

  public boolean handleEvent(Event evt) {
    if(evt.id == Event.WINDOW_DESTROY)
      destroy();
    else if(evt.id == Event.LOST_FOCUS && evt.target == logname &&
	    logname.getText().length() > 0) {
      showMessage("");
      uselected = true;
      valid = true;
      wakeup();
    }
    return super.handleEvent(evt);
  }

  public void destroy() {
    uselected = true;
    pselected = true;
    valid = false;
    wakeup();
    hide();
    dispose();
  }

  private synchronized void wakeup() { notifyAll(); }

  public synchronized String getUsername() {
    while(!uselected)
      try {
	wait();
      } catch(InterruptedException e) {}
    if(valid) {
      logname.disable();
      return logname.getText();
    }
    else
      return null;
  }

  public synchronized String getPassword() {
    while(!pselected)
      try {
	wait();
      } catch(InterruptedException e) {}
    if(valid) {
      passwd.disable();
      return passwd.getText();
    }
    else
      return null;
  }
}
