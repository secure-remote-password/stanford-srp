package security.srp;

import java.awt.*;

public class PasswordEntryBox extends Frame {
  private TextField field;
  private Button okay, clear, cancel;
  private String answer;
  private boolean selected;

  public PasswordEntryBox(String title, String prompt) {
    super(title);
    selected = false;
    answer = null;
    add("North", new Label(prompt, Label.CENTER));
    Panel pp = new Panel();
    field = new TextField(20);
    field.setEchoCharacter('*');
    pp.setLayout(new FlowLayout(FlowLayout.CENTER, 10, 10));
    pp.add(field);
    add("Center", pp);
    Panel p = new Panel();
    p.setLayout(new FlowLayout(FlowLayout.CENTER, 10, 10));
    okay = new Button("OK");
    clear = new Button("Clear");
    cancel = new Button("Cancel");
    p.add(okay);
    p.add(clear);
    p.add(cancel);
    add("South", p);

    resize(200, 150);
    show();
  }

  public boolean action(Event evt, Object arg) {
    if(evt.id == Event.ACTION_EVENT)
      if(evt.target == clear)
	field.setText("");
      else if(evt.target == cancel) {
	selected = true;
        wakeup();
	hide();
	dispose();
      }
      else if(evt.target == field || evt.target == okay) {
	answer = field.getText();
	selected = true;
        wakeup();
	hide();
	dispose();
      }

    return super.action(evt, arg);
  }

  public boolean handleEvent(Event evt) {
    if(evt.id == Event.WINDOW_DESTROY) {
      selected = true;
      wakeup();
      hide();
      dispose();
    }
    return super.handleEvent(evt);
  }

  private synchronized void wakeup() { notifyAll(); }

  public synchronized String getAnswer() {
    while(!selected)
      try {
        wait();
      } catch(InterruptedException e) {}
    return answer;
  }

  public static void main(String[] args) {
    PasswordEntryBox pe = new PasswordEntryBox("Enter password", "Enter password");
    String p = pe.getAnswer();
    if(p == null)
      System.out.println("No password entered");
    else
      System.out.println("Password: " + p);
  }
}
