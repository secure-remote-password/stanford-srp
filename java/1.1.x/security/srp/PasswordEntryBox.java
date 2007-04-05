package security.srp;

import java.awt.*;
import java.awt.event.*;

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
    field.setEchoChar('*');
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

    ActionListener doneListener = new ActionListener() {
      public void actionPerformed(ActionEvent e) {
	answer = field.getText();
	close();
      }
    };

    okay.addActionListener(doneListener);
    field.addActionListener(doneListener);

    cancel.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
	close();
      }
    });

    clear.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
	field.setText("");
	field.requestFocus();
      }
    });

    addWindowListener(new WindowAdapter() {
      public void windowClosing(WindowEvent e) {
	close();
      }
    });

    setSize(200, 150);
    show();

    field.requestFocus();
  }

  private synchronized void wakeup() { notifyAll(); }

  // Should be private, but a 1.1 compiler bug prevents us from doing that.
  void close() {
    selected = true;
    wakeup();
    setVisible(false);
    dispose();
  }

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
    System.exit(0);
  }
}
