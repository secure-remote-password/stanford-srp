/*
 * ErrorDialog.java
 * Author: Tom Wu
 *
 * A simple dialog box for displaying error messages.
 */

package socket;

import java.awt.*;

public class ErrorDialog extends Dialog {
  protected Button okay;
  private boolean selected;

  public ErrorDialog(Frame parent, String title, String message) {
    super(parent, title, false);
    selected = false;
    if(message == null)
      message = title;
    Label label = new Label(message, Label.CENTER);
    add("Center", label);
    int width = label.getFontMetrics(label.getFont()).stringWidth(message);
    Panel p = new Panel();
    p.setLayout(new FlowLayout(FlowLayout.CENTER, 15, 15));
    okay = new Button("OK");
    p.add(okay);
    add("South", p);

    resize(width + 50, 150);
    show();
  }

  public boolean action(Event evt, Object arg) {
    if(evt.id == Event.ACTION_EVENT)
      if(evt.target == okay) {
	selected = true;
	hide();
	dispose();
	wakeup();
      }
    return super.action(evt, arg);
  }

  public boolean gotFocus(Event evt, Object arg) {
    okay.requestFocus();
    return true;
  }

  public boolean handleEvent(Event evt) {
    if(evt.id == Event.WINDOW_DESTROY) {
      selected = true;
      hide();
      dispose();
      wakeup();
    }
    return super.handleEvent(evt);
  }

  public synchronized void wakeup() { notifyAll(); }

  public synchronized void waitForUser() {
    while(!selected)
      try {
	wait();
      } catch(InterruptedException e) {}
  }
}
