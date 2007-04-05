package security.crypt;

import java.util.Random;

public class RandomBytes extends Random {
  public RandomBytes() {
    super();
  }
  public RandomBytes(long seed) {
    super(seed);
  }

  public byte[] nextBytes(int n) {
    byte[] result = new byte[n];
    int i, ec;
    long val = 0;

    for(i = 0, ec = 0; i < n; ++i, ++ec) {
      if(ec >= 8)
	ec = 0;
      if(ec == 0)
	val = this.nextLong();
      result[i] = (byte) (val & 0xff);
      val >>= 8;
    }
    return result;
  }
}
