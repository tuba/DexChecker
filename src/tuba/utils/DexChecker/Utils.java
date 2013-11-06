package tuba.utils.DexChecker;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

public class Utils {


  public static int readLeInt(InputStream is) throws IOException {
    byte[] buf = new byte[4];
    is.read(buf);

    return leToBe(byteArrayToInt(buf));
  }

  public static String readLeString(InputStream is, int len)
      throws IOException {
    byte[] buf = new byte[len];
    is.read(buf);

    for (int i = 0; i < len / 2; i++) {
      byte tmp = buf[i];
      buf[i] = buf[len - i - 1];
      buf[len - i - 1] = tmp;
    }

    return new String(buf);
  }

  public static int leToBe(int i) {
    return ((i & 0xff) << 24) + ((i & 0xff00) << 8) + ((i & 0xff0000) >> 8) + ((i >> 24) & 0xff);
  }

  public static int byteArrayToInt(byte[] b) {
    return byteArrayToInt(b, 0);
  }

  public static int byteArrayToInt(byte[] b, int offset) {
    int value = 0;
    for (int i = 0; i < 4; i++) {
      int shift = (4 - 1 - i) * 8;
      value += (b[i + offset] & 0x000000FF) << shift;
    }
    return value;
  }

  public static void hashBlock(InputStream is, MessageDigest complete, int needToRead) throws IOException {
    int numRead;
    byte[] buffer = new byte[4096];
    // Update hash by data
    do {
      numRead = (needToRead >= buffer.length) ? is.read(buffer) : is.read(buffer, 0, needToRead);
      if (numRead < 0) {
        return;
      }

      complete.update(buffer, 0, numRead);
      needToRead -= numRead;
    } while (needToRead > 0);
  }
}
