import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class PrivateKeyReader {

  public static PrivateKey get(String filename)
    throws Exception {

    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

    PKCS8EncodedKeySpec spec =
      new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
  }

    public static void main(String[] args)
  {
      try {
        PrivateKey pk = get("./private_key.der");
        System.out.println("kp.length:" + pk.getEncoded().length);
      } catch (Exception e) {
        e.printStackTrace();
      }
  }

}
