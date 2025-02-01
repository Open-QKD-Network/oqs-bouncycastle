import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class PublicKeyReader {

  public static PublicKey get(String filename)
    throws Exception {
    
    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

    System.out.println("key file length:" + keyBytes.length);
    X509EncodedKeySpec spec =
      new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  public static void main(String[] args)
  {   
      try {
        PublicKey pk = get("./public_key.der");
        System.out.println("kp.length:" + pk.getEncoded().length);
      } catch (Exception e) {
        e.printStackTrace();
      }
  }
}
