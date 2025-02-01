package chapter15;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.io.File;
import java.nio.file.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPrivateKey;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.Arrays;


public class MLKEM
{   
    static {
        java.security.Security.addProvider(new BouncyCastleProvider());
    }

    static public String BC_PUBLIC_KEY   = System.getProperty("user.home") + File.separator + "Desktop/bc-mlkem-publickey.txt";
    static public String BC_PRIVATE_KEY  = System.getProperty("user.home") + File.separator + "Desktop/bc-mlkem-privkey.txt";
    static public String BC_CIPHER_TEXT  = System.getProperty("user.home") + File.separator + "Desktop/bc-mlkem-ciphertext.txt";
    static public String OQS_PUBLIC_KEY  = System.getProperty("user.home") + File.separator + "Desktop/oqs-mlkem-publickey.txt";
    static public String OQS_PRIVATE_KEY = System.getProperty("user.home") + File.separator + "Desktop/oqs-mlkem-privkey.txt";
    static public String OQS_CIPHER_TEXT = System.getProperty("user.home") + File.separator + "Desktop/oqs-mlkem-ciphertext.txt";

    public static void main(String[] args) {
        try {
	        test();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean writeByteArrayToFile(byte[] bytes, String fileName) {
        try {
            String hexString = Hex.toHexString(bytes);
            Files.write(Paths.get(fileName), hexString.getBytes());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
	    return false;
	    }
    }
    
    public static byte[] readByteArrayFromFile(String fileName) {
        try {
            Path filePath = Paths.get(fileName);
            String hexString = Files.readString(filePath);
            return Hex.decode(hexString);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static BCKyberPublicKey readKyberPublicKeyFromFile(String fileName) {
        byte[] key = readByteArrayFromFile(fileName);
        if (key == null) {
            return null;
        }
        MLKEMPublicKeyParameters fpkp = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_512, key);
        return new BCKyberPublicKey(fpkp);
    }
    
    public static BCKyberPrivateKey readKyberPrivateKeyFromFile(String fileName) {
        byte[] key = readByteArrayFromFile(fileName);
        if (key == null) {
            return null;
        }
        MLKEMPrivateKeyParameters fpkp = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_512, key);
        return new BCKyberPrivateKey(fpkp);
    }

    public static void test() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        // https://openquantumsafe.org/liboqs/algorithms/kem/kyber
        // mlkem-512: public key size/800, private key size/1632, cipher text size/768, shared secret size/32
        // Test public/private key write to file/read from file
        byte[] rawKey = ((MLKEMPublicKeyParameters) PublicKeyFactory.createKey(kp.getPublic().getEncoded())).getEncoded();
        System.out.println("raw public key encoded size : " + kp.getPublic().getEncoded().length); // 822
        System.out.println("raw public key size         : " + rawKey.length); // 800
        MLKEMPublicKeyParameters fpukp = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_512, rawKey);
        PublicKey puk2 = new BCKyberPublicKey(fpukp);
        System.out.println("puk2 keysize: " + puk2.getEncoded().length);
        System.out.println("public key match:"  + Arrays.areEqual(kp.getPublic().getEncoded(), puk2.getEncoded()));
        writeByteArrayToFile(rawKey, BC_PUBLIC_KEY);
        byte[] rkey = readByteArrayFromFile(BC_PUBLIC_KEY);
        System.out.println("write/read public key match:"  + Arrays.areEqual(rawKey, rkey));

        // Test private key
        rawKey = ((MLKEMPrivateKeyParameters) PrivateKeyFactory.createKey(kp.getPrivate().getEncoded())).getEncoded();
        System.out.println("raw private key encoded size : " + kp.getPrivate().getEncoded().length);
        System.out.println("raw private key size         : " + rawKey.length);
        MLKEMPrivateKeyParameters fprkp = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_512, rawKey);
        PrivateKey prk2 = new BCKyberPrivateKey(fprkp); // this is wrong???
        System.out.println("original private key encoded length:" + kp.getPrivate().getEncoded().length);
        System.out.println("recover  private key encoded length:" + prk2.getEncoded().length);        
        System.out.println("private key match:"  + Arrays.areEqual(kp.getPrivate().getEncoded(), prk2.getEncoded()));
        writeByteArrayToFile(rawKey, BC_PRIVATE_KEY);
        rkey = readByteArrayFromFile(BC_PRIVATE_KEY);
        System.out.println("write/read private key match:"  + Arrays.areEqual(rawKey, rkey));

        KeyGenerator keygen = KeyGenerator.getInstance("ML-KEM", "BC");
        keygen.init(new KEMGenerateSpec(kp.getPublic(), "AES", 128), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keygen.generateKey();
        // secEnc1.getEncoded() // shared secret
        // secEnc1.getEncapsulation() // cipher text

        keygen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES", 128));
        
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keygen.generateKey();

        if (Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded())) {
            System.out.println("AES key generated successfully:" + Hex.toHexString(secEnc1.getEncoded()));
            System.exit(0);
        }

        System.exit(1);
    }
}