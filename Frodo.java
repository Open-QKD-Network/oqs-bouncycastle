package chapter15;

import java.util.*;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;

import java.nio.file.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.Key;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
//import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.jcajce.provider.frodo.BCFrodoPublicKey;
import org.bouncycastle.pqc.jcajce.provider.frodo.BCFrodoPrivateKey;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;

public class Frodo
{   
    static {
        java.security.Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
	//test();
        testLiboqs("/home/kxie/Desktop/oqs-bc/oqs_public_key.txt");
        //testLiboqs2();
    }

    public static KeyPair frodoGenerateKeyPair(FrodoParameterSpec frodoParameters) throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Frodo", "BCPQC");
        kpg.initialize(frodoParameters, new SecureRandom());

        return kpg.generateKeyPair();
    }

    public static SecretKeyWithEncapsulation frodoGeneratePartyU(PublicKey vPubKey) throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");
        keyGen.init(new KEMGenerateSpec(vPubKey, "AES"), new SecureRandom());

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static SecretKeyWithEncapsulation frodoGeneratePartyV(PrivateKey vPriv, byte[] encapsulation) throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");
        keyGen.init(new KEMExtractSpec(vPriv, encapsulation, "AES"));

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static void write(Key key, String filename) throws FileNotFoundException, IOException
    {
        PemObject pemObject = new PemObject("Frodo PRIVATE KEY", key.getEncoded());
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        try {
            pemWriter.writeObject(pemObject);
        } finally {
            pemWriter.close();
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

    public static BCFrodoPublicKey readFrodoPublicKeyFromFile(String fileName) {
        byte[] key = readByteArrayFromFile(fileName);
        if (key == null) {
            return null;
        }
        FrodoPublicKeyParameters fpkp = new FrodoPublicKeyParameters(FrodoParameters.frodokem640aes, key);
        return new BCFrodoPublicKey(fpkp);
    }
    
    public static BCFrodoPrivateKey readFrodoPrivateKeyFromFile(String fileName) {
        byte[] key = readByteArrayFromFile(fileName);
        if (key == null) {
            return null;
        }
        FrodoPrivateKeyParameters fpkp = new FrodoPrivateKeyParameters(FrodoParameters.frodokem640aes, key);
        return new BCFrodoPrivateKey(fpkp);
    }

    public static boolean testFrodoKEM(String publicKeyFileName, String privateKeyFileName) {
        PublicKey publicKey = readFrodoPublicKeyFromFile(publicKeyFileName);
        PrivateKey privateKey = readFrodoPrivateKeyFromFile(privateKeyFileName);
	if (publicKey == null || privateKey == null) {
            System.out.println("testForodKEMEncap fails, check publicKey/privateKey!");
	    return false;
        }
        try {
            SecretKeyWithEncapsulation secEnc1 = frodoGeneratePartyU(publicKey);
	    writeByteArrayToFile(secEnc1.getEncapsulation(), "/home/kxie/Desktop/bc-frodo-ciphertext.txt");
            SecretKeyWithEncapsulation secEnc2 = frodoGeneratePartyV(privateKey, secEnc1.getEncapsulation());
            System.out.println("secrets match: " + Arrays.equals(secEnc1.getEncoded(), secEnc2.getEncoded()));
	    return Arrays.equals(secEnc1.getEncoded(), secEnc2.getEncoded());
	} catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void test() {
        try {
            // https://openquantumsafe.org/liboqs/algorithms/kem/frodokem.html
            KeyPair kp = frodoGenerateKeyPair(FrodoParameterSpec.frodokem640aes); // FrodoKEM-640-AEM, cipher text size: 9720, AES keysize: 16, public key length: 9644, private key length: 19918
            //KeyPair kp = frodoGenerateKeyPair(FrodoParameterSpec.frodokem43088shaker3); // FrodoKEM-1344-SHAKE, cipher text size: 21632, AES keysize: 32
            System.out.println("Frodo public key length: " + kp.getPublic().getEncoded().length + ", format: " + kp.getPublic().getFormat() + ", algorithm: " + kp.getPublic().getAlgorithm());
            //System.out.println("Frodo public key: " + Hex.toHexString(kp.getPublic().getEncoded()));
            System.out.println("Frodo private key length: " + kp.getPrivate().getEncoded().length + ", format: " + kp.getPrivate().getFormat() + ", algorithm: " + kp.getPrivate().getAlgorithm());
            //System.out.println("Frodo private key: " + Hex.toHexString(kp.getPrivate().getEncoded()));
            SecretKeyWithEncapsulation secEnc1 = frodoGeneratePartyU(kp.getPublic());
            SecretKeyWithEncapsulation secEnc2 = frodoGeneratePartyV(kp.getPrivate(), secEnc1.getEncapsulation());
            System.out.println("encapsulation length: " + secEnc1.getEncapsulation().length); // + ", " + Hex.toHexString(secEnc1.getEncapsulation()));
            System.out.println("shared secret length: " + secEnc1.getEncoded().length); // + ", " + Hex.toHexString(secEnc1.getEncoded()));
            byte[] kppb = Hex.decode(Hex.toHexString(kp.getPublic().getEncoded()));
            System.out.println("Hex decode/encode mathc: " + Arrays.equals(kppb, kp.getPublic().getEncoded()));
            System.out.println("secrets match: " + Arrays.equals(secEnc1.getEncoded(), secEnc2.getEncoded()));
	    //write(kp.getPrivate(), "frodo-private.pem");
            //write(kp.getPublic(),  "frodo-public.pem");

            // get the rawkey from PublicKey
            byte[] rawKey = ((FrodoPublicKeyParameters) PublicKeyFactory.createKey(kp.getPublic().getEncoded())).getPublicKey();

            // generate PublicKey from rawKey
            System.out.println("raw public key size: " + rawKey.length);
            FrodoPublicKeyParameters fpukp = new FrodoPublicKeyParameters(FrodoParameters.frodokem640aes, rawKey);
            PublicKey puk2 = new BCFrodoPublicKey(fpukp);
            System.out.println("public key match:"  + Arrays.equals(kp.getPublic().getEncoded(), puk2.getEncoded()));

            //write(pk2, "frodo-public2.pem");
	    writeByteArrayToFile(rawKey, "/home/kxie/Desktop/bc-frodom-publickey.txt");
	    byte[] rkey = readByteArrayFromFile("/home/kxie/Desktop/bc-frodom-publickey.txt");
            System.out.println("write/read public key match:"  + Arrays.equals(rawKey, rkey));

            rawKey = ((FrodoPrivateKeyParameters) PrivateKeyFactory.createKey(kp.getPrivate().getEncoded())).getPrivateKey();
	    // generate PrivateKey from rawKey
            System.out.println("raw private key size: " + rawKey.length);
            FrodoPrivateKeyParameters fprkp = new FrodoPrivateKeyParameters(FrodoParameters.frodokem640aes, rawKey);
            PrivateKey prk2 = new BCFrodoPrivateKey(fprkp);
            System.out.println("private key match:"  + Arrays.equals(kp.getPrivate().getEncoded(), prk2.getEncoded()));

	    writeByteArrayToFile(rawKey, "/home/kxie/Desktop/bc-frodom-privatekey.txt");
	    rkey = readByteArrayFromFile("/home/kxie/Desktop/bc-frodom-privatekey.txt");
            System.out.println("write/read private key match:"  + Arrays.equals(rawKey, rkey));

            testFrodoKEM("/home/kxie/Desktop/bc-frodom-publickey.txt", "/home/kxie/Desktop/bc-frodom-privatekey.txt");
        } catch (Exception e) {
            e.printStackTrace();
	}
    }

    // liboqs writes public key to file, bouncycastle reads public key,
    // encaps with the public key, writes the cipher text to file for liboqs to decap.
    public static boolean testLiboqs(String publicKeyFileName) {
        PublicKey publicKey = readFrodoPublicKeyFromFile(publicKeyFileName);
	if (publicKey == null) {
            System.out.println("testLiboqs fails, check publicKey!");
	    return false;
        }
        try {
            SecretKeyWithEncapsulation secEnc1 = frodoGeneratePartyU(publicKey);
	    writeByteArrayToFile(secEnc1.getEncapsulation(), "/home/kxie/Desktop/oqs-bc/bc_cipher_text.txt");
	    System.out.println("Shared secret:" + Hex.toHexString(secEnc1.getEncoded()));
	    return true;
	} catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // bouncy castle writes the public key to file, liboqs encaps with the public key
    // reads the cipher text from liboqs, and decaps the cipher text.
    public static boolean testLiboqs2() {
        try {
            KeyPair kp = frodoGenerateKeyPair(FrodoParameterSpec.frodokem640aes); // FrodoKEM-640-AEM, cipher text size: 9720, AES keysize: 16, public key length: 9644, private key length: 19918
            byte[] rawKey = ((FrodoPublicKeyParameters) PublicKeyFactory.createKey(kp.getPublic().getEncoded())).getPublicKey();
            writeByteArrayToFile(rawKey, "/home/kxie/Desktop/oqs-bc/bc_public_key.txt");
            File file = new File("/home/kxie/Desktop/oqs-bc/oqs_cipher_text.txt");
            while (!file.exists()) {
                System.out.println("File /home/kxie/Desktop/oqs-bc/oqs_cipher_text.txt is not ready, wait 1 minute");
                Thread.sleep(1000 * 60); // sleep 1 minute
                file = new File("/home/kxie/Desktop/oqs-bc/oqs_cipher_text.txt");
            }
            byte[] cipher = readByteArrayFromFile("/home/kxie/Desktop/oqs-bc/oqs_cipher_text.txt");
	    System.out.println("cipher text size:" + cipher.length);
            SecretKeyWithEncapsulation decap = frodoGeneratePartyV(kp.getPrivate(), cipher);
	    System.out.println("Shared secret:" + Hex.toHexString(decap.getEncoded()));
            return true;
        } catch (Exception e) {
            System.out.println("Exception in testLiboqs2)");
            e.printStackTrace();
            return false;
        }
    }
}
