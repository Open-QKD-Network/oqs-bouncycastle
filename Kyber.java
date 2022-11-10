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
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPrivateKey;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;

public class Kyber
{   
    static 
    {
        java.security.Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
	    //test();
        testLiboqs("/home/kxie/Desktop/oqs-bc/oqs_kyber_public_key.txt");
        //testLiboqs2();
    }

    public static KeyPair kyberGenerateKeyPair(KyberParameterSpec kyberParameters) throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(kyberParameters, new SecureRandom());

        return kpg.generateKeyPair();
    }

    public static SecretKeyWithEncapsulation kyberGeneratePartyU(PublicKey vPubKey) throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");
        keyGen.init(new KEMGenerateSpec(vPubKey, "AES"), new SecureRandom());

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static SecretKeyWithEncapsulation kyberGeneratePartyV(PrivateKey vPriv, byte[] encapsulation) throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");
        keyGen.init(new KEMExtractSpec(vPriv, encapsulation, "AES"));

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static void write(Key key, String filename) throws FileNotFoundException, IOException
    {
        PemObject pemObject = new PemObject("Kyber PRIVATE KEY", key.getEncoded());
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        try {
            pemWriter.writeObject(pemObject);
        } finally {
            pemWriter.close();
        }
    }

    public static boolean writeByteArrayToFile(byte[] bytes, String fileName)
    {
        try {
            String hexString = Hex.toHexString(bytes);
            Files.write(Paths.get(fileName), hexString.getBytes());
            return true;
    	} catch (Exception e) {
            e.printStackTrace();
	        return false;
	    }
    }
    
    public static byte[] readByteArrayFromFile(String fileName)
    {
        try {
	        Path filePath = Paths.get(fileName);
	        String hexString = Files.readString(filePath);
            return Hex.decode(hexString);
	    } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static BCKyberPublicKey readKyberPublicKeyFromFile(String fileName)
    {
        byte[] key = readByteArrayFromFile(fileName);
        if (key == null) {
            return null;
        }
        KyberPublicKeyParameters fpkp = new KyberPublicKeyParameters(KyberParameters.kyber512, key);
        return new BCKyberPublicKey(fpkp);
    }
    
    public static BCKyberPrivateKey readKyberPrivateKeyFromFile(String fileName)
    {
        byte[] key = readByteArrayFromFile(fileName);
        if (key == null) {
            return null;
        }
        byte[] empty = new byte[0];
        KyberPrivateKeyParameters fpkp = new KyberPrivateKeyParameters(KyberParameters.kyber512, key, empty, empty, empty, empty);
        return new BCKyberPrivateKey(fpkp);
    }

    public static boolean testKyberKEM(String publicKeyFileName, String privateKeyFileName)
    {
        PublicKey publicKey = readKyberPublicKeyFromFile(publicKeyFileName);
        PrivateKey privateKey = readKyberPrivateKeyFromFile(privateKeyFileName);
	    if (publicKey == null || privateKey == null) {
            System.out.println("testKyberKEMEncap fails, check publicKey/privateKey!");
	        return false;
        }
        try {
            SecretKeyWithEncapsulation secEnc1 = kyberGeneratePartyU(publicKey);
	        writeByteArrayToFile(secEnc1.getEncapsulation(), "/home/kxie/Desktop/bc-kyber-ciphertext.txt");
            SecretKeyWithEncapsulation secEnc2 = kyberGeneratePartyV(privateKey, secEnc1.getEncapsulation());
            System.out.println("secrets match: " + Arrays.equals(secEnc1.getEncoded(), secEnc2.getEncoded()));
	        return Arrays.equals(secEnc1.getEncoded(), secEnc2.getEncoded());
	    } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void test() {
        try {
            // https://openquantumsafe.org/liboqs/algorithms/kem/kyber.html
            KeyPair kp = kyberGenerateKeyPair(KyberParameterSpec.kyber512); // Kyber512
            System.out.println("Kyber public key length: " + kp.getPublic().getEncoded().length + ", format: " + kp.getPublic().getFormat() + ", algorithm: " + kp.getPublic().getAlgorithm());
            //System.out.println("Kyber public key: " + Hex.toHexString(kp.getPublic().getEncoded()));
            System.out.println("Kyber private key length: " + kp.getPrivate().getEncoded().length + ", format: " + kp.getPrivate().getFormat() + ", algorithm: " + kp.getPrivate().getAlgorithm());
            //System.out.println("Kyber private key: " + Hex.toHexString(kp.getPrivate().getEncoded()));
            SecretKeyWithEncapsulation secEnc1 = kyberGeneratePartyU(kp.getPublic());
            SecretKeyWithEncapsulation secEnc2 = kyberGeneratePartyV(kp.getPrivate(), secEnc1.getEncapsulation());
            System.out.println("encapsulation length: " + secEnc1.getEncapsulation().length); // + ", " + Hex.toHexString(secEnc1.getEncapsulation()));
            System.out.println("shared secret length: " + secEnc1.getEncoded().length); // + ", " + Hex.toHexString(secEnc1.getEncoded()));
            byte[] kppb = Hex.decode(Hex.toHexString(kp.getPublic().getEncoded()));
            System.out.println("Hex decode/encode math: " + Arrays.equals(kppb, kp.getPublic().getEncoded()));
            System.out.println("secrets match: " + Arrays.equals(secEnc1.getEncoded(), secEnc2.getEncoded()));
	    
            //write(kp.getPrivate(), "frodo-private.pem");
            //write(kp.getPublic(),  "frodo-public.pem");

            // get the rawkey from PublicKey
            byte[] rawKey = ((KyberPublicKeyParameters) PublicKeyFactory.createKey(kp.getPublic().getEncoded())).getPublicKey();

            // generate PublicKey from rawKey
            System.out.println("raw public key size: " + rawKey.length);
            KyberPublicKeyParameters fpukp = new KyberPublicKeyParameters(KyberParameters.kyber512, rawKey);
            PublicKey puk2 = new BCKyberPublicKey(fpukp);
            System.out.println("public key match:"  + Arrays.equals(kp.getPublic().getEncoded(), puk2.getEncoded()));

            //write(pk2, "frodo-public2.pem");
	        writeByteArrayToFile(rawKey, "/home/kxie/Desktop/bc-kyber-publickey.txt");
	        byte[] rkey = readByteArrayFromFile("/home/kxie/Desktop/bc-kyber-publickey.txt");
            System.out.println("write/read public key match:"  + Arrays.equals(rawKey, rkey));

            rawKey = ((KyberPrivateKeyParameters) PrivateKeyFactory.createKey(kp.getPrivate().getEncoded())).getPrivateKey();
	        // generate PrivateKey from rawKey
            System.out.println("raw private key size: " + rawKey.length);
        } catch (Exception e) {
            e.printStackTrace();
	    }
    }

    // liboqs writes public key to file, bouncycastle reads public key,
    // encaps with the public key, writes the cipher text to file for liboqs to decap.
    public static boolean testLiboqs(String publicKeyFileName)
    {
        PublicKey publicKey = readKyberPublicKeyFromFile(publicKeyFileName);
	    if (publicKey == null) {
            System.out.println("testLiboqs fails, check publicKey!");
	        return false;
        }
        try {
            SecretKeyWithEncapsulation secEnc1 = kyberGeneratePartyU(publicKey);
	        writeByteArrayToFile(secEnc1.getEncapsulation(), "/home/kxie/Desktop/oqs-bc/bc_kyber_cipher_text.txt");
	        System.out.println("Shared secret:" + Hex.toHexString(secEnc1.getEncoded()));
	        return true;
	    } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // bouncy castle writes the public key to file, liboqs encaps with the public key
    // reads the cipher text from liboqs, and decaps the cipher text.
    public static boolean testLiboqs2()
    {
        try {
            KeyPair kp = kyberGenerateKeyPair(KyberParameterSpec.kyber512);
            byte[] rawKey = ((KyberPublicKeyParameters) PublicKeyFactory.createKey(kp.getPublic().getEncoded())).getPublicKey();
            writeByteArrayToFile(rawKey, "/home/kxie/Desktop/oqs-bc/bc_kyber_public_key.txt");
            File file = new File("/home/kxie/Desktop/oqs-bc/oqs_kyber_cipher_text.txt");
            while (!file.exists()) {
                System.out.println("File /home/kxie/Desktop/oqs-bc/oqs_kyber_cipher_text.txt is not ready, wait 1 minute");
                Thread.sleep(1000 * 60); // sleep 1 minute
                file = new File("/home/kxie/Desktop/oqs-bc/oqs_kyber_cipher_text.txt");
            }
            byte[] cipher = readByteArrayFromFile("/home/kxie/Desktop/oqs-bc/oqs_kyber_cipher_text.txt");
	        System.out.println("cipher text size:" + cipher.length);
            SecretKeyWithEncapsulation decap = kyberGeneratePartyV(kp.getPrivate(), cipher);
	        System.out.println("Shared secret:" + Hex.toHexString(decap.getEncoded()));
            return true;
        } catch (Exception e) {
            System.out.println("Exception in testLiboqs2)");
            e.printStackTrace();
            return false;
        }
    }
}
