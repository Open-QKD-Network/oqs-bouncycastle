package chapter15;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.GeneralSecurityException;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPrivateKey;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;


public class Kyber
{   
    static {
        //java.security.Security.addProvider(new BouncyCastleProvider());
        java.security.Security.addProvider(new BouncyCastlePQCProvider());

    }

    static public String BC_PUBLIC_KEY   = System.getProperty("user.home") + File.separator + "Desktop/bc-mlkem-publickey.txt";
    static public String BC_PRIVATE_KEY  = System.getProperty("user.home") + File.separator + "Desktop/bc-mlkem-privkey.txt";
    static public String BC_CIPHER_TEXT  = System.getProperty("user.home") + File.separator + "Desktop/bc-mlkem-ciphertext.txt";
    static public String OQS_PUBLIC_KEY  = System.getProperty("user.home") + File.separator + "Desktop/oqs-mlkem-publickey.txt";
    static public String OQS_PRIVATE_KEY = System.getProperty("user.home") + File.separator + "Desktop/oqs-mlkem-privkey.txt";
    static public String OQS_CIPHER_TEXT = System.getProperty("user.home") + File.separator + "Desktop/oqs-mlkem-ciphertext.txt";

    public static void main(String[] args) {
        try {
            //test(KyberParameterSpec.ml_kem_512, KyberParameters.ml_kem_512, 256);
            //test(KyberParameterSpec.ml_kem_1024, KyberParameters.ml_kem_1024, 256);
            //testOQSEncapBCDecap(KyberParameterSpec.kyber512, 256);
            testOQSDecapBCEncap(MLKEMParameters.ml_kem_512, 256);
            //test(KyberParameterSpec.kyber512, MLKEMParameters.ml_kem_512, 256);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static KeyPair KyberGenerateKeyPair(KyberParameterSpec param) throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(param, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static SecretKeyWithEncapsulation KyberGeneratePartyU(PublicKey vPubKey, int bits) throws GeneralSecurityException
    {
        KeyGenerator keygen = KeyGenerator.getInstance("Kyber", "BCPQC");
        keygen.init(new KEMGenerateSpec(vPubKey, "AES", bits), new SecureRandom());

        return (SecretKeyWithEncapsulation)keygen.generateKey();
    }

    public static SecretKeyWithEncapsulation KyberGeneratePartyV(PrivateKey vPriv, byte[] ciphertext, int bits) throws GeneralSecurityException
    {
        KeyGenerator keygen = KeyGenerator.getInstance("Kyber", "BCPQC");
        keygen.init(new KEMExtractSpec(vPriv, ciphertext, "AES", bits));

        return (SecretKeyWithEncapsulation)keygen.generateKey();
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

    public static void test(KyberParameterSpec spec, MLKEMParameters parameters, int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(spec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        // https://openquantumsafe.org/liboqs/algorithms/kem/kyber
        // Kyber-512: public key size/800, private key size/1632, cipher text size/768, shared secret size/32
        // Test public/private key write to file/read from file
        BCKyberPublicKey pubk = (BCKyberPublicKey) kp.getPublic();       
        // get the rawkey from PublicKey
        MLKEMPublicKeyParameters pkp = (MLKEMPublicKeyParameters) PublicKeyFactory.createKey(kp.getPublic().getEncoded());
        byte[] rawKey = pkp.getEncoded();
        // generate PublicKey from rawKey
        System.out.println("raw public key size: " + rawKey.length);
        MLKEMPublicKeyParameters fpukp = new MLKEMPublicKeyParameters(parameters, rawKey);
        PublicKey puk2 = new BCKyberPublicKey(fpukp);
        System.out.println("public key match:"  + Arrays.areEqual(kp.getPublic().getEncoded(), puk2.getEncoded()));
        writeByteArrayToFile(rawKey, BC_PUBLIC_KEY);
        byte[] rkey = readByteArrayFromFile(BC_PUBLIC_KEY);
        System.out.println("write/read public key match:"  + Arrays.areEqual(rawKey, rkey));

        KeyGenerator keygen = KeyGenerator.getInstance("Kyber", "BCPQC");
        keygen.init(new KEMGenerateSpec(puk2, "AES", bits), new SecureRandom());
        //keygen.init(new KEMGenerateSpec(kp.getPublic(), "AES", bits), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keygen.generateKey();
        // secEnc1.getEncoded() // shared secret
        // secEnc1.getEncapsulation() // cipher text

        keygen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES", bits));
        
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keygen.generateKey();

        if (Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded())) {
            System.out.println("AES key generated successfully:" + Hex.toHexString(secEnc1.getEncoded()));
            System.exit(0);
        } else {
            System.out.println("AES key generated failed:" + Hex.toHexString(secEnc1.getEncoded()));
            System.out.println("AES key generated failed:" + Hex.toHexString(secEnc2.getEncoded()));

        }

        System.exit(1);
    }

    // BC Decap OQS Encap
    // bouncy castle writes the public key to file, liboqs encaps with the public key
    // bouncy castle reads the cipher text from liboqs, and decaps the cipher text.
    public static boolean testOQSEncapBCDecap(KyberParameterSpec spec, int bits)
    {
        try {
            KeyPair kp = KyberGenerateKeyPair(spec);
            BCKyberPublicKey pubk = (BCKyberPublicKey) kp.getPublic();
            MLKEMPublicKeyParameters pkp = (MLKEMPublicKeyParameters) PublicKeyFactory.createKey(kp.getPublic().getEncoded());
            byte[] rawKey = pkp.getEncoded();
            System.out.println("Write public key to " + BC_PUBLIC_KEY);
            writeByteArrayToFile(rawKey, BC_PUBLIC_KEY);
            File file = new File(OQS_CIPHER_TEXT);
            while (!file.exists()) {
                System.out.println("File " + OQS_CIPHER_TEXT + " is not ready, wait 1 minute");
                Thread.sleep(1000 * 60); // sleep 1 minute
                file = new File(OQS_CIPHER_TEXT);
            }
            byte[] cipher = readByteArrayFromFile(OQS_CIPHER_TEXT);
	        System.out.println("cipher text size:" + cipher.length);
            writeByteArrayToFile(cipher, "/home/dell2/Desktop/bc-read-ciphertext");
            SecretKeyWithEncapsulation decap = KyberGeneratePartyV(kp.getPrivate(), cipher, bits);
            System.out.println("Shared secret:" + Hex.toHexString(decap.getEncoded()));
            return true;
        } catch (Exception e) {
            System.out.println("Exception in testOQSEncapBCDecap");
            e.printStackTrace();
            return false;
        }
    }

    // OQS Decap BC Encap
    // bouncy castle writes the public key to file, liboqs encaps with the public key
    // bouncy castle reads the cipher text from liboqs, and decaps the cipher text.
    public static boolean testOQSDecapBCEncap(MLKEMParameters parameters, int bits)
    {
        try {
            // Read OQS public key
            File file = new File(OQS_PUBLIC_KEY);
            while (!file.exists()) {
                System.out.println("File " + OQS_PUBLIC_KEY + " is not ready, wait 1 minute");
                Thread.sleep(1000 * 60); // sleep 1 minute
                file = new File(OQS_PUBLIC_KEY);
            }
            byte[] rawKey = readByteArrayFromFile(OQS_PUBLIC_KEY);
            System.out.println("public key size:" + rawKey.length);
            MLKEMPublicKeyParameters fpukp = new MLKEMPublicKeyParameters(parameters, rawKey);
            PublicKey pubKey = new BCKyberPublicKey(fpukp);
            SecretKeyWithEncapsulation secEncap = KyberGeneratePartyU(pubKey, 256);
            writeByteArrayToFile(secEncap.getEncapsulation(), BC_CIPHER_TEXT);
            byte[] sharedSecret = secEncap.getEncoded();
            System.out.println("Shared secred length: " + sharedSecret.length + ", secret: " + Hex.toHexString(sharedSecret));
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
