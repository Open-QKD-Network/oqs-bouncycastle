package com.goodstartsoft.pqc;

import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class TLSUtils
{
    public static final int PORT_NO = 9090;
    public static final char[] ID_STORE_PASSWORD = "123456".toCharArray();

    /**
     * Create a KeyStore containing a single key with a self-signed certificate.
     *
     * @return a KeyStore containing a single key with a self-signed certificate.
     */
    public static KeyStore createIdentityKeyStore(int keylength)
        throws Exception
    {
        PrivateCredential cred = KeyStoreUtils.createSelfSignedCredentials(keylength);

        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(null, null);

        //store.setKeyEntry("identity", cred.getPrivateKey(), ID_STORE_PASSWORD,
        //                            new Certificate[]{cred.getCertificate()});

        store.setKeyEntry("identity", cred.getPrivateKey(), null,
            new Certificate[] { cred.getCertificate() });
        return store;

	/*PrivateCredential cred = createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(null, null);

        store.setKeyEntry("key", cred.getPrivateKey(), null,
            new Certificate[] { cred.getCertificate() });

        FileOutputStream fOut = new FileOutputStream("basic.p12");

        store.store(fOut, "123456".toCharArray());

        fOut.close();*/
    }

    /**
     * Create a key store suitable for use as a trust store, containing only
     * the certificates associated with each alias in the passed in
     * credentialStore.
     *
     * @param credentialStore key store containing public/private credentials.
     * @return a key store containing only certificates.
     */
    public static KeyStore createTrustStore(KeyStore credentialStore)
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(null, null);

        for (Enumeration<String> en = credentialStore.aliases(); en.hasMoreElements();)
        {
            String alias = en.nextElement();
            System.out.println("createTrustStore, alias:" + alias);

            store.setCertificateEntry(alias, credentialStore.getCertificate(alias));
        }

        return store;
    }

    // That is good
    public static KeyStore createIdentityStoreFromFile(String storeName) throws Exception{
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(storeName), ID_STORE_PASSWORD);
        return ks;
    }

    public static KeyStore createTrustStoreFromFile(String storeName) throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(storeName), null);
        if (ks.getCertificate("identity") != null) {
            System.out.println("Trust store has identity certificate");
        } else {
            System.out.println("Trust store does not has identity certificate");
        }
        return ks;
    }

    // That is good
    public static void saveIdentityStoreToFile(KeyStore keyStore, String storeName) throws Exception
    {
        FileOutputStream fOut = new FileOutputStream(storeName);
        keyStore.store(fOut, ID_STORE_PASSWORD);
        fOut.close();
    }

    public static void saveTrustStoreToFile(KeyStore keyStore, String storeName) throws Exception
    {
        FileOutputStream fOut = new FileOutputStream(storeName);
        keyStore.store(fOut, null);
        fOut.close();
    }
}