package com.goodstartsoft.pqc;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

import java.security.KeyStore;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.Strings;

public class TLSServer {
    private static Logger LOG = Logger.getLogger(TLSServer.class.getName());

    private final KeyStore serverStore_;
    private final char[] passwd_;

    private static final String[] protocols = new String[] {"TLSv1.3"};
    private static final String[] cipher_suites = new String[] {
            "TLS_AES_256_GCM_SHA384"};

    static public String DESKTOP_DIR = System.getProperty("user.home") + File.separator + "Desktop/";
    static public String IDENTITY_STORE = DESKTOP_DIR + "identity512.p12";
    static public String TRUST_STORE = DESKTOP_DIR + "trust512.p12";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        /*try {
            KeyStore identityStore = TLSUtils.createIdentityKeyStore(512);
            KeyStore trustStore = TLSUtils.createTrustStore(identityStore);
            TLSUtils.saveIdentityStoreToFile(identityStore, IDENTITY_STORE);
            TLSUtils.saveTrustStoreToFile(trustStore, TRUST_STORE);
            KeyStore identityStore2 = TLSUtils.createIdentityStoreFromFile(IDENTITY_STORE);
            KeyStore trustStore2 = TLSUtils.createTrustStoreFromFile(TRUST_STORE);
            System.out.println(identityStore2.equals(identityStore));
            System.out.println(trustStore2.equals(trustStore));
            TLSUtils.saveIdentityStoreToFile(identityStore2, DESKTOP_DIR + "identity5122.p12");
            TLSUtils.saveTrustStoreToFile(trustStore2, DESKTOP_DIR + "trust5122.p12");
            System.out.println("Good!");
        } catch (Exception e) {
            e.printStackTrace();
        }*/
        KeyStore serverStore = null;
        try {
            serverStore = TLSUtils.createIdentityStoreFromFile(IDENTITY_STORE);
        } catch (Exception e) {
            System.out.println("Fails to read identity");
            e.printStackTrace();
            return;
        }
        TLSServer server = new TLSServer(serverStore, TLSUtils.ID_STORE_PASSWORD);
        System.out.println("Server starts...");
        server.start();
    }

    TLSServer(KeyStore serverStore, char[] passwd)
    {
        this.serverStore_ = serverStore;
        this.passwd_ = passwd;
    }

    public void start() {
        try
        {
            SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
            keyMgrFact.init(serverStore_, passwd_);

            sslContext.init(keyMgrFact.getKeyManagers(), null, null);

            SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
            SSLServerSocket sSock =
                (SSLServerSocket)fact.createServerSocket(4443);
            sSock.setEnabledProtocols(protocols);
            sSock.setEnabledCipherSuites(cipher_suites);

            SSLSocket sslSock = (SSLSocket)sSock.accept();
            OutputStream out = sslSock.getOutputStream();
            InputStream in = sslSock.getInputStream();
            out.write(Strings.toByteArray("Welcome to Java SSL\n"));
            //out.write('!');
            int ch = 0;
            while ((ch = in.read()) != '!')
            {
                System.out.print((char)ch);
            }
            System.out.println((char)ch);
        }
        catch (Exception e)
        {
            LOG.log(Level.SEVERE, "server: " + e.getMessage(), e);
        }
    }
}
