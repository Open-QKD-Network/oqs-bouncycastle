package com.goodstartsoft.pqc;

import java.io.InputStream;
import java.io.OutputStream;

import java.security.KeyStore;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.Strings;

/**
 * Basic TLS client - using the '!' protocol.
 */
public class TLSClient
{
    private static Logger LOG = Logger.getLogger(TLSClient.class.getName());

    private static final String[] protocols = new String[] {"TLSv1.3"};
    private static final String[] cipher_suites = new String[] {
            "TLS_AES_256_GCM_SHA384"};
    private final KeyStore trustStore_;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        KeyStore trustStore = null;
        try {
            trustStore = TLSUtils.createTrustStoreFromFile("/home/kxie/Desktop/trust.p12");
        } catch (Exception e) {
            System.out.println("Fails to read trust store");
            e.printStackTrace();
            return;
        }
        TLSClient client = new TLSClient(trustStore);
        System.out.println("Start client ....");
        client.start();
    }

    /**
     * Base client constructor.
     *
     * @param trustStore the certificates we are willing to trust from a server.
     */
    public TLSClient(KeyStore trustStore)
    {
        this.trustStore_ = trustStore;
    }

    public void start() {
        try
        {
            SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");

            TrustManagerFactory trustMgrFact =
                            TrustManagerFactory.getInstance("PKIX", "BCJSSE");
            trustMgrFact.init(trustStore_);

            sslContext.init(null, trustMgrFact.getTrustManagers(), null);

            SSLSocketFactory fact = sslContext.getSocketFactory();
            SSLSocket cSock = (SSLSocket)fact.createSocket("localhost", 8080);
            cSock.setEnabledProtocols(protocols);
            cSock.setEnabledCipherSuites(cipher_suites);

            OutputStream out = cSock.getOutputStream();
            InputStream in = cSock.getInputStream();
            out.write(Strings.toByteArray("Hello world from Client"));
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
            LOG.log(Level.SEVERE, "client: " + e.getMessage(), e);
        }
    }
}
