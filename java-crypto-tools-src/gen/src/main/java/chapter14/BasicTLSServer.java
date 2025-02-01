package chapter14;

import java.security.KeyStore;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import static chapter14.TLSUtils.PORT_NO;

/**
 * Basic TLS server - using the '!' protocol.
 */
public class BasicTLSServer
{
    private static Logger LOG = Logger.getLogger(BasicTLSServer.class.getName());

    private final CountDownLatch readyLatch = new CountDownLatch(1);

    private final KeyStore serverStore;
    private final char[] passwd;

    private static final String[] protocols = new String[] {"TLSv1.3"};
    private static final String[] cipher_suites = new String[] {
            "TLS_AES_256_GCM_SHA384"};

    /**
     * Base server constructor.
     *
     * @param serverStore the public/private keys for the server.
     * @param passwd the password to unlock the private keys in the serverStore.
     */
    BasicTLSServer(KeyStore serverStore, char[] passwd)
    {
        this.serverStore = serverStore;
        this.passwd = passwd;
    }

    /**
     * Task for bringing up a server-side TLS connection.
     */
    public void start()
        throws InterruptedException
    {
        new Thread(new ServerTask()).start();

        readyLatch.await();
    }

    /**
     * Task for bringing up a server-side of the TLS connection.
     */
    private class ServerTask
        implements Runnable
    {
        public void run()
        {
            try
            {
                SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");

                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance(
                    "PKIX", "BCJSSE");
                keyMgrFact.init(serverStore, passwd);

                sslContext.init(keyMgrFact.getKeyManagers(), null, null);

                SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
                SSLServerSocket sSock =
                    (SSLServerSocket)fact.createServerSocket(PORT_NO);
		sSock.setEnabledProtocols(protocols);
		sSock.setEnabledCipherSuites(cipher_suites);

                readyLatch.countDown();

                SSLSocket sslSock = (SSLSocket)sSock.accept();

                Protocol.doServerSide(sslSock);
            }
            catch (Exception e)
            {
                LOG.log(Level.SEVERE, "server: " + e.getMessage(), e);
            }
        }
    }
}
