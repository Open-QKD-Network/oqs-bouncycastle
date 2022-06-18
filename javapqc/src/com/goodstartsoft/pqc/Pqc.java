package com.goodstartsoft.pqc;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;

/*
 * Don't forget to set the following system properties when you run the class:
 *
 *     javax.net.ssl.keyStore
 *     javax.net.ssl.keyStorePassword
 *     javax.net.ssl.trustStore
 *     javax.net.ssl.trustStorePassword
 *
 * More details can be found in JSSE docs.
 *
 * For example:
 * 
 *     java -cp classes \
 *         -Djavax.net.ssl.keyStore=keystore \
 *         -Djavax.net.ssl.keyStorePassword=passphrase \
 *         -Djavax.net.ssl.trustStore=keystore \
 *         -Djavax.net.ssl.trustStorePassword=passphrase \
 *             com.goodstartsoft.pqc.Pqc
 *
 * For testing purposes, you can download the keystore file from 
 *
 *     https://github.com/openjdk/jdk/tree/master/test/jdk/javax/net/ssl/etc
 */
public class Pqc {

    private static final int delay = 1000; // in millis
    private static final String[] protocols = new String[] {"TLSv1.3"};
    private static final String[] cipher_suites = new String[] {
            "TLS_AES_256_GCM_SHA384"};
    private static final String message =
            "Like most of life's problems, this one can be solved with bending!";

    static {
        java.security.Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
        java.security.Security.insertProviderAt(new org.bouncycastle.jsse.provider.BouncyCastleJsseProvider(), 2);
    }

    public static void main(String[] args) throws Exception {
        try (EchoServer server = EchoServer.create()) {
            new Thread(server).start();
            Thread.sleep(delay);

            /*try (SSLSocket socket = createSocket("localhost", server.port())) {
                InputStream is = new BufferedInputStream(socket.getInputStream());
                OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                os.write(message.getBytes());
                os.flush();
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len <= 0) {
                    throw new IOException("no data received");
                }
                System.out.printf("client received %d bytes: %s%n",
                        len, new String(data, 0, len));
            }*/
	    while (true) {
	    }
        }
    }

    public static SSLSocket createSocket(String host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault()
                .createSocket(host, port);
        socket.setEnabledProtocols(protocols);
        socket.setEnabledCipherSuites(cipher_suites);
        return socket;
    }

    public static class EchoServer implements Runnable, AutoCloseable {

        private static final int FREE_PORT = 4433;

        private final SSLServerSocket sslServerSocket;

        private EchoServer(SSLServerSocket sslServerSocket) {
            this.sslServerSocket = sslServerSocket;
        }

        public int port() {
            return sslServerSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            if (sslServerSocket != null && !sslServerSocket.isClosed()) {
                sslServerSocket.close();
            }
        }

        @Override
        public void run() {
            System.out.printf("server started on port %d%n", port());

            try (SSLSocket socket = (SSLSocket) sslServerSocket.accept()) {
                System.out.println("accepted");
                InputStream is = new BufferedInputStream(socket.getInputStream());
                OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len <= 0) {
                    throw new IOException("no data received");
                }
                System.out.printf("server received %d bytes: %s%n",
                        len, new String(data, 0, len));
                os.write(data, 0, len);
                os.flush();
            } catch (Exception e) {
                System.out.printf("exception: %s%n", e.getMessage());
            }

            System.out.println("server stopped");
        }

        public static EchoServer create() throws IOException {
            return create(FREE_PORT);
        }

        public static EchoServer create(int port) throws IOException {
            SSLServerSocket socket = (SSLServerSocket)
                    SSLServerSocketFactory.getDefault().createServerSocket(port);
            socket.setEnabledProtocols(protocols);
            socket.setEnabledCipherSuites(cipher_suites);
            return new EchoServer(socket);
        }
    }
}
