package org.joychou.security.ssrf;

import org.joychou.security.SecurityUtil;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * SSL socket factory for https connections to a validated host. HttpsURLConnection connects the plain
 * socket first and then layers TLS over it through {@link #createSocket(Socket, String, int, boolean)};
 * here the address that was really connected to is re-checked, so a DNS answer that changed after
 * validation (DNS rebinding) is rejected before the TLS handshake or any request data is sent.
 */
public class PinnedSslSocketFactory extends SSLSocketFactory {

    private final SSLSocketFactory delegate = (SSLSocketFactory) SSLSocketFactory.getDefault();

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        InetAddress peer = s.getInetAddress();
        if (peer == null || !SecurityUtil.isPublicAddress(peer)) {
            s.close();
            throw new IOException("[-] SSRF check failed. Connected to an internal address.");
        }
        return delegate.createSocket(s, host, port, autoClose);
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.createSocket();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    // Direct connects bypass the layered path above, so they are refused.
    @Override
    public Socket createSocket(String h, int port) throws IOException {
        throw new IOException("Direct socket creation is not allowed");
    }

    @Override
    public Socket createSocket(String h, int port, InetAddress localHost, int localPort) throws IOException {
        throw new IOException("Direct socket creation is not allowed");
    }

    @Override
    public Socket createSocket(InetAddress h, int port) throws IOException {
        throw new IOException("Direct socket creation is not allowed");
    }

    @Override
    public Socket createSocket(InetAddress h, int port, InetAddress localAddress, int localPort) throws IOException {
        throw new IOException("Direct socket creation is not allowed");
    }
}
