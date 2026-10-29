package org.joychou.RMI;

import java.io.IOException;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;


public class Server implements Hello {

    private static final int REGISTRY_PORT = 1099;

    /** Plain client sockets; serializable because it is embedded in the stubs handed to clients. */
    private static class PlainClientSocketFactory implements RMIClientSocketFactory, Serializable {
        private static final long serialVersionUID = 1L;

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return new Socket(host, port);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof PlainClientSocketFactory;
        }

        @Override
        public int hashCode() {
            return PlainClientSocketFactory.class.hashCode();
        }
    }

    /** Server sockets that only listen on the loopback interface, never on a public address. */
    private static class LoopbackServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof LoopbackServerSocketFactory;
        }

        @Override
        public int hashCode() {
            return LoopbackServerSocketFactory.class.hashCode();
        }
    }

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            RMIClientSocketFactory csf = new PlainClientSocketFactory();
            RMIServerSocketFactory ssf = new LoopbackServerSocketFactory();
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, csf, ssf);
            // Restrict the classes the registry may deserialize (JEP 290) before it is created.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;org.joychou.RMI.Hello;"
                            + "org.joychou.RMI.Server$PlainClientSocketFactory;"
                            + "java.rmi.**;sun.rmi.server.**;sun.rmi.transport.**;!*");
            // Loopback-only registry with the deserialization filter above.
            Registry registry = LocateRegistry.createRegistry(REGISTRY_PORT, csf, ssf);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

