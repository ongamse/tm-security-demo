package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    private static final int REGISTRY_PORT = 1099;

    /**
     * Server sockets bound to the loopback interface only, so the registry and the
     * exported object are not reachable from other hosts.
     */
    private static class LoopbackServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof LoopbackServerSocketFactory;
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
            // JEP 290 registry deserialization allowlist (must be set before the registry is created):
            // only types needed to bind/lookup a remote stub are accepted, everything else is rejected.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "maxdepth=5;java.lang.String;java.lang.Number;java.lang.reflect.Proxy;"
                            + "java.rmi.Remote;org.joychou.RMI.Hello;java.rmi.server.**;sun.rmi.server.**;sun.rmi.transport.**;!*");
            RMIServerSocketFactory loopbackFactory = new LoopbackServerSocketFactory();
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackFactory);
            Registry registry = LocateRegistry.createRegistry(REGISTRY_PORT, null, loopbackFactory);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

