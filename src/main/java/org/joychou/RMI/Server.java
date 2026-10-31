package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    /**
     * Server sockets are bound to the loopback interface only, so the RMI endpoints are never
     * reachable from other hosts.
     */
    private static final class LoopbackServerSocketFactory implements RMIServerSocketFactory {
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

        // The RMI endpoint is never started implicitly: it must be enabled explicitly (-Djoychou.rmi.enabled=true).
        if (!Boolean.getBoolean("joychou.rmi.enabled")) {
            System.err.println("RMI server disabled; start with -Djoychou.rmi.enabled=true to enable it (loopback only).");
            return;
        }

        try {
            RMIServerSocketFactory loopbackFactory = new LoopbackServerSocketFactory();
            // Restrict what the registry may deserialize (JEP 290, JDK 8u121+) so a crafted
            // bind/rebind payload cannot trigger gadget chains. Must be set before createRegistry.
            if (System.getProperty("sun.rmi.registry.registryFilter") == null) {
                System.setProperty("sun.rmi.registry.registryFilter",
                        "java.lang.String;java.lang.reflect.Proxy;java.rmi.**;sun.rmi.server.**;"
                                + "sun.rmi.transport.**;org.joychou.RMI.Hello;!*");
            }
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackFactory);
            Registry registry = LocateRegistry.createRegistry(1099, null, loopbackFactory);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}
