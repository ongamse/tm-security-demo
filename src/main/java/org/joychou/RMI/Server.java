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
     * Server socket factory that only listens on the loopback interface.
     */
    private static class LoopbackSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof LoopbackSocketFactory;
        }

        @Override
        public int hashCode() {
            return LoopbackSocketFactory.class.hashCode();
        }
    }

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        // Fail closed: the demo RMI server only starts when explicitly enabled.
        if (!Boolean.getBoolean("joychou.rmi.server.enabled")) {
            System.err.println("RMI server disabled. Start with -Djoychou.rmi.server.enabled=true to enable it.");
            return;
        }
        try {
            // Restrict what the registry will deserialize (JEP 290) so a crafted bind/rebind
            // argument cannot trigger a gadget chain. Must be set before the registry is created.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.reflect.Proxy;java.rmi.**;sun.rmi.**;java.lang.String;org.joychou.RMI.Hello;!*");
            // Bind RMI sockets to loopback only (not reachable from other hosts).
            System.setProperty("java.rmi.server.hostname", "127.0.0.1");
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0,
                    null, new LoopbackSocketFactory());
            Registry registry = LocateRegistry.createRegistry(1099,
                    null, new LoopbackSocketFactory());
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

