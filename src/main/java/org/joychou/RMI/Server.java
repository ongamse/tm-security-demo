package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.RMIServerSocketFactory;


public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    /** Server sockets bound to the loopback interface only. */
    private static class LoopbackSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"));
        }
    }

    public static void main(String args[]) {

        // The demo RMI server must be enabled explicitly: -Djoychou.rmi.enabled=true
        if (!Boolean.getBoolean("joychou.rmi.enabled")) {
            System.err.println("RMI server disabled. Start with -Djoychou.rmi.enabled=true to enable.");
            return;
        }

        try {
            System.setProperty("java.rmi.server.hostname", "127.0.0.1");
            // JEP 290: reject every class deserialized by the registry (must be set before
            // createRegistry). No remote object is exported or bound, so nothing remotely
            // callable exists and no gadget chain can be reached.
            System.setProperty("sun.rmi.registry.registryFilter", "!*");
            LocateRegistry.createRegistry(1099, null, new LoopbackSocketFactory());
            System.out.println("RMI registry started on 127.0.0.1:1099 (no objects bound)");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.getClass().getSimpleName());
        }
    }
}
