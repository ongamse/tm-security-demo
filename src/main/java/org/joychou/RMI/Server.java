package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    /** Accepts connections on the loopback interface only. */
    private static class LoopbackServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        }
    }

    public static void main(String args[]) {

        // Demo server: refuses to start unless explicitly enabled (-Drmi.demo.enabled=true).
        if (!Boolean.getBoolean("rmi.demo.enabled")) {
            System.err.println("RMI demo server is disabled. Start with -Drmi.demo.enabled=true to enable it.");
            return;
        }

        try {
            // Allowlist deserialization on the RMI registry (must be set before createRegistry).
            // Anything outside RMI plumbing, String/Number and this package's Hello is rejected.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;java.rmi.**;sun.rmi.**;"
                            + "org.joychou.RMI.Hello;!*");
            System.setProperty("java.rmi.server.useCodebaseOnly", "true");
            System.setProperty("java.rmi.server.hostname", "127.0.0.1");
            RMIServerSocketFactory loopbackFactory = new LoopbackServerSocketFactory();
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackFactory);
            Registry registry = LocateRegistry.createRegistry(1099, null, loopbackFactory);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功 (loopback only)");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

