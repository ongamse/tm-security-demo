package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    /**
     * RMI server socket factory that binds only to localhost to prevent
     * remote RMI deserialization attacks.
     */
    private static class LocalhostServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            ServerSocket ss = new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
            return ss;
        }
    }

    // Allowlist of permitted RMI binding names
    private static final Set<String> ALLOWED_BINDINGS = new HashSet<>(
            java.util.Arrays.asList("Hello")
    );

    public static void main(String args[]) {

        try {
            String bindingName = "Hello";
            if (!ALLOWED_BINDINGS.contains(bindingName)) {
                System.err.println("RMI binding name not allowed: " + bindingName);
                return;
            }
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            // Bind registry to localhost only to restrict access
            LocateRegistry.createRegistry(1099, null, new LocalhostServerSocketFactory());
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
            registry.bind(bindingName, stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

