package org.joychou.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.io.IOException;
import java.io.Serializable;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    /**
     * RMI server socket factory that binds only to localhost to prevent remote attacks.
     */
    private static class LocalhostServerSocketFactory implements RMIServerSocketFactory, Serializable {
        private static final long serialVersionUID = 1L;

        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
        }
    }

    public static void main(String args[]) {

        try {
            // Set JVM-level deserialization filter for RMI to restrict allowed types
            System.setProperty("sun.rmi.registry.registryFilter",
                    "org.joychou.RMI.*;java.lang.*;!*");

            Server obj = new Server();
            // Bind to localhost only using a custom server socket factory
            RMIServerSocketFactory ssf = new LocalhostServerSocketFactory();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, ssf);
            Registry registry = LocateRegistry.createRegistry(1099, null, ssf);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功 (localhost only)");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

