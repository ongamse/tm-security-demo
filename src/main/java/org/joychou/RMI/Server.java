package org.joychou.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.io.IOException;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    /**
     * RMI server socket factory that binds only to localhost to prevent
     * remote code execution via unauthenticated RMI exposure.
     */
    private static class LocalhostServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
        }
    }

    public static void main(String args[]) {

        try {
            // Bind to localhost only to prevent remote RCE via RMI
            RMIServerSocketFactory ssf = new LocalhostServerSocketFactory();
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            LocateRegistry.createRegistry(1099, null, ssf);
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功（仅localhost）");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

