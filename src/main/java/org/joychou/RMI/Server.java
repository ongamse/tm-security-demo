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
     * RMIServerSocketFactory that binds only to localhost (127.0.0.1)
     * to prevent remote access to the RMI registry.
     */
    private static class LocalhostRMIServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
        }
    }

    public static void main(String args[]) {

        try {
            Server obj = new Server();
            RMIServerSocketFactory localFactory = new LocalhostRMIServerSocketFactory();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, localFactory);
            Registry registry = LocateRegistry.createRegistry(1099, null, localFactory);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功 (localhost only)");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

