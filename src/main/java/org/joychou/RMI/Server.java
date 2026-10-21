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

    /**
     * RMIServerSocketFactory that restricts the RMI registry to localhost only,
     * preventing remote deserialization attacks via network-accessible RMI.
     */
    private static class LocalhostRMIServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            ServerSocket ss = new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
            return ss;
        }
    }

    public static void main(String args[]) {

        try {
            RMIServerSocketFactory ssf = new LocalhostRMIServerSocketFactory();
            Server obj = new Server();
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

