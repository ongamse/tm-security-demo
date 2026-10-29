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

    public static void main(String args[]) {

        try {
            // Restrict what the registry will deserialize (JEP 290 registry filter): only
            // String and java.rmi types are accepted, everything else is rejected. Must be set
            // before the first registry is created.
            System.setProperty("sun.rmi.registry.registryFilter", "java.lang.String;java.rmi.**;!*");
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            // Bind the registry to the loopback interface only instead of all interfaces.
            LocateRegistry.createRegistry(1099, null, new RMIServerSocketFactory() {
                @Override
                public ServerSocket createServerSocket(int port) throws IOException {
                    return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
                }
            });
            Registry registry = LocateRegistry.getRegistry();
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

