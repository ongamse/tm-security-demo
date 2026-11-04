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
            Server obj = new Server();
            // Listen on the loopback interface only unless an operator explicitly opts in
            // with -Drmi.server.bindAddress=<ip>, so the registry is not exposed to the network.
            final InetAddress bindAddress = InetAddress.getByName(
                    System.getProperty("rmi.server.bindAddress", "127.0.0.1"));
            RMIServerSocketFactory ssf = new RMIServerSocketFactory() {
                public ServerSocket createServerSocket(int port) throws IOException {
                    return new ServerSocket(port, 50, bindAddress);
                }
            };
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, ssf);
            // Restrict what the registry may deserialize (JDK 8u121+ honours this property),
            // so a malicious bind/rebind payload cannot trigger gadget-chain code execution.
            if (System.getProperty("sun.rmi.registry.registryFilter") == null) {
                System.setProperty("sun.rmi.registry.registryFilter",
                        "java.lang.String;java.lang.Number;java.rmi.Remote;java.lang.reflect.Proxy;"
                                + "java.rmi.server.*;java.rmi.activation.ActivationID;"
                                + "sun.rmi.server.*;sun.rmi.transport.tcp.*;"
                                + "org.joychou.RMI.Hello;!*");
            }
            LocateRegistry.createRegistry(1099, null, ssf);
            Registry registry = LocateRegistry.getRegistry(bindAddress.getHostAddress(), 1099);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

